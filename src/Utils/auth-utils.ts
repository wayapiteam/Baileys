import NodeCache from '@cacheable/node-cache'
import { AsyncLocalStorage } from 'async_hooks'
import { Mutex } from 'async-mutex'
import { randomBytes } from 'crypto'
import PQueue from 'p-queue'
import { DEFAULT_CACHE_TTLS } from '../Defaults'
import type {
	AuthenticationCreds,
	CacheStore,
	SignalDataSet,
	SignalDataTypeMap,
	SendInstrumentation,
	SignalKeyStore,
	SignalKeyStoreWithTransaction,
	TransactionCapabilityOptions
} from '../Types'
import { Curve, signedKeyPair } from './crypto'
import { delay, generateRegistrationId } from './generics'
import { emitTelemetry } from './instrumentation'
import type { ILogger } from './logger'
import { PreKeyManager } from './pre-key-manager'

/**
 * Transaction context stored in AsyncLocalStorage
 */
interface TransactionContext {
	cache: SignalDataSet
	mutations: SignalDataSet
	dbQueries: number
}

/**
 * Adds caching capability to a SignalKeyStore
 * @param store the store to add caching to
 * @param logger to log trace events
 * @param _cache cache store to use
 */
export function makeCacheableSignalKeyStore(
	store: SignalKeyStore,
	logger?: ILogger,
	_cache?: CacheStore
): SignalKeyStore {
	const cache =
		_cache ||
		new NodeCache<SignalDataTypeMap[keyof SignalDataTypeMap]>({
			stdTTL: DEFAULT_CACHE_TTLS.SIGNAL_STORE, // 5 minutes
			useClones: false,
			deleteOnExpire: true
		})

	// Mutex for protecting cache operations
	const cacheMutex = new Mutex()

	function getUniqueId(type: string, id: string) {
		return `${type}.${id}`
	}

	return {
		async get(type, ids) {
			return cacheMutex.runExclusive(async () => {
				const data: { [_: string]: SignalDataTypeMap[typeof type] } = {}
				const idsToFetch: string[] = []

				for (const id of ids) {
					const item = (await cache.get<SignalDataTypeMap[typeof type]>(getUniqueId(type, id))) as any
					if (typeof item !== 'undefined') {
						data[id] = item
					} else {
						idsToFetch.push(id)
					}
				}

				if (idsToFetch.length) {
					logger?.trace({ items: idsToFetch.length }, 'loading from store')
					const fetched = await store.get(type, idsToFetch)
					for (const id of idsToFetch) {
						const item = fetched[id]
						if (item) {
							data[id] = item
							// eslint-disable-next-line @typescript-eslint/no-unnecessary-type-assertion
							await cache.set(getUniqueId(type, id), item as SignalDataTypeMap[keyof SignalDataTypeMap])
						}
					}
				}

				return data
			})
		},
		async set(data) {
			return cacheMutex.runExclusive(async () => {
				let keys = 0
				for (const type in data) {
					for (const id in data[type as keyof SignalDataTypeMap]) {
						await cache.set(getUniqueId(type, id), data[type as keyof SignalDataTypeMap]![id]!)
						keys += 1
					}
				}

				logger?.trace({ keys }, 'updated cache')
				await store.set(data)
			})
		},
		async clear() {
			await cache.flushAll()
			await store.clear?.()
		}
	}
}

/**
 * Adds DB-like transaction capability to the SignalKeyStore
 * Uses AsyncLocalStorage for automatic context management
 * @param state the key store to apply this capability to
 * @param logger logger to log events
 * @returns SignalKeyStore with transaction capability
 */
export const addTransactionCapability = (
	state: SignalKeyStore,
	logger: ILogger,
	{ maxCommitRetries, delayBetweenTriesMs }: TransactionCapabilityOptions,
	telemetry?: SendInstrumentation
): SignalKeyStoreWithTransaction => {
	const txStorage = new AsyncLocalStorage<TransactionContext>()

	const emitSendPathTelemetry = (
		stage: string,
		status: 'start' | 'success' | 'hit' | 'miss' | 'failure',
		counts?: {
			participants?: number
			devices?: number
			sessionsExisting?: number
			sessionsFetched?: number
			cacheHits?: number
			cacheMisses?: number
			cacheSets?: number
			attempts?: number
		},
		details?: Record<string, unknown>
	) => {
		void emitTelemetry(telemetry, {
			stage,
			status,
			counts,
			details: {
				namespace: 'send_path',
				component: 'auth-utils',
				schemaVersion: 1,
				...details
			}
		})
	}

	// Queues for concurrency control (keyed by signal data type - bounded set)
	const keyQueues = new Map<string, PQueue>()

	// Transaction mutexes with reference counting for cleanup
	const txMutexes = new Map<string, Mutex>()
	const txMutexRefCounts = new Map<string, number>()

	// Pre-key manager for specialized operations
	const preKeyManager = new PreKeyManager(state, logger)

	/**
	 * Get or create a queue for a specific key type
	 */
	function getQueue(key: string): PQueue {
		if (!keyQueues.has(key)) {
			keyQueues.set(key, new PQueue({ concurrency: 1 }))
		}

		return keyQueues.get(key)!
	}

	/**
	 * Get or create a transaction mutex
	 */
	function getTxMutex(key: string): Mutex {
		if (!txMutexes.has(key)) {
			txMutexes.set(key, new Mutex())
			txMutexRefCounts.set(key, 0)
		}

		return txMutexes.get(key)!
	}

	/**
	 * Acquire a reference to a transaction mutex
	 */
	function acquireTxMutexRef(key: string): void {
		const count = txMutexRefCounts.get(key) ?? 0
		txMutexRefCounts.set(key, count + 1)
	}

	/**
	 * Release a reference to a transaction mutex and cleanup if no longer needed
	 */
	function releaseTxMutexRef(key: string): void {
		const count = (txMutexRefCounts.get(key) ?? 1) - 1
		txMutexRefCounts.set(key, count)

		// Cleanup if no more references and mutex is not locked
		if (count <= 0) {
			const mutex = txMutexes.get(key)
			if (mutex && !mutex.isLocked()) {
				txMutexes.delete(key)
				txMutexRefCounts.delete(key)
			}
		}
	}

	/**
	 * Check if currently in a transaction
	 */
	function isInTransaction(): boolean {
		return !!txStorage.getStore()
	}

	/**
	 * Commit transaction with retries
	 */
	async function commitWithRetry(mutations: SignalDataSet): Promise<void> {
		if (Object.keys(mutations).length === 0) {
			emitSendPathTelemetry('keys.transaction.commit', 'hit', undefined, { reason: 'no_mutations' })
			return
		}

		const commitStartedAt = Date.now()
		emitSendPathTelemetry(
			'keys.transaction.commit',
			'start',
			{ cacheSets: Object.values(mutations).reduce((count, value) => count + Object.keys(value || {}).length, 0) },
			{ types: Object.keys(mutations) }
		)

		for (let attempt = 0; attempt < maxCommitRetries; attempt++) {
			try {
				const attemptStartedAt = Date.now()
				await state.set(mutations)
				emitSendPathTelemetry(
					'keys.transaction.commit',
					'success',
					{
						cacheSets: Object.values(mutations).reduce((count, value) => count + Object.keys(value || {}).length, 0),
						attempts: attempt + 1
					},
					{
						mutationCount: Object.keys(mutations).length,
						durationMs: Date.now() - attemptStartedAt,
						totalDurationMs: Date.now() - commitStartedAt
					}
				)
				return
			} catch (error) {
				const retriesLeft = maxCommitRetries - attempt - 1
				emitSendPathTelemetry(
					'keys.transaction.commit',
					'failure',
					{ attempts: attempt + 1 },
					{
						retriesLeft,
						totalDurationMs: Date.now() - commitStartedAt,
						error: error instanceof Error ? error.message : String(error)
					}
				)

				if (retriesLeft === 0) {
					throw error
				}

				await delay(delayBetweenTriesMs)
			}
		}
	}

	return {
		get: async (type, ids) => {
			const ctx = txStorage.getStore()

			if (!ctx) {
				// No transaction - direct read without exclusive lock for concurrency
				return state.get(type, ids)
			}

			// In transaction - check cache first
			const cached = ctx.cache[type] || {}
			const missing = ids.filter(id => !(id in cached))

				if (missing.length > 0) {
					ctx.dbQueries++
					const fetchStartedAt = Date.now()
					emitSendPathTelemetry('keys.transaction.get', 'start', { participants: missing.length }, { type })

					const fetched = await getTxMutex(type).runExclusive(async () => {
						const waitMs = Date.now() - fetchStartedAt
						emitSendPathTelemetry('keys.transaction.get.lock', 'success', { participants: missing.length }, { type, waitMs })

						const stateGetStartedAt = Date.now()
						const result = await state.get(type, missing)
						emitSendPathTelemetry(
							'keys.transaction.get.read',
							'success',
							{ participants: missing.length },
							{
								type,
								waitMs,
								durationMs: Date.now() - stateGetStartedAt
							}
						)
						return result
					})
					emitSendPathTelemetry(
						'keys.transaction.get',
						'success',
					{ participants: missing.length },
					{
						type,
						durationMs: Date.now() - fetchStartedAt
					}
				)

				// Update cache
				ctx.cache[type] = ctx.cache[type] || ({} as any)
				Object.assign(ctx.cache[type]!, fetched)
			}

			// Return requested ids from cache
			const result: { [key: string]: any } = {}
			for (const id of ids) {
				const value = ctx.cache[type]?.[id]
				if (value !== undefined && value !== null) {
					result[id] = value
				}
			}

			return result
		},

		set: async data => {
			const ctx = txStorage.getStore()

			if (!ctx) {
				// No transaction - direct write with queue protection
				const types = Object.keys(data)

				// Process pre-keys with validation
				for (const type_ of types) {
					const type = type_ as keyof SignalDataTypeMap
					if (type === 'pre-key') {
						await preKeyManager.validateDeletions(data, type)
					}
				}

				// Write all data in parallel
				await Promise.all(
					types.map(type =>
						getQueue(type).add(async () => {
							const typeData = { [type]: data[type as keyof SignalDataTypeMap] } as SignalDataSet
							await state.set(typeData)
						})
					)
				)
				return
			}

			// In transaction - update cache and mutations
			const setStartedAt = Date.now()
			emitSendPathTelemetry('keys.transaction.set', 'start', { cacheSets: Object.keys(data).length }, { types: Object.keys(data) })

			for (const key_ in data) {
				const key = key_ as keyof SignalDataTypeMap

				// Ensure structures exist
				ctx.cache[key] = ctx.cache[key] || ({} as any)
				ctx.mutations[key] = ctx.mutations[key] || ({} as any)

				// Special handling for pre-keys
				if (key === 'pre-key') {
					await preKeyManager.processOperations(data, key, ctx.cache, ctx.mutations, true)
				} else {
					// Normal key types
					Object.assign(ctx.cache[key]!, data[key])
					Object.assign(ctx.mutations[key]!, data[key])
				}
			}

			emitSendPathTelemetry(
				'keys.transaction.set',
				'success',
				{ cacheSets: Object.keys(data).length },
				{
					types: Object.keys(data),
					durationMs: Date.now() - setStartedAt,
					mutationCount: Object.values(data).reduce((count, value) => count + Object.keys(value || {}).length, 0)
				}
			)
		},

		isInTransaction,

		transaction: async (work, key) => {
			const existing = txStorage.getStore()

			// Nested transaction - reuse existing context
			if (existing) {
				logger.trace('reusing existing transaction context')
				return work()
			}

			// New transaction - acquire mutex and create context
			const mutex = getTxMutex(key)
			acquireTxMutexRef(key)

			try {
				const queuedAt = Date.now()
				emitSendPathTelemetry('keys.transaction.enter', 'start', undefined, { key })
				return await mutex.runExclusive(async () => {
					const waitMs = Date.now() - queuedAt
					const ctx: TransactionContext = {
						cache: {},
						mutations: {},
						dbQueries: 0
					}

					emitSendPathTelemetry('keys.transaction.enter', 'success', undefined, { key, waitMs })

					try {
						const workStartedAt = Date.now()
						const result = await txStorage.run(ctx, work)
						emitSendPathTelemetry('keys.transaction.work', 'success', undefined, {
							key,
							waitMs,
							workDurationMs: Date.now() - workStartedAt,
							dbQueries: ctx.dbQueries
						})

						// Commit mutations
						await commitWithRetry(ctx.mutations)

						emitSendPathTelemetry('keys.transaction.complete', 'success', undefined, {
							key,
							waitMs,
							dbQueries: ctx.dbQueries
						})

						return result
					} catch (error) {
						emitSendPathTelemetry('keys.transaction.complete', 'failure', undefined, {
							key,
							waitMs,
							dbQueries: ctx.dbQueries,
							error: error instanceof Error ? error.message : String(error)
						})
						logger.error({ error }, 'transaction failed, rolling back')
						throw error
					}
				})
			} finally {
				releaseTxMutexRef(key)
			}
		}
	}
}

export const initAuthCreds = (): AuthenticationCreds => {
	const identityKey = Curve.generateKeyPair()
	return {
		noiseKey: Curve.generateKeyPair(),
		pairingEphemeralKeyPair: Curve.generateKeyPair(),
		signedIdentityKey: identityKey,
		signedPreKey: signedKeyPair(identityKey, 1),
		registrationId: generateRegistrationId(),
		advSecretKey: randomBytes(32).toString('base64'),
		processedHistoryMessages: [],
		nextPreKeyId: 1,
		firstUnuploadedPreKeyId: 1,
		accountSyncCounter: 0,
		accountSettings: {
			unarchiveChats: false
		},
		registered: false,
		pairingCode: undefined,
		lastPropHash: undefined,
		routingInfo: undefined,
		additionalData: undefined
	}
}
