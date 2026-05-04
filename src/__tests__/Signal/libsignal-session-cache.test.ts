import { jest } from '@jest/globals'

const mockDeserialize = jest.fn(() => ({
	haveOpenSession: () => true
}))

const mockEncrypt = jest.fn(async function (this: { storage: { loadSession: (id: string) => Promise<unknown> }; addr: { toString: () => string } }) {
	await this.storage.loadSession(this.addr.toString())
	return {
		type: 3,
		body: 'ciphertext'
	}
})

await jest.unstable_mockModule('libsignal', () => ({
	ProtocolAddress: class ProtocolAddress {
		constructor(
			private readonly user: string,
			private readonly device: number
		) {}

		toString() {
			return `${this.user}.${this.device}`
		}
	},
	SessionCipher: jest.fn().mockImplementation(function (storage, addr) {
		return {
			storage,
			addr,
			encrypt: mockEncrypt
		}
	}),
	SessionBuilder: jest.fn(),
	SessionRecord: {
		deserialize: mockDeserialize
	}
}))

const { makeLibSignalRepository } = await import('../../Signal/libsignal')

const makeLogger = () =>
	({
		trace: jest.fn(),
		debug: jest.fn(),
		info: jest.fn(),
		warn: jest.fn(),
		error: jest.fn()
	}) as any

const makeAuth = () =>
	({
		creds: {
			me: { id: 'me@s.whatsapp.net' },
			signedPreKey: {
				keyId: 1,
				keyPair: {
					private: Buffer.alloc(32),
					public: Buffer.alloc(33)
				}
			},
			signedIdentityKey: {
				private: Buffer.alloc(32),
				public: Buffer.alloc(32)
			}
		},
		keys: {
			get: jest.fn(),
			set: jest.fn(),
			clear: jest.fn(),
			transaction: jest.fn(async (work: () => Promise<unknown>) => work())
		}
	}) as any

describe('makeLibSignalRepository session cache', () => {
	beforeEach(() => {
		mockDeserialize.mockClear()
		mockEncrypt.mockClear()
	})

	it('preloads sessions once and reuses them inside the scoped cache', async () => {
		const auth = makeAuth()
		const repo = makeLibSignalRepository(auth, makeLogger())
		const jids = ['111111111111111@lid', '222222222222222@lid']
		const wireAddresses = jids.map(jid => repo.jidToSignalProtocolAddress(jid))
		const serializedSession = Buffer.from('serialized-session')

		auth.keys.get.mockImplementation(async (_type: string, ids: string[]) => {
			if (_type !== 'session') {
				return {}
			}

			return Object.fromEntries(ids.map(id => [id, serializedSession]))
		})

		const result = await repo.withSessionCache!(jids, async () =>
			Promise.all(jids.map(jid => repo.encryptMessage({ jid, data: Buffer.from('payload') })))
		)

		expect(result).toHaveLength(2)
		expect(auth.keys.get).toHaveBeenCalledTimes(1)
		expect(auth.keys.get).toHaveBeenCalledWith('session', wireAddresses)
		expect(mockDeserialize).toHaveBeenCalledTimes(2)
		expect(mockEncrypt).toHaveBeenCalledTimes(2)
	})

	it('falls back to the store when a preload miss occurs', async () => {
		const auth = makeAuth()
		const repo = makeLibSignalRepository(auth, makeLogger())
		const jid = '333333333333333@lid'
		const wireAddress = repo.jidToSignalProtocolAddress(jid)
		const serializedSession = Buffer.from('serialized-session')

		auth.keys.get
			.mockResolvedValueOnce({})
			.mockResolvedValueOnce({ [wireAddress]: serializedSession })

		const result = await repo.withSessionCache!([jid], async () =>
			repo.encryptMessage({ jid, data: Buffer.from('payload') })
		)

		expect(result).toBeTruthy()
		expect(auth.keys.get).toHaveBeenCalledTimes(2)
		expect(auth.keys.get).toHaveBeenNthCalledWith(1, 'session', [wireAddress])
		expect(auth.keys.get).toHaveBeenNthCalledWith(2, 'session', [wireAddress])
		expect(mockDeserialize).toHaveBeenCalledTimes(1)
		expect(mockEncrypt).toHaveBeenCalledTimes(1)
	})
})
