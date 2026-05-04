import { jest } from '@jest/globals'
import { withScopedSessionCache } from '../../Socket/messages-send'

describe('withScopedSessionCache', () => {
	it('uses repository.withSessionCache when available', async () => {
		const work = jest.fn(async () => 'ok')
		const withSessionCache = jest.fn(async (_jids: string[], callback: () => Promise<string>) => callback())

		const result = await withScopedSessionCache(
			{ withSessionCache } as any,
			['11111111111@s.whatsapp.net', '22222222222@s.whatsapp.net'],
			work
		)

		expect(result).toBe('ok')
		expect(withSessionCache).toHaveBeenCalledTimes(1)
		expect(withSessionCache).toHaveBeenCalledWith(
			['11111111111@s.whatsapp.net', '22222222222@s.whatsapp.net'],
			expect.any(Function)
		)
		expect(work).toHaveBeenCalledTimes(1)
	})

	it('runs work directly when the repository does not support scoped caching', async () => {
		const work = jest.fn(async () => 'ok')

		const result = await withScopedSessionCache({}, ['11111111111@s.whatsapp.net'], work)

		expect(result).toBe('ok')
		expect(work).toHaveBeenCalledTimes(1)
	})
})
