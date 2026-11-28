import { afterEach, beforeEach, describe, expect, test } from 'bun:test'
import { enroll, frozenChanges, makeDefault, proveWithKey, removeAuthenticator, renameAuthenticator } from '../src/enroll'
import { KeyringRequestError } from '../src/http'
import { endOtherSessions, endSession, listSessions } from '../src/sessions'
import { impersonate, stopImpersonating } from '../src/impersonation'
import { createCredential, fromBase64Url, getCredential, toBase64Url } from '../src/webauthn'
import { standIn } from './browser'

// A browser without the JSON helpers (parse*FromJSON, toJSON), so the
// conversions Keyring does itself run. Each call to navigator.credentials
// is recorded and answered with a fake credential.
class FakeCredential {
  id = 'key-1'
  rawId = Uint8Array.from([1, 2, 3]).buffer
  type = 'public-key'
  authenticatorAttachment = 'platform'

  constructor(public response: Record<string, any>) {}

  getClientExtensionResults() {
    return {}
  }
}

const bytes = (...values: number[]) => Uint8Array.from(values).buffer

let calls: Array<{ method: string, options: any }> = []
let requests: Array<{ method: string, url: string, body: any }> = []
let answers: Array<{ status: number, body: any }> = []
let restore = () => {}

beforeEach(() => {
  calls = []
  requests = []
  answers = []

  restore = standIn({
    window: globalThis,
    PublicKeyCredential: FakeCredential,
    document: { cookie: 'XSRF-TOKEN=abc%3D' },
    navigator: {
      credentials: {
        create: async (options: any) => {
          calls.push({ method: 'create', options })

          return new FakeCredential({
            clientDataJSON: bytes(9),
            attestationObject: bytes(8),
            getTransports: () => ['internal'],
          })
        },
        get: async (options: any) => {
          calls.push({ method: 'get', options })

          return new FakeCredential({ clientDataJSON: bytes(9), authenticatorData: bytes(7), signature: bytes(6), userHandle: null })
        },
      },
    },
    fetch: async (url: string, init: any) => {
      requests.push({ method: init.method, url, body: init.body === undefined ? undefined : JSON.parse(init.body), headers: init.headers } as any)
      const { status, body } = answers.shift() ?? { status: 200, body: {} }

      return new Response(JSON.stringify(body), { status })
    },
  })
})

// Bun's own fetch and navigator come back, for whichever file runs next.
afterEach(() => restore())

describe('creating a credential', () => {
  test('turns the base64url fields into bytes, and the result back into json', async () => {
    const credential = await createCredential({
      challenge: toBase64Url(bytes(1, 2)),
      user: { id: toBase64Url(bytes(3)), name: 'taylor@example.com' },
      excludeCredentials: [{ type: 'public-key', id: toBase64Url(bytes(4)) }],
    })

    const { publicKey } = calls[0].options
    expect(new Uint8Array(publicKey.challenge)).toEqual(Uint8Array.from([1, 2]))
    expect(new Uint8Array(publicKey.user.id)).toEqual(Uint8Array.from([3]))
    expect(publicKey.user.name).toBe('taylor@example.com')
    expect(new Uint8Array(publicKey.excludeCredentials[0].id)).toEqual(Uint8Array.from([4]))

    expect(credential).toEqual({
      id: 'key-1',
      rawId: 'AQID',
      type: 'public-key',
      authenticatorAttachment: 'platform',
      clientExtensionResults: {},
      response: { clientDataJSON: 'CQ', attestationObject: 'CA', transports: ['internal'] },
    })
  })

  test('lets a browser with the json helpers read the options itself', async () => {
    const options = { challenge: 'AQI', user: { id: 'Aw', name: 'taylor@example.com' } }
    const parsed = { parsed: true }
    const parsing: unknown[] = []
    // On the shared class, since what the browser hands back must be one,
    // and taken off again whatever happens.
    ;(FakeCredential as any).parseCreationOptionsFromJSON = (json: unknown) => {
      parsing.push(json)

      return parsed
    }

    try {
      await createCredential(options)
    } finally {
      delete (FakeCredential as any).parseCreationOptionsFromJSON
    }

    expect(parsing).toEqual([options])
    expect(calls[0].options.publicKey).toBe(parsed)
  })

  test('says so when the browser has no webauthn', async () => {
    delete (globalThis as any).PublicKeyCredential

    await expect(createCredential({})).rejects.toThrow('does not support passkeys')
  })
})

describe('getting a credential', () => {
  test('sends allowed keys as bytes, and asks for autofill when told to', async () => {
    const credential = await getCredential(
      { challenge: toBase64Url(bytes(5)), allowCredentials: [{ type: 'public-key', id: toBase64Url(bytes(6)) }] },
      { autofill: true },
    )

    expect(calls[0].options.mediation).toBe('conditional')
    expect(new Uint8Array(calls[0].options.publicKey.allowCredentials[0].id)).toEqual(Uint8Array.from([6]))
    expect(credential.response).toEqual({ clientDataJSON: 'CQ', authenticatorData: 'Bw', signature: 'Bg', userHandle: null })
  })

  test('says so when the browser hands back no credential', async () => {
    ;(navigator.credentials as any).get = async () => null

    await expect(getCredential({ challenge: toBase64Url(bytes(5)) })).rejects.toThrow('No passkey or security key was used.')
  })

  test('asks in a modal by default', async () => {
    await getCredential({ challenge: toBase64Url(bytes(5)) })

    expect(calls[0].options.mediation).toBeUndefined()
    expect(calls[0].options.publicKey.allowCredentials).toEqual([])
  })
})

describe('enrolling', () => {
  test('runs the ceremony between beginning and confirming a passkey', async () => {
    answers.push(
      { status: 200, body: { factor: 'passkey', enrollment: { options: { challenge: toBase64Url(bytes(1)), rp: { id: 'example.com' }, user: { id: 'AQ' } } } } },
      { status: 200, body: { authenticator: { id: 'a1', name: 'MacBook' } } },
    )

    const result = await enroll('passkey', { name: 'MacBook' })

    expect(requests.map(request => `${request.method} ${request.url}`)).toEqual([
      'POST /user/authenticators/passkey',
      'POST /user/authenticators/passkey/confirm',
    ])
    expect(requests[1].body.name).toBe('MacBook')
    expect(requests[1].body.credential.id).toBe('key-1')
    expect((requests[0] as any).headers['X-XSRF-TOKEN']).toBe('abc=')
    expect(result.authenticator.id).toBe('a1')
  })

  test('confirms factors without a ceremony as they are', async () => {
    answers.push({ status: 200, body: { factor: 'recovery', enrollment: { codes: ['a', 'b'] } } }, { status: 200, body: { authenticator: { id: 'r1' } } })

    await enroll('recovery')

    expect(calls).toEqual([])
    expect(requests[1].body).toEqual({})
  })

  test('hands back the validation errors when removing fails', async () => {
    answers.push({ status: 422, body: { message: 'Enter your password', errors: { password: ['Enter your password'] } } })

    const error = await removeAuthenticator('a1').catch(error => error)

    expect(error).toBeInstanceOf(KeyringRequestError)
    expect(error.status).toBe(422)
    expect(error.errors.password).toEqual(['Enter your password'])
    expect(requests[0]).toMatchObject({ method: 'DELETE', url: '/user/authenticators/a1', body: undefined })
  })

  test('asks for the other sessions to end when removing, with or without the password', async () => {
    await removeAuthenticator('a1', undefined, { signOutOthers: true })
    await removeAuthenticator('a1', 'secret', { signOutOthers: false })
    await removeAuthenticator('a1', 'secret')

    expect(requests.map(request => request.body)).toEqual([
      { sign_out_others: true },
      { password: 'secret', sign_out_others: false },
      { password: 'secret' },
    ])
  })

  test('proves a frozen removal with a key and sends it again with the proof', async () => {
    answers.push(
      { status: 422, body: { message: 'Frozen', errors: { authenticator: ['Frozen'] }, frozen: { reason: 'new-authenticator', until: '2026-12-04T00:00:00+00:00', skip: ['passkey'] } } },
      { status: 200, body: { options: { challenge: 'AQID', rpId: 'localhost', allowCredentials: [{ id: 'BAU', type: 'public-key' }] } } },
      { status: 200, body: { status: 'authenticator-removed' } },
    )

    const error = await removeAuthenticator('a1').catch(error => error)
    const frozen = frozenChanges(error)

    expect(frozen?.skip).toEqual(['passkey'])

    const proof = await proveWithKey(frozen!.skip[0], { action: 'remove', target: 'a1' })
    await removeAuthenticator('a1', undefined, { proof })

    expect(requests.map(request => `${request.method} ${request.url}`)).toEqual([
      'DELETE /user/authenticators/a1',
      'POST /user/authenticators/passkey/proof-options',
      'DELETE /user/authenticators/a1',
    ])
    expect(requests[1].body).toEqual({ action: 'remove', target: 'a1' })
    expect(calls[0].options.publicKey.allowCredentials[0].id).toEqual(bytes(4, 5))
    expect(requests[2].body.proof.factor).toBe('passkey')
    expect(requests[2].body.proof.credential.id).toBe('key-1')
  })

  test('only finds a freeze in a refusal for one', async () => {
    answers.push({ status: 422, body: { message: 'Enter your password', errors: { password: ['Enter your password'] } } })

    expect(frozenChanges(await removeAuthenticator('a1').catch(error => error))).toBeNull()
    expect(frozenChanges(new Error('offline'))).toBeNull()
  })

  test('sends the proof for new recovery codes with the beginning only', async () => {
    answers.push({ status: 200, body: { factor: 'recovery', enrollment: { codes: ['a'] } } }, { status: 200, body: { authenticator: { id: 'r1' } } })

    await enroll('recovery', { proof: { factor: 'passkey', credential: { id: 'key-1' } } })

    expect(requests[0].body.proof.factor).toBe('passkey')
    expect(requests[1].body).toEqual({})
  })

  test('sends the password for a first second factor with the beginning only', async () => {
    answers.push({ status: 200, body: { factor: 'recovery', enrollment: { codes: ['a'] } } }, { status: 200, body: { authenticator: { id: 'r1' } } })

    await enroll('recovery', { password: 'secret', name: 'Codes' })

    expect(requests[0].body).toEqual({ password: 'secret', name: 'Codes' })
    expect(requests[1].body).toEqual({ name: 'Codes' })
  })

  test('asks for a rename\'s challenge with the name it gives', async () => {
    answers.push(
      { status: 200, body: { options: { challenge: 'AQID', rpId: 'localhost', allowCredentials: [{ id: 'BAU', type: 'public-key' }] } } },
      { status: 200, body: { authenticator: { id: 'a1', name: 'Laptop' } } },
    )

    const proof = await proveWithKey('passkey', { action: 'rename', target: 'a1', name: 'Laptop' })
    await renameAuthenticator('a1', 'Laptop', { proof })

    expect(requests[0].body).toEqual({ action: 'rename', target: 'a1', name: 'Laptop' })
    expect(requests[1].body.name).toBe('Laptop')
    expect(requests[1].body.proof.credential.id).toBe('key-1')
  })

  test('renames a frozen authenticator with a proof', async () => {
    answers.push({ status: 200, body: { authenticator: { id: 'a1', name: 'Laptop' } } })

    await renameAuthenticator('a1', 'Laptop', { proof: { factor: 'totp', authenticator: 'a2', code: '123456' } })

    expect(requests[0].body).toEqual({ name: 'Laptop', proof: { factor: 'totp', authenticator: 'a2', code: '123456' } })
  })

  test('renames an authenticator and makes one the default', async () => {
    answers.push({ status: 200, body: { authenticator: { id: 'a1', name: 'Work laptop' } } }, { status: 200, body: { authenticator: { id: 'a1', default: true } } })

    await renameAuthenticator('a1', 'Work laptop')
    await makeDefault('a1')

    expect(requests).toMatchObject([
      { method: 'PATCH', url: '/user/authenticators/a1', body: { name: 'Work laptop' } },
      { method: 'PATCH', url: '/user/authenticators/a1', body: { default: true } },
    ])
  })

  test('still throws with the status when the error page is not json', async () => {
    globalThis.fetch = (async () => new Response('<h1>Server Error</h1>', { status: 500 })) as any

    const error = await renameAuthenticator('a1', 'Work laptop').catch(error => error)

    expect(error).toBeInstanceOf(KeyringRequestError)
    expect(error.status).toBe(500)
    expect(error.message).toBe('Request failed')
    expect(error.errors).toEqual({})
  })

  test('asks for the other sessions to end when adding', async () => {
    answers.push({ status: 200, body: { factor: 'recovery', enrollment: { codes: ['a'] } } }, { status: 200, body: { authenticator: { id: 'r1' } } })

    await enroll('recovery', { sign_out_others: true })

    expect(requests[1]).toMatchObject({ method: 'POST', url: '/user/authenticators/recovery/confirm', body: { sign_out_others: true } })
  })
})

describe('sessions', () => {
  test('lists the sessions the server returns', async () => {
    const session = { id: '9f2c', name: 'Firefox on Windows', ip: '203.0.113.7', device: null, remembered: false, signedInAt: 'a', lastActiveAt: 'b', expiresAt: 'c', current: true, impersonated: true, impersonator: { name: 'Ada Admin' } }
    answers.push({ status: 200, body: { sessions: [session] } })

    expect(await listSessions()).toEqual([session])
    expect(requests[0]).toMatchObject({ method: 'GET', url: '/user/sessions', body: undefined })
  })

  test('ends one session by its handle, or all the others', async () => {
    answers.push({ status: 200, body: { status: 'session-revoked' } }, { status: 200, body: { status: 'sessions-revoked' } })

    expect(await endSession('9f2c')).toEqual({ status: 'session-revoked' })
    expect(await endOtherSessions()).toEqual({ status: 'sessions-revoked' })

    expect(requests.map(({ method, url }) => ({ method, url }))).toEqual([
      { method: 'DELETE', url: '/user/sessions/9f2c' },
      { method: 'DELETE', url: '/user/sessions' },
    ])
  })

  test('answers with nothing when the session ended was this one', async () => {
    answers.push({ status: 204, body: null })

    expect(await endSession('9f2c')).toEqual({})
  })

  test('throws on a session that is not the user\'s, or a stale verification', async () => {
    answers.push({ status: 404, body: { message: 'Not found' } }, { status: 423, body: { message: 'Confirm first', redirect: '/confirm' } })

    expect((await endSession('nope').catch(error => error)).status).toBe(404)
    expect((await endOtherSessions().catch(error => error)).data.redirect).toBe('/confirm')
  })
})

describe('impersonation', () => {
  test('starts by the user\'s id, and stops', async () => {
    answers.push({ status: 200, body: { status: 'impersonation-started', redirect: '/dashboard' } }, { status: 200, body: { status: 'impersonation-ended', redirect: '/dashboard' } })

    expect(await impersonate(42)).toEqual({ status: 'impersonation-started', redirect: '/dashboard' })
    expect(await stopImpersonating()).toEqual({ status: 'impersonation-ended', redirect: '/dashboard' })

    expect(requests.map(({ method, url }) => ({ method, url }))).toEqual([
      { method: 'POST', url: '/impersonate/42' },
      { method: 'DELETE', url: '/impersonate' },
    ])
  })

  test('stops as asked when the impersonation had already ended by itself, or been stopped', async () => {
    answers.push(
      { status: 409, body: { status: 'impersonation-ended', message: 'You\'re back in your own account.', redirect: '/admin' } },
      { status: 409, body: { status: 'not-impersonating', message: 'You\'re not signed in as someone else.', redirect: '/admin' } },
      { status: 401, body: { status: 'signed-out', redirect: '/login' } },
      { status: 409, body: { message: 'Something else' } },
    )

    expect(await stopImpersonating()).toEqual({ status: 'impersonation-ended', redirect: '/admin' })
    expect(await stopImpersonating()).toEqual({ status: 'not-impersonating', redirect: '/admin' })
    expect((await stopImpersonating().catch(error => error)).status).toBe(401)
    expect((await stopImpersonating().catch(error => error)).status).toBe(409)
  })

  test('throws when it\'s refused, or needs a fresh second factor', async () => {
    answers.push({ status: 403, body: { status: 'impersonation-refused', message: 'You can\'t sign in as that user.' } }, { status: 423, body: { message: 'Confirm first', redirect: '/confirm' } })

    const refused = await impersonate('7').catch(error => error)
    expect(refused.status).toBe(403)
    expect(refused.data.status).toBe('impersonation-refused')
    expect((await impersonate('7').catch(error => error)).data.redirect).toBe('/confirm')
  })
})

test('base64url decoding accepts what the server sends', () => {
  expect(new Uint8Array(fromBase64Url('-_8'))).toEqual(Uint8Array.from([251, 255]))
})
