import { afterEach, describe, expect, test } from 'bun:test'
import { isWebAuthn } from '../src/enroll'
import { configureRoutes, routes } from '../src/routes'
import { fromBase64Url, toBase64Url } from '../src/webauthn'

describe('base64url', () => {
  test('round trips bytes, including ones that need padding', () => {
    for (const length of [0, 1, 2, 3, 32, 65]) {
      const bytes = Uint8Array.from({ length }, (_, i) => (i * 37) % 256)

      expect(new Uint8Array(fromBase64Url(toBase64Url(bytes.buffer)))).toEqual(bytes)
    }
  })

  test('uses the url-safe alphabet without padding', () => {
    expect(toBase64Url(Uint8Array.from([251, 255]).buffer)).toBe('-_8')
  })
})

test('the main entry point has the passkey sign in helpers, for a frontend without inertia', async () => {
  const main = await import('../src/index')
  const inertia = await import('../src/inertia')

  expect(main.passkeyCredential).toBe(inertia.passkeyCredential)
  expect(main.isAbort).toBe(inertia.isAbort)
  expect(main.configureRequests).toBeFunction()
})

describe('enrollment', () => {
  test('runs the browser ceremony for any factor that sends creation options', () => {
    expect(isWebAuthn({ options: { challenge: 'abc', rp: { id: 'example.com' } } })).toBe(true)
    expect(isWebAuthn({ secret: 'ABC', qr: '<svg/>' })).toBe(false)
  })
})

describe('routes', () => {
  // The routes are one object for the whole process, so what a test sets
  // here would still be set for the next test and the next file.
  const challengeBase = routes.challengeBase

  afterEach(() => configureRoutes({ prefix: '', login: undefined, challengeBase }))

  test('follow the server\'s route prefix, however its slashes are written', () => {
    configureRoutes({ prefix: 'account/' })

    expect(routes.login).toBe('/account/login')
    expect(routes.loginOptions('passkey')).toBe('/account/login/passkey/options')
    expect(routes.verify('confirm', 'totp')).toBe('/account/confirm/totp')
    expect(routes.enroll('totp')).toBe('/account/user/authenticators/totp')
    expect(routes.sessions()).toBe('/account/user/sessions')
    expect(routes.session('9f2c')).toBe('/account/user/sessions/9f2c')
    expect(routes.impersonate('42')).toBe('/account/impersonate/42')
    expect(routes.stopImpersonating()).toBe('/account/impersonate')

    configureRoutes({ prefix: '' })

    expect(routes.login).toBe('/login')
    expect(routes.authenticator('abc')).toBe('/user/authenticators/abc')
  })

  // OWASP ASVS 5.0.0, 1.2.2: a value put into a URL is encoded for where
  // it goes, so it can't aim the request at another path.
  test('keep a factor or an ID inside its own path segment, whatever it holds', () => {
    expect(routes.authenticator('../sessions')).toBe('/user/authenticators/..%2Fsessions')
    expect(routes.authenticator('abc/confirm')).toBe('/user/authenticators/abc%2Fconfirm')
    expect(routes.authenticator('abc?default=1#x')).toBe('/user/authenticators/abc%3Fdefault%3D1%23x')
    expect(routes.session('9f2c/../../logout')).toBe('/user/sessions/9f2c%2F..%2F..%2Flogout')
    expect(routes.session('a b%2Fc')).toBe('/user/sessions/a%20b%252Fc')
    expect(routes.impersonate('1/../logout')).toBe('/impersonate/1%2F..%2Flogout')
    expect(routes.enroll('totp/../../password')).toBe('/user/authenticators/totp%2F..%2F..%2Fpassword')
    expect(routes.confirmEnrollment('totp?x')).toBe('/user/authenticators/totp%3Fx/confirm')
    expect(routes.loginOptions('passkey/../..')).toBe('/login/passkey%2F..%2F../options')
    expect(routes.loginWith('passkey#')).toBe('/login/passkey%23')
    expect(routes.challenge('login', 'totp/send')).toBe('/login/challenge/totp%2Fsend')
    expect(routes.verify('confirm', 'totp?')).toBe('/confirm/totp%3F')
    expect(routes.send('confirm', 'email-code/x')).toBe('/confirm/email-code%2Fx/send')

    // Where each of those lands is the segment it was given, on this origin.
    for (const path of [routes.authenticator('../sessions'), routes.session('9f2c/../../logout'), routes.loginOptions('passkey/../..')]) {
      expect(new URL(path, 'https://app.example').pathname).toBe(path)
    }
  })

  test('leave the keys and IDs the server issues as they are', () => {
    expect(routes.verify('login', 'email-code')).toBe('/login/challenge/email-code')
    expect(routes.enroll('security-key')).toBe('/user/authenticators/security-key')
    expect(routes.authenticator('01JCM8Q3ZV7W9X2Y4T6R8S0A1B')).toBe('/user/authenticators/01JCM8Q3ZV7W9X2Y4T6R8S0A1B')
    expect(routes.challenge('login')).toBe('/login/challenge')
  })

  test('refuse a segment a browser would resolve away, encoded or not', () => {
    for (const dots of ['.', '..']) {
      expect(() => routes.authenticator(dots)).toThrow(TypeError)
      expect(() => routes.session(dots)).toThrow(TypeError)
      expect(() => routes.loginWith(dots)).toThrow(TypeError)
      expect(() => routes.verify('confirm', dots)).toThrow(TypeError)
    }
  })

  test('use an overridden route as written', () => {
    configureRoutes({ prefix: 'account', login: '/sign-in' })

    expect(routes.login).toBe('/sign-in')
  })

  test('follow a changed challenge prefix', () => {
    configureRoutes({ challengeBase: purpose => purpose === 'login' ? '/auth/challenge' : '/auth/confirm' })

    expect(routes.verify('login', 'totp')).toBe('/auth/challenge/totp')
    expect(routes.send('confirm', 'email-code')).toBe('/auth/confirm/email-code/send')
  })
})
