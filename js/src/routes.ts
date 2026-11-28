let prefix = ''
let login: string | null = null

/**
 * Keyring's default URLs. If you changed the `prefix` option on the server,
 * say so once with configureRoutes({ prefix }). Override single routes the
 * same way if you registered them yourself.
 */
export const routes = {
  get login(): string {
    return login ?? `${prefix}/login`
  },
  set login(path: string) {
    login = path
  },
  loginOptions: (factor: string) => `${prefix}/login/${segment(factor)}/options`,
  loginWith: (factor: string) => `${prefix}/login/${segment(factor)}`,
  challenge: (purpose: Purpose, factor?: string) => `${routes.challengeBase(purpose)}${factor ? `/${segment(factor)}` : ''}`,
  verify: (purpose: Purpose, factor: string) => `${routes.challengeBase(purpose)}/${segment(factor)}`,
  send: (purpose: Purpose, factor: string) => `${routes.challengeBase(purpose)}/${segment(factor)}/send`,
  challengeBase: (purpose: Purpose) => `${prefix}${purpose === 'login' ? '/login/challenge' : '/confirm'}`,
  enroll: (factor: string) => `${prefix}/user/authenticators/${segment(factor)}`,
  confirmEnrollment: (factor: string) => `${prefix}/user/authenticators/${segment(factor)}/confirm`,
  authenticator: (id: string) => `${prefix}/user/authenticators/${segment(id)}`,
  proofOptions: (factor: string) => `${prefix}/user/authenticators/${segment(factor)}/proof-options`,
  sessions: () => `${prefix}/user/sessions`,
  session: (id: string) => `${prefix}/user/sessions/${segment(id)}`,
  ssoRedirect: (provider: string) => `${prefix}/auth/${segment(provider)}/redirect`,
  ssoCallback: (provider: string) => `${prefix}/auth/${segment(provider)}/callback`,
  ssoConfirm: (authenticator?: string) => `${prefix}/confirm/sso/redirect${authenticator ? `?authenticator=${encodeURIComponent(authenticator)}` : ''}`,
  impersonate: (user: string) => `${prefix}/impersonate/${segment(user)}`,
  stopImpersonating: () => `${prefix}/impersonate`,
}

/**
 * A factor's key or an ID as one path segment, whatever it holds. The server
 * issues these, but nothing says a page passes one on untouched, and a slash
 * or a question mark in one would aim the request, with the user's cookies,
 * at another path. "." and ".." have no encoding a browser won't resolve
 * away, so they're refused.
 */
function segment(value: string): string {
  if (value === '.' || value === '..') {
    throw new TypeError(`Keyring can't put [${value}] in a URL path.`)
  }

  return encodeURIComponent(value)
}

export type Purpose = 'login' | 'confirm'

/**
 * `prefix` is the server's route prefix, with or without its slashes
 * ("account" and "/account/" both work). Anything else replaces one route.
 */
export function configureRoutes({ prefix: path, ...overrides }: Partial<typeof routes> & { prefix?: string }): void {
  if (path !== undefined) {
    const trimmed = path.replace(/^\/+|\/+$/g, '')

    prefix = trimmed === '' ? '' : `/${trimmed}`
  }

  Object.assign(routes, overrides)
}
