import type { Purpose } from './routes.js'

/**
 * A sign-in method as the challenge page offers it.
 */
export interface AuthenticatorSummary {
  factor: string
  id: string | null
  name: string
  hint?: string
  remaining?: number
  replace?: boolean
}

/**
 * A sign-in method as a factor presents it everywhere else: in the answer to
 * adding or renaming one, and on your settings page. The dates are ISO 8601.
 * `lastUsedAt` is null until it's first used.
 */
export interface Authenticator extends AuthenticatorSummary {
  createdAt: string | null
  lastUsedAt: string | null
}

/**
 * Why an established sign-in method, or a set of recovery codes, can't be
 * removed or replaced just now, and until when (ISO 8601). It comes with a
 * `422`, as `data.frozen` on the `KeyringRequestError`, beside the usual
 * `message` and `errors.authenticator`. `skip` names the factors that could
 * make the change now (see `proveWithKey()`), and is empty when none can.
 */
export interface FrozenChanges {
  reason: 'new-authenticator' | 'recent-change'
  until: string
  skip: string[]
}

/**
 * A change an established sign-in method can make while the account's
 * sign-in methods are frozen: removing or renaming an authenticator, by
 * its ID, or replacing a factor's, by its key (`recovery` for new recovery
 * codes). A rename gives the `name` it renames to, and its proof only
 * works for that name.
 */
export type ProvableChange =
  | { action: 'remove' | 'replace', target: string }
  | { action: 'rename', target: string, name: string }

/**
 * What the change's own request sends as `proof`: a key's answer to a
 * challenge for that change, or a code from an authenticator app where
 * the server allows it. `authenticator` names which of the user's
 * authenticators of the factor to check, such as one of two apps. A
 * factor of the app's own reads its answer from its own fields.
 */
export interface FreezeProof {
  factor: string
  authenticator?: string
  credential?: Record<string, any>
  code?: string
  [field: string]: unknown
}

/**
 * A linked account at an identity provider, as the `sso` factor presents
 * it: the provider's name in `keyring.sso.providers`, and the address the
 * provider had for the account when it last signed in, if it gave one.
 */
export interface SsoAuthenticator extends Authenticator {
  factor: 'sso'
  provider: string
  email: string | null
}

/**
 * An identity provider the login page offers. `url` starts a sign in with
 * it: link to it, adding `?remember=1` for "remember me".
 */
export interface IdentityProvider {
  name: string
  label: string
  url: string
}

/**
 * Props Keyring sends to the login page. `providers` is empty until the
 * SingleSignOn factor is registered.
 */
export interface LoginProps {
  canResetPassword: boolean
  canRegister: boolean
  status: string | null
  providers: IdentityProvider[]
}

/**
 * Props Keyring sends to the challenge and confirm pages.
 */
export interface ChallengeProps {
  purpose: Purpose
  factor: string
  authenticator: AuthenticatorSummary
  challenge: Record<string, any>
  alternatives: AuthenticatorSummary[]
  canTrustDevice: boolean
  expiresAt: string
}

/**
 * The `challenge` of a link at an identity provider on the confirm page:
 * the provider, what it's called, and the URL that sends the user there to
 * sign in. confirmWithProvider() goes there for a frontend on another
 * origin.
 */
export interface SsoChallenge {
  provider: string
  label: string
  url: string
}

/**
 * What beginEnrollment() resolves with.
 */
export interface Enrollment {
  factor: string
  enrollment: Record<string, any>
}

/**
 * The `enrollment` of a link to an identity provider: where to send the
 * browser to finish it.
 */
export interface SsoEnrollment {
  provider: string
  url: string
}

/**
 * One of the user's sessions, as listSessions() returns it. `id` is a handle
 * for endSession(), not the session's own ID. It stays the same when the
 * session moves to a new record, and stops matching once the session ends,
 * so list again before ending one from an old list.
 */
export interface Session {
  id: string
  name: string | null
  ip: string | null
  device: string | null
  remembered: boolean
  signedInAt: string
  lastActiveAt: string
  expiresAt: string
  current: boolean
  /**
   * Someone else is signed in to it as the user, e.g. support. Its `name`,
   * `ip` and `device` are then always null: they'd be that person's.
   */
  impersonated: boolean
  /**
   * Who that is, by name only, or null when nobody else is in it or the
   * impersonator has been deleted.
   */
  impersonator: { name: string | null } | null
}

/**
 * Who is impersonating the signed-in user, as Keyring::impersonation()
 * gives it to share with every page, for a banner with a way to stop.
 * Share null when nobody is.
 */
export interface Impersonation {
  impersonator: { id: string, name: string | null }
  startedAt: string
  expiresAt: string
  stopUrl: string | null
}
