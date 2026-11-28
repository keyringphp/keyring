import { json, KeyringRequestError } from './http.js'
import { routes } from './routes.js'

/**
 * Sign in as another user by their ID, where the server lets this user.
 * It needs a fresh second factor first: a 423 says where to confirm. A
 * refusal throws with a 403 `impersonation-refused`, whatever the reason.
 * Load the page in full afterwards, at the `redirect` it answers with.
 */
export function impersonate(user: string | number) {
  return json<{ status: string, redirect?: string }>('POST', routes.impersonate(String(user)))
}

/**
 * Go back to your own account. Load the page in full afterwards: at the
 * `redirect` it answers with, or the login page when it answers 401 because
 * your own session had ended meanwhile.
 *
 * An impersonation that had already ended by itself (its time ran out, or
 * the user ended its session) is answered with a 409 `impersonation-ended`
 * by the session middleware, having gone back all the same, and one another
 * tab already stopped with a 409 `not-impersonating`. Both resolve like
 * stopping did, with their own `status`, since you're back either way.
 */
export async function stopImpersonating() {
  try {
    return await json<{ status: string, redirect?: string }>('DELETE', routes.stopImpersonating())
  } catch (error) {
    if (error instanceof KeyringRequestError && error.status === 409 && (error.data?.status === 'impersonation-ended' || error.data?.status === 'not-impersonating')) {
      return { status: error.data.status as string, redirect: error.data.redirect as string | undefined }
    }

    throw error
  }
}
