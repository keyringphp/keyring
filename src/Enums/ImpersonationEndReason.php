<?php

declare(strict_types=1);

namespace Keyring\Enums;

/**
 * Why an impersonation ended (ImpersonationEnded). It ends back in the
 * impersonator's own session for Stopped, Expired and Revoked, as long as
 * that session is still good: otherwise the browser is signed out, and the
 * reason is ImpersonatorSessionEnded, or Lost.
 */
enum ImpersonationEndReason: string
{
    /** The impersonator stopped it. */
    case Stopped = 'stopped';

    /** It was on for impersonation.lifetime, or its session idled out. */
    case Expired = 'expired';

    /**
     * Its session was revoked some other way: by the user from their sessions
     * list, by signing out everywhere, a password change, a risk response,
     * the user no longer being allowed to sign in, or the impersonator no
     * longer being allowed to impersonate them.
     */
    case Revoked = 'revoked';

    /**
     * The impersonator's own session has ended (revoked, timed out), or the
     * impersonator was deleted, is no longer allowed to sign in, is held
     * for a new password, or their password changed, so there was nobody to
     * go back to and the browser was signed out. Under
     * sessions.end_on_lapse, also an impersonator whose session signed in
     * above AAL1: coming back at AAL1 would have lapsed it.
     */
    case ImpersonatorSessionEnded = 'impersonator_session_ended';

    /**
     * The browser's session no longer held the impersonation it started:
     * the user can no longer be loaded (deleted, say), someone else is
     * signed in on it, or it lost what was parked. Nothing says it's still
     * the impersonator's, so the browser was signed out. Also what a request
     * that another of the browser's beat to ending it returns, a copy of
     * the session from before it ended say: that one is signed out quietly,
     * and ImpersonationEnded doesn't fire for it, as the other request's
     * end is the one announced.
     */
    case Lost = 'lost';

    /**
     * The browser signed out while impersonating, or someone signed in on
     * a session still holding an impersonation.
     */
    case SignedOut = 'signed_out';

    /**
     * Starting it failed after its start was logged, handing the browser
     * over, so the browser stayed the impersonator's. Only ever in the
     * security log: ImpersonationEnded doesn't fire for it, as
     * ImpersonationStarted never did.
     */
    case Failed = 'failed';

    /**
     * Whether the impersonation goes back to the impersonator's session,
     * when that's still good.
     */
    public function returns(): bool
    {
        return in_array($this, [self::Stopped, self::Expired, self::Revoked], true);
    }
}
