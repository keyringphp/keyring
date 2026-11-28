<?php

declare(strict_types=1);

namespace Keyring\Enums;

/**
 * Why Keyring wouldn't start an impersonation. Disabled and NoCallback
 * mean the app hasn't set it up yet, rather than that this impersonator
 * was turned down.
 */
enum ImpersonationRefusal: string
{
    // Features::impersonation() is off.
    case Disabled = 'disabled';

    // The feature is on, but Keyring::allowImpersonationWhen() was never
    // called, so nobody may impersonate anyone yet.
    case NoCallback = 'no_callback';

    // The impersonator asked to sign in as themselves.
    case Self = 'self';

    // The callback didn't answer true, the user may not sign in
    // (allowSignInWhen), or one of the two isn't an account Keyring's
    // guard loads.
    case NotAllowed = 'not_allowed';

    // Keyring's route found nobody with the ID asked for. It's only
    // logged: what's thrown is NotAllowed, so the answer doesn't say which
    // IDs have an account.
    case NotFound = 'not_found';

    // The session is impersonating someone already. It's one at a time.
    case Impersonating = 'impersonating';

    // The impersonator's session has no record in the registry, so there
    // would be nothing to come back to.
    case Unregistered = 'unregistered';
}
