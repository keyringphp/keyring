<?php

declare(strict_types=1);

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

/**
 * Someone signed in as another user (Keyring::impersonate). The user's own
 * Login and Authenticated events don't fire: they didn't sign in.
 *
 * $handle is the impersonated session's handle: the same one
 * Sessions::handle() gives, and the RegisteredSessionEnded that announces
 * its record ending carries, also for a browser that never comes back.
 */
class ImpersonationStarted
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public readonly Authenticatable $impersonator,
        public readonly Authenticatable $user,
        public readonly string $handle,
    ) {}
}
