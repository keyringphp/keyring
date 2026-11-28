<?php

declare(strict_types=1);

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Keyring\Enums\ImpersonationEndReason;

/**
 * An impersonation ended, in the request of the browser it was in: stopped,
 * timed out, or found ended or left with nobody to go back to. $returned
 * says whether the browser is back in the impersonator's own session, or
 * was signed out. $impersonator is null when they've since been deleted.
 * A session that lost what it had parked still names them, from its
 * record. $user is null when the user can no longer be loaded, deleted
 * say. One of the two is always there.
 *
 * $handle is the impersonated session's handle, as ImpersonationStarted
 * gave it: the same one Sessions::handle() gives and RegisteredSessionEnded
 * carries. It's null only when neither the session nor the impersonated
 * record says which session it was, such as an impersonation that started
 * before Keyring noted it. The event still fires, and the end is logged.
 */
class ImpersonationEnded
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public readonly ?Authenticatable $impersonator,
        public readonly ?Authenticatable $user,
        public readonly ImpersonationEndReason $reason,
        public readonly bool $returned,
        public readonly ?string $handle,
    ) {}
}
