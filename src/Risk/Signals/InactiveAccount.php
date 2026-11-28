<?php

declare(strict_types=1);

namespace Keyring\Risk\Signals;

use Keyring\Contracts\SessionRegistry;
use Keyring\Facades\Keyring;
use Keyring\Features;
use Keyring\Risk\Assessment;
use Keyring\Risk\Finding;
use Keyring\Sessions\RegisteredSession;
use Keyring\Support\Duration;

/**
 * The account's first sign in for a long while, 90 days unless told
 * otherwise. An account nobody is using is where a leaked password gets
 * tried without anyone noticing.
 *
 * It goes by when the account's devices last signed in, so it needs
 * Features::devices(), and it says nothing about an account Keyring has no
 * sign in on record for. One with a session still in use isn't quiet,
 * however long ago that session began, unless it's impersonated: that's
 * someone else in the account, not its owner.
 */
class InactiveAccount extends Signal
{
    /** What its finding is called, in Risk::has(). */
    public const string FINDING = 'inactive_account';

    public function __construct(
        protected SessionRegistry $sessions,
        protected int $score = 30,
        protected string $after = '90d',
    ) {}

    public function assess(Assessment $assessment): ?Finding
    {
        if (! Features::enabled(Features::devices())) {
            return null;
        }

        $last = Keyring::deviceModel()::query()
            ->ownedBy($assessment->user)
            ->whereNotNull('last_seen_at')
            ->latest('last_seen_at')
            ->first()
            ?->last_seen_at;

        $quietSince = now()->getTimestamp() - Duration::seconds($this->after);

        if ($last === null || $last->getTimestamp() > $quietSince || $this->inUseSince($assessment, $quietSince)) {
            return null;
        }

        return new Finding(self::FINDING, $this->score, sprintf('The first sign in for %d days.', $last->diffInDays(now())));
    }

    /**
     * Whether one of the user's own sessions has been used since the given
     * time. An impersonated one is someone else using the account.
     */
    protected function inUseSince(Assessment $assessment, int $since): bool
    {
        return $this->sessions->forUser($assessment->user)->contains(fn (RegisteredSession $session) => ! $session->isImpersonated() && $session->lastActivityAt > $since);
    }
}
