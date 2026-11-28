<?php

declare(strict_types=1);

namespace Keyring\Sessions;

use Illuminate\Container\Attributes\Scoped;
use Illuminate\Contracts\Session\Session;
use Keyring\Enums\Assurance;
use Keyring\Enums\Category;
use Keyring\Enums\Purpose;
use Keyring\KeyringManager;
use Keyring\Login\AttemptStore;
use Keyring\Login\Requirement;
use Keyring\Login\Verification;

/**
 * What the signed-in user has proved during this session, and when. Used by
 * the assurance and freshness middleware.
 *
 * Each level lapses on its own clock: it only counts
 * verifications made within its overall limit (sessions.levels.aal2.absolute,
 * 24 hours by default), and inactivity past its idle limit (an hour at AAL2)
 * lapses it until the user proves every factor for it again. The session
 * itself stays signed in at whatever level is left, unless
 * sessions.end_on_lapse says a session ends with the level it signed in at.
 */
#[Scoped]
class SessionAssurance
{
    public const string KEY = 'keyring.verified';

    /** When the session was last active, for the idle limits. */
    public const string ACTIVE = 'keyring.active_at';

    /** When inactivity last lapsed each level, keyed by the level's value. */
    public const string LAPSED = 'keyring.lapsed_at';

    /** The level the session signed in at, as its value. */
    public const string SIGNED_IN = 'keyring.signed_in_level';

    public function __construct(
        protected Session $session,
        protected Sessions $sessions,
        protected KeyringManager $keyring,
    ) {}

    /**
     * Replace what's recorded, for a brand new login.
     *
     * @param  list<Verification>  $verifications
     */
    public function reset(array $verifications): void
    {
        $this->flush();
        $this->record($verifications);
        $this->session->put(static::SIGNED_IN, Assurance::of($verifications)->value);
    }

    /**
     * Add verifications, keeping the latest for each authenticator.
     *
     * @param  list<Verification>  $verifications
     */
    public function record(array $verifications): void
    {
        $stored = $this->session->get(static::KEY, []);

        foreach ($verifications as $verification) {
            $stored[$verification->authenticator ?? $verification->factor] = $verification->toArray();
        }

        $this->session->put(static::KEY, $stored);
        $this->session->put(static::ACTIVE, now()->getTimestamp());
    }

    /**
     * Bring the session down to AAL1 at most, so anything that asks for
     * more asks for the second factor again. Of what it proved, only as
     * much as stays short of AAL2 is kept, what isn't something the user
     * has first: a password beside an authenticator app keeps the password,
     * while an authenticator app's code on its own, short of AAL2 alone, is
     * kept as it is. What's kept still counts as before, so stepping up
     * asks for the second factor alone. A session that proved nothing short
     * of AAL2, a passkey that verified the user being both factors at once,
     * keeps nothing.
     *
     * The level the session signed in at isn't touched, so under
     * sessions.end_on_lapse one that signed in above AAL1 lapses from here.
     *
     * @internal
     */
    public function lowerToAal1(): void
    {
        $kept = [];
        $stored = $this->session->get(static::KEY, []);

        // What isn't something the user has goes first, so it's what's kept.
        uasort($stored, fn (array $a, array $b) => in_array(Category::Possession->value, $a['categories'], true) <=> in_array(Category::Possession->value, $b['categories'], true));

        foreach ($stored as $key => $verification) {
            if (! Assurance::of(array_map(Verification::fromArray(...), [...array_values($kept), $verification]))->atLeast(Assurance::AAL2)) {
                $kept[$key] = $verification;
            }
        }

        $this->session->put(static::KEY, $kept);
    }

    /**
     * Note a request, lapsing any level whose idle limit passed since the
     * last one. Call it before checking the level.
     */
    public function touch(): void
    {
        $now = now()->getTimestamp();
        $active = $this->session->get(static::ACTIVE);

        if (is_int($active)) {
            $lapsed = array_find([Assurance::AAL1, Assurance::AAL2, Assurance::AAL3], function (Assurance $level) use ($now, $active) {
                $idle = $this->sessions->idle($level);

                return $idle !== null && $now - $active > $idle;
            });

            // A lapsed level takes the ones above it along. What was verified
            // before now stops counting toward them, so one factor proved
            // afterwards can't bring back a level that needs two.
            if ($lapsed !== null) {
                $this->session->put(static::LAPSED, array_replace(
                    $this->session->get(static::LAPSED, []),
                    array_fill_keys(range($lapsed->value, Assurance::AAL3->value), $now),
                ));
            }
        }

        $this->session->put(static::ACTIVE, $now);
    }

    /**
     * Record a step-up confirmation. It also satisfies Laravel's own
     * password.confirm middleware, so apps can keep using it: its marker
     * goes to when the user last really proved one of $added, what the
     * confirm proved itself (Verification::provedAt()), all of it when
     * that's not given. What the confirm built on was proved before it, at
     * sign in say, and confirms nothing. A confirm that added only what
     * can't say when, like a round trip to an identity provider whose sign
     * ins are never fresh, leaves the marker as it was, and so does one
     * that proved nothing later than it.
     *
     * @param  list<Verification>  $verifications
     * @param  list<Verification>|null  $added
     */
    public function confirm(array $verifications, ?array $added = null): void
    {
        $this->record($verifications);

        $provedAt = max([Verification::UNKNOWN, ...array_map(fn (Verification $verification) => $verification->provedAt(), $added ?? $verifications)]);

        if ($provedAt > (int) $this->session->get('auth.password_confirmed_at', 0)) {
            $this->session->put('auth.password_confirmed_at', $provedAt);
        }
    }

    /**
     * What still counts: an authenticator removed since, say a stolen key the
     * owner took off their account, stops counting in every session it was
     * used in.
     *
     * @return list<Verification>
     */
    public function all(): array
    {
        $verifications = $this->recorded();
        $ids = array_column($verifications, 'authenticator') |> array_filter(...) |> array_values(...);

        if ($ids === []) {
            return $verifications;
        }

        $kept = $this->keyring->authenticatorModel()::query()->whereKey($ids)->pluck('id')->all();

        return array_values(array_filter($verifications, fn (Verification $verification) => $verification->authenticator === null || in_array($verification->authenticator, $kept, true)));
    }

    /**
     * Verifications made since the given timestamp.
     *
     * @return list<Verification>
     */
    public function since(int $timestamp): array
    {
        return array_values(array_filter($this->all(), fn (Verification $verification) => $verification->at >= $timestamp));
    }

    /**
     * Verifications the user proved since the given timestamp: by when they
     * really proved each one (Verification::provedAt()), so a sign in an
     * identity provider let through on a session it already had is as old
     * as that session. This is what freshness asks.
     *
     * @return list<Verification>
     */
    public function provedSince(int $timestamp): array
    {
        return array_values(array_filter($this->all(), fn (Verification $verification) => $verification->provedAt() >= $timestamp));
    }

    /**
     * The highest level the session holds right now. Given a timestamp, the
     * highest it holds from what was proved since then alone, each level
     * still on its own clock: a level that lapsed isn't rebuilt from what
     * counts toward a lower one.
     */
    public function level(int $since = 0): Assurance
    {
        return Assurance::highest(fn (Assurance $level) => $this->countingToward($level, $since));
    }

    /**
     * The verifications that still count toward a level: those within its
     * overall limit, and made since inactivity last lapsed it. Given a
     * timestamp, only those made since then too.
     *
     * @return list<Verification>
     */
    public function countingToward(Assurance $level, int $since = 0): array
    {
        return $this->since(max($this->countsFrom($level), $since));
    }

    /**
     * Why the level the session signed in at no longer holds, if it
     * doesn't and sessions.end_on_lapse is on: "idle" past its idle limit,
     * "expired" past its overall one. NIST SP 800-63B-4 (Sec. 5.2) ends a
     * session when either passes. Proving every factor for the level again
     * in time starts both over, as reauthenticating does there.
     *
     * A level a step-up reached later lapses on its own and takes nothing
     * with it, and an authenticator removed since doesn't end the sessions
     * it signed in: only time does.
     *
     * @return 'idle'|'expired'|null
     */
    public function lapse(): ?string
    {
        $level = $this->signedInLevel();

        if (! $this->endsOnLapse()) {
            return null;
        }

        $from = $this->countsFrom($level);

        if (Requirement::for($level)->isMetBy(array_values(array_filter($this->recorded(), fn (Verification $verification) => $verification->at >= $from)))) {
            return null;
        }

        return $from > now()->getTimestamp() - $this->sessions->absolute($level) ? 'idle' : 'expired';
    }

    /**
     * The level this session signed in at. None for one Keyring didn't sign
     * in itself, such as a session an app started with Auth::login().
     */
    public function signedInLevel(): Assurance
    {
        return Assurance::tryFrom((int) $this->session->get(static::SIGNED_IN, 0)) ?? Assurance::None;
    }

    /**
     * Whether this session is one sessions.end_on_lapse ends once the level
     * it signed in at has gone.
     */
    public function endsOnLapse(): bool
    {
        return config('keyring.sessions.end_on_lapse') && $this->signedInLevel() !== Assurance::None;
    }

    /**
     * The moment a verification must be no older than to count toward a
     * level: its overall limit ago, or when inactivity last lapsed it.
     */
    protected function countsFrom(Assurance $level): int
    {
        return max(
            now()->getTimestamp() - $this->sessions->absolute($level),
            $this->session->get(static::LAPSED, [])[$level->value] ?? 0,
        );
    }

    /**
     * Everything recorded, whether or not its authenticator is still there.
     *
     * @return list<Verification>
     */
    protected function recorded(): array
    {
        return array_map(Verification::fromArray(...), array_values($this->session->get(static::KEY, [])));
    }

    /**
     * Forget everything proved this session, including a confirmation in
     * progress and the marker that keeps Laravel's own password.confirm
     * middleware satisfied.
     */
    public function flush(): void
    {
        $this->session->forget([static::KEY, static::LAPSED, static::SIGNED_IN, AttemptStore::key(Purpose::Confirm), 'auth.password_confirmed_at']);
    }
}
