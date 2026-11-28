<?php

declare(strict_types=1);

namespace Keyring\Sessions;

use Closure;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Auth\Events\CurrentDeviceLogout;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Session\CookieSessionHandler;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Str;
use Keyring\Changes\PendingEmailChanges;
use Keyring\Contracts\SessionRegistry;
use Keyring\Devices\UserAgent;
use Keyring\Enums\Assurance;
use Keyring\Enums\SessionEndReason;
use Keyring\Events\SessionsRevoked;
use Keyring\Features;
use Keyring\Impersonation\Impersonation;
use Keyring\KeyringManager;
use Keyring\Models\Device;
use Keyring\Support\Cookies;
use Keyring\Support\Duration;
use Keyring\Support\KeyedHash;
use Keyring\Support\RowLock;
use Keyring\Support\Throttle;
use LogicException;
use PDOException;
use Throwable;

/**
 * Starts, finds and ends registered sessions for the current request.
 */
class Sessions
{
    public const string KEY = 'keyring.session';

    /**
     * Set on a session "remember me" may bring back. On one with no record
     * yet, a "remember me" cookie signed it in and the record it goes with
     * is still to be found (AuthenticateSession).
     */
    public const string REMEMBERED = 'keyring.remembered';

    public function __construct(
        protected SessionRegistry $registry,
        protected KeyringManager $keyring,
        protected PendingEmailChanges $emailChanges,
    ) {}

    public function start(Request $request, Authenticatable $user, ?Device $device, Assurance $assurance, bool $remembered = false): RegisteredSession
    {
        $now = now()->getTimestamp();

        $session = new RegisteredSession(
            id: Str::random(40),
            userId: (string) $user->getAuthIdentifier(),
            userType: RegisteredSession::typeOf($user),
            guard: config('keyring.guard'),
            deviceId: $device?->id,
            assurance: $assurance,
            ip: $this->keyring->recordedIp($request),
            userAgent: UserAgent::from($request),
            authenticatedAt: $now,
            lastActivityAt: $now,
            expiresAt: $now + $this->absolute(),
            remembered: $remembered,
        );

        $previous = $request->session()->get(self::KEY);

        $this->register($user, $session);
        $this->bind($request, $session, $remembered);

        // A browser that signs in while it's signed in leaves the session it
        // was on. Ending it is all that stops a copy of the old cookie
        // carrying on with it on the cookie session driver, and on any
        // driver it would be listed and counted with nobody left on it.
        if (is_string($previous)) {
            $this->because(SessionEndReason::SignedInAgain, fn () => $this->registry->revoke($previous));
        }

        return $session;
    }

    /**
     * Register the session someone signs in to as $user (Impersonation),
     * naming them and the record of their own session, which is left as it
     * is to come back to. It proved nothing, is never remembered, is on no
     * device, and lasts no longer than the impersonation may. It keeps no
     * IP address or browser: they'd be the impersonator's, and the record
     * is the user's, listed to them. It's saved as it is: it ends none of
     * the user's sessions to keep them to "sessions.max", and none of the
     * impersonator's.
     */
    public function startImpersonation(Authenticatable $user, Authenticatable $impersonator, #[\SensitiveParameter] RegisteredSession $parked, int $until): RegisteredSession
    {
        $now = now()->getTimestamp();

        $session = new RegisteredSession(
            id: Str::random(40),
            userId: (string) $user->getAuthIdentifier(),
            userType: RegisteredSession::typeOf($user),
            guard: config('keyring.guard'),
            deviceId: null,
            assurance: Assurance::None,
            ip: null,
            userAgent: null,
            authenticatedAt: $now,
            lastActivityAt: $now,
            expiresAt: min($now + $this->absolute(), $until),
            impersonatorId: (string) $impersonator->getAuthIdentifier(),
            impersonatorType: RegisteredSession::typeOf($impersonator),
            impersonatorSession: $parked->id,
        );

        $this->registry->save($session);

        return $session;
    }

    /**
     * Point the request's session at a record it's moving to without a new
     * "remember me" cookie: the browser keeps the one it has, which still
     * names the record it was issued with (Impersonation).
     */
    public function rebind(Request $request, #[\SensitiveParameter] RegisteredSession $session, bool $remembered): void
    {
        $request->session()->put(self::KEY, $session->id);
        $request->attributes->set(self::KEY, $session->id);

        $remembered ? $request->session()->put(self::REMEMBERED, true) : $request->session()->forget(self::REMEMBERED);
    }

    /**
     * Store a new session, and keep the account to "sessions.max" of them:
     * past that, whichever has gone unused longest ends. Sessions someone
     * is impersonating the user in neither count nor end. Refusing the sign
     * in instead would let whoever holds an account's sessions keep its
     * owner out. Two sign ins at once take turns (holding), so neither
     * counts the sessions without the other's.
     *
     * A revocation that fails takes the whole sign in with it. On the
     * database driver sharing the user's connection, the row lock's
     * transaction is rolled back, the new record included. On a driver
     * that announces straight away, the new record is revoked again,
     * unannounced (withdraw), before the lock is let go, so it doesn't count
     * toward the limit, and the sessions ended before the failure stay
     * ended.
     */
    protected function register(Authenticatable $user, RegisteredSession $session): void
    {
        if (($max = config('keyring.sessions.max')) === null) {
            $this->registry->save($session);

            return;
        }

        $this->holdingThenThrow($user, function () use ($user, $session, $max) {
            $this->registry->save($session);

            try {
                $now = now()->getTimestamp();

                $this->registry->forUser($user)
                    ->reject(fn (RegisteredSession $other) => $other->id === $session->id || $other->isImpersonated())
                    ->sortBy([
                        // One that has idled out is over already, so it goes first.
                        fn (RegisteredSession $a, RegisteredSession $b) => $this->idledOut($a, $now) <=> $this->idledOut($b, $now),
                        fn (RegisteredSession $a, RegisteredSession $b) => $b->lastActivityAt <=> $a->lastActivityAt,
                    ])
                    ->skip(max(0, (int) $max - 1))
                    // By ID, byte by byte. That's the order the sweep and
                    // revokeAll() lock rows in where the database sorts IDs the
                    // same way (SQLite, or a binary or "C" collation). Where it
                    // sorts them otherwise (MySQL's utf8mb4_*_ci, PostgreSQL's
                    // locale collations), this and a sweep ending the same
                    // sessions can deadlock now and then: the database ends one,
                    // the sweep tries again, and the sign in fails as it would
                    // on any database error.
                    ->sortBy(fn (RegisteredSession $other) => $other->id, SORT_STRING)
                    ->each(fn (RegisteredSession $other) => $this->because(SessionEndReason::SessionLimit, fn () => $this->registry->revoke($other->id)));
            } catch (Throwable $e) {
                // No rollback takes the new record back on a driver that
                // announces straight away. It's revoked while the lock is
                // still held, so no other sign in counts it, and on the
                // driver underneath, unannounced, as nobody used the session.
                if ($this->registry instanceof AnnouncingSessionRegistry && $this->registry->announcesStraightAway()) {
                    $this->withdraw($session->id);
                }

                throw $e;
            }
        });
    }

    /**
     * Run a change to which sessions a user has while holding the user's
     * row, so it and any other wait for each other. A session moving to a
     * new record is such a change: if a sign-out everywhere could run in the
     * middle of one, it would revoke the old record and miss the new.
     *
     * @template TResult
     *
     * @param  Closure(): TResult  $change
     * @return TResult
     */
    protected function holding(Authenticatable $user, Closure $change): mixed
    {
        return $user instanceof Model ? RowLock::hold($user, fn () => $change()) : $change();
    }

    /**
     * holding(), then a callback that runs whether or not the change
     * failed, outside the user's row lock, and the change's failure thrown
     * after it.
     *
     * The row lock is a transaction on the user's connection. On a driver
     * that announces straight away (AnnouncingSessionRegistry), a
     * synchronous listener runs inside it: thrown from inside, a failure
     * part way through would roll back what the listeners wrote for the
     * sessions that did end, a job on a database queue included. So there
     * the failure is held until the lock's transaction has committed, which
     * keeps only what happened. Inside a transaction of the app's own, the
     * failure, once thrown, still rolls that back unless the app catches it.
     *
     * On the database driver sharing the user's connection, the failure is
     * thrown from inside, as the change is all or nothing: the revocations
     * it made and the announcements waiting on them are rolled back
     * together. So is any database failure, on any driver (canThrowLater):
     * it may have left the transaction unusable, and committing it would
     * run its after-commit callbacks for work that was rolled back.
     *
     * @template TResult
     *
     * @param  Closure(): TResult  $change
     * @param  (Closure(): void)|null  $then  Run whether or not the change failed.
     * @return TResult
     */
    protected function holdingThenThrow(Authenticatable $user, Closure $change, ?Closure $then = null): mixed
    {
        try {
            $outcome = $this->holding($user, function () use ($change): Closure {
                try {
                    $result = $change();

                    return fn () => $result;
                } catch (Throwable $e) {
                    if (! $this->canThrowLater($e)) {
                        throw $e;
                    }

                    return fn () => throw $e;
                }
            });
        } catch (Throwable $e) {
            $outcome = fn () => throw $e;
        }

        try {
            $then?->__invoke();
        } finally {
            $result = $outcome();
        }

        return $result;
    }

    /**
     * Whether a change's failure can wait until the user's row is let go:
     * only when the registry announces straight away, and the failure came
     * from nowhere near a database (no PDOException, which Laravel's
     * QueryException and DeadlockException are too, anywhere in its
     * chain). Any failed query may have left the
     * connection's transaction unusable: on PostgreSQL a COMMIT after one
     * silently rolls back, and Laravel would still run its after-commit
     * callbacks.
     */
    protected function canThrowLater(Throwable $e): bool
    {
        if (! $this->registry instanceof AnnouncingSessionRegistry || ! $this->registry->announcesStraightAway()) {
            return false;
        }

        for ($cause = $e; $cause !== null; $cause = $cause->getPrevious()) {
            if ($cause instanceof PDOException) {
                return false;
            }
        }

        return true;
    }

    /**
     * Make a change only a signed-in session may make, holding the user's
     * row so it and a sign-out everywhere take turns, and refusing if this
     * request's session has been ended since its middleware let it through
     * (an email change undone, a password reset, a device reported).
     * Without this a request already under way would still save its change
     * after the account's owner had ended every session. The change is
     * given the user as the locked row has it.
     *
     * A session whose record has gone is an ended one, as it is to the
     * session middleware. A request with no session, or one Keyring never
     * registered, isn't one Keyring keeps track of, and is let through.
     *
     * The row is held on the user's own connection. Where what's being
     * changed is kept on another, the two can't commit as one, and the lock
     * goes a moment before the change is saved. And on MySQL, a caller
     * that has already read inside a transaction of its own reads the
     * registry as it was then: Keyring's routes open none.
     *
     * @template TResult
     *
     * @param  Closure(Authenticatable&Model): TResult  $change
     * @return TResult
     *
     * @throws AuthenticationException
     */
    public function whileSignedIn(Request $request, Authenticatable&Model $user, Closure $change): mixed
    {
        return RowLock::hold($user, function (?Model $fresh) use ($request, $change) {
            if (! $fresh instanceof Authenticatable) {
                throw new AuthenticationException;
            }

            $id = $request->hasSession() ? $request->session()->get(self::KEY) : null;

            if (is_string($id)) {
                $session = $this->registry->find($id);

                if ($session === null || ! $session->isActive(now()->getTimestamp()) || ! $session->belongsTo($fresh)) {
                    throw new AuthenticationException;
                }
            }

            return $change($fresh);
        });
    }

    /**
     * Carry a remembered session on in the new session its "remember me"
     * cookie signed in, under a new record and a new cookie. The cookie that
     * came is used up: a copy of it brings nothing back. The new record is a
     * copy of the old, so it keeps the limits it started with and the record
     * it started on (origin), but its address and browser are this
     * request's. The cookie proved nothing, so the level starts again.
     *
     * Null when the record couldn't be replaced: a request sent alongside
     * this one used the cookie first, or the session was just revoked.
     */
    public function resume(Request $request, Authenticatable $user, RegisteredSession $session): ?RegisteredSession
    {
        $current = $session->with([
            'id' => Str::random(40),
            'origin' => $session->origin(),
            'assurance' => Assurance::None,
            'ip' => $this->keyring->recordedIp($request),
            'userAgent' => UserAgent::from($request),
            'lastActivityAt' => now()->getTimestamp(),
        ]);

        if (! $this->holding($user, fn () => $this->registry->replace($session->id, $current))) {
            return null;
        }

        $this->bind($request, $current, remembered: true);

        return $current;
    }

    /**
     * The session a request may join when the cookie it came with was used
     * up a moment ago. A browser coming back often sends several requests at
     * once, all with the same cookie. The first replaces it, and the rest
     * belong on that session, not signed out.
     *
     * Only within "sessions.remember_grace" of the cookie being replaced,
     * however often it's sent, and only for the browser that replaced it:
     * the same cookie from two browsers is two holders, however close
     * together. Null for anything else.
     */
    public function overlapped(Request $request, RegisteredSession $replaced): ?RegisteredSession
    {
        if ($replaced->replacedBy === null || now()->getTimestamp() - (int) $replaced->replacedAt >= Duration::seconds(config('keyring.sessions.remember_grace') ?? 0)) {
            return null;
        }

        $session = $this->registry->find($replaced->replacedBy);

        return $session?->userAgent === UserAgent::from($request) ? $session : null;
    }

    /**
     * Put a request on the session one sent alongside it resumed
     * (overlapped). Nothing is registered and the record stays as that
     * request left it, so a used cookie can't start a session of its own.
     */
    public function join(Request $request, RegisteredSession $session): void
    {
        $this->bind($request, $session, remembered: true);
    }

    /**
     * The session a replaced record became, however many times it has moved
     * since. Null when that record is gone.
     */
    public function latest(?RegisteredSession $session): ?RegisteredSession
    {
        while ($session?->replacedBy !== null) {
            $session = $this->registry->find($session->replacedBy);
        }

        return $session;
    }

    /**
     * Point the request's session at its record. A remembered one also gets
     * the cookie that lets "remember me" bring it back.
     */
    protected function bind(Request $request, RegisteredSession $session, bool $remembered): void
    {
        $request->session()->put(self::KEY, $session->id);
        $request->attributes->set(self::KEY, $session->id);

        if (! $remembered) {
            $request->session()->forget(self::REMEMBERED);

            return;
        }

        $request->session()->put(self::REMEMBERED, true);
        $this->queueRememberCookie($request, $session);
    }

    /**
     * The user's sessions that can still be carried on, most recently active
     * first. One that has idled out is over, though its record only says so
     * once something comes across it.
     *
     * @return Collection<int, RegisteredSession>
     */
    public function active(Authenticatable $user): Collection
    {
        $now = now()->getTimestamp();

        return $this->registry->forUser($user)
            ->reject(fn (RegisteredSession $session) => $this->idledOut($session, $now))
            ->values();
    }

    /**
     * The user's sessions for a "where you're signed in" page, most recently
     * active first, each under its handle. One someone else is signed in to
     * as the user is marked "impersonated", with who it is by name, as long
     * as "impersonation.show_in_sessions" is on. With it off, it's left
     * out, unless it's the session asking. It has no name, IP address or
     * device, whatever its record holds: they'd be the impersonator's.
     *
     * @return Collection<int, array{id: string, name: ?string, ip: ?string, device: ?string, remembered: bool, signedInAt: string, lastActiveAt: string, expiresAt: string, current: bool, impersonated: bool, impersonator: array{name: ?string}|null}>
     */
    public function list(Request $request, Authenticatable $user): Collection
    {
        $current = $request->session()->get(self::KEY);
        $time = fn (int $timestamp) => now()->setTimestamp($timestamp)->toIso8601String();
        $shown = config('keyring.impersonation.show_in_sessions') !== false;

        return $this->active($user)
            ->reject(fn (RegisteredSession $session) => $session->isImpersonated() && ! $shown && $session->id !== $current)
            ->values()
            ->map(fn (RegisteredSession $session) => [
                'id' => $this->handle($session),
                'name' => $session->isImpersonated() ? null : $this->keyring->describeDevice($session->userAgent),
                'ip' => $session->isImpersonated() ? null : $session->ip,
                'device' => $session->isImpersonated() ? null : $session->deviceId,
                'remembered' => $session->remembered,
                'signedInAt' => $time($session->authenticatedAt),
                'lastActiveAt' => $time($session->lastActivityAt),
                'expiresAt' => $time($session->expiresAt),
                'current' => $session->id === $current,
                'impersonated' => $session->isImpersonated(),
                'impersonator' => $session->isImpersonated() ? app(Impersonation::class)->describe($session) : null,
            ]);
    }

    /**
     * What a session goes by outside the server. Its registry ID is what the
     * "remember me" cookie carries, so that never reaches a page: whoever
     * could read it there could come back as the session. The handle is a
     * keyed hash of the ID of the record the session started on (origin),
     * so it stays the same when the session moves to a new record. It picks
     * the session out from its user's others and leads nowhere else: not
     * back to an ID, and to nothing at all in a cookie.
     */
    public function handle(RegisteredSession $session): string
    {
        return $this->handles($session)[0];
    }

    /**
     * Every handle the session goes by: under the current app key first,
     * then under each of the previous keys (APP_PREVIOUS_KEYS), so a handle
     * kept from before the key was rotated still names its session.
     *
     * A record with no IDs, such as the one a queued SessionResumed or
     * RememberMeReused carries, has no handle: every such record would get
     * the same one. Use the event's own handle instead.
     *
     * @return non-empty-list<string>
     *
     * @throws LogicException when the record's IDs have been blanked
     */
    public function handles(RegisteredSession $session): array
    {
        if ($session->origin() === '') {
            throw new LogicException('This session record has no registry IDs, so it has no handle. A queued event carries its handle as $event->handle.');
        }

        return KeyedHash::candidates(KeyedHash::SESSION_HANDLES, $session->origin());
    }

    /**
     * The user's session with this handle, if it's one that can still be
     * carried on. Only ever looked for among the user's own. A handle given
     * under a previous app key still counts. Each of the session's handles
     * is compared whichever matches, so how long it takes doesn't say which.
     */
    public function find(Authenticatable $user, string $handle): ?RegisteredSession
    {
        return $this->active($user)->first(fn (RegisteredSession $session) => array_reduce(
            $this->handles($session),
            fn (bool $found, string $candidate) => hash_equals($candidate, $handle) || $found,
            false,
        ));
    }

    /**
     * Whether the user is still signed in on the session with this handle,
     * for code that knows a session by its handle and nothing else. Only
     * while the app still lets the user sign in (Keyring::allowSignInWhen),
     * and the session can still be carried on, under Keyring's guard.
     * Asking changes nothing: it doesn't count as activity, so it never
     * keeps a session from idling out.
     */
    public function stillSignedIn(Authenticatable $user, string $handle): bool
    {
        if (! $user instanceof Model || ! $this->keyring->allowsSignIn($user)) {
            return false;
        }

        return $this->find($user, $handle)?->guard === config('keyring.guard');
    }

    /**
     * End one of the user's sessions, wherever it is by now: "remember me"
     * may have carried it on to another record since it was listed.
     */
    public function revoke(Authenticatable $user, #[\SensitiveParameter] RegisteredSession $session): void
    {
        $this->holding($user, function () use ($session) {
            if ($current = $this->latest($this->registry->find($session->id))) {
                $this->registry->revoke($current->id);
            }
        });
    }

    /**
     * End the session a record has become by now, holding the user's row so
     * a move to a new record can't slip in between finding it and ending
     * it: the move either lands first and is followed, or waits and finds
     * its record ended. Returns the record that was ended, or null when
     * there was nothing left to end.
     */
    public function endLatest(Authenticatable $user, #[\SensitiveParameter] RegisteredSession $session): ?RegisteredSession
    {
        return $this->holding($user, function () use ($session) {
            $current = $this->latest($this->registry->find($session->id));

            if ($current === null || ! $current->isActive(now()->getTimestamp())) {
                return null;
            }

            $this->registry->revoke($current->id);

            return $current;
        });
    }

    /**
     * The record the request's session is on. Its ID is noted on the
     * request too, so end() can still find it if the app empties the
     * session before signing out.
     */
    public function current(Request $request): ?RegisteredSession
    {
        $id = $request->session()->get(self::KEY);

        if (! is_string($id)) {
            return null;
        }

        $request->attributes->set(self::KEY, $id);

        return $this->registry->find($id);
    }

    /**
     * Record the level a step-up reached, for the sessions list. The session
     * keeps its own limits; levels lapse on their own (SessionAssurance).
     */
    public function elevate(Request $request, Assurance $assurance): void
    {
        $session = $this->current($request);

        if ($session !== null && $assurance->value > $session->assurance->value) {
            $this->registry->update($session->id, ['assurance' => $assurance]);
        }
    }

    /**
     * The session's ID is only forgotten once its record is revoked. A
     * registry that throws leaves it in place, so the next request finds
     * the record still open and signs out again, rather than finding a
     * signed-in session with no record and registering it afresh.
     *
     * A session the app emptied before signing out, with invalidate() or
     * flush() ahead of Auth::logout(), is ended by the ID the request
     * noted (bind, current). Given a copy, like a form request passed to
     * SignIn::out(), only the copy forgets the ID, so the Logout listener
     * revokes again from request(): the record has ended, so nothing is
     * announced twice.
     */
    public function end(Request $request): void
    {
        $id = $request->session()->get(self::KEY) ?? $request->attributes->get(self::KEY);

        try {
            if (is_string($id)) {
                $this->registry->revoke($id);
                $request->attributes->remove(self::KEY);
            }

            $request->session()->forget(self::KEY);
        } finally {
            $request->session()->forget(self::REMEMBERED);
            $this->forgetRememberCookie($request);
        }
    }

    /**
     * Give the current session a new ID, so a copy of it made before now
     * stops working: after a step-up, a password change, signing out
     * everywhere else. Regenerating destroys the old session on the server.
     * A cookie session lives in the browser, where nothing can destroy a
     * copy, so its registry record is swapped for a new one and the old one
     * revoked.
     */
    public function rotate(Request $request): void
    {
        if ($request->session()->getHandler() instanceof CookieSessionHandler) {
            $this->reregister($request);
        }

        $request->session()->regenerate(true);
    }

    /**
     * Swap the session's registry record for a new one and revoke the old.
     * Only this request's copy of the session learns the new ID, so any
     * other copy from before now (an older cookie, a request that overlapped
     * and saves later) is signed out when it's next used. The old record
     * names the new one, so a "remember me" cookie used up before the swap
     * can still be followed to the session it became (latest).
     *
     * Returns whether it moved. It doesn't when the session has no record
     * or nobody is signed in, nor when the record has ended or moved on
     * without this request: of two requests moving it at once, only one
     * does.
     *
     * @param  array<string, mixed>  $changes
     */
    public function reregister(Request $request, array $changes = []): bool
    {
        $session = $this->current($request);
        $user = $this->keyring->guard()->user();

        if ($session === null || $user === null) {
            return false;
        }

        $current = $session->with(['id' => Str::random(40), 'origin' => $session->origin(), ...$changes]);

        // One that has ended, or moved on without this request, isn't brought back.
        if (! $this->holding($user, fn () => $this->registry->replace($session->id, $current, revoke: true))) {
            return false;
        }

        // The browser's "remember me" moves to the new record with it.
        $this->bind($request, $current, $request->session()->get(self::REMEMBERED) === true);

        return true;
    }

    /**
     * The record this browser's "remember me" belongs to, if there still is
     * one. Another guard's record doesn't count: its users can have the same
     * IDs as this one's.
     */
    public function remembered(Request $request): ?RegisteredSession
    {
        $id = $request->cookie($this->rememberCookie()) ?? Cookies::earlier($request, $this->rememberCookie());
        $session = is_string($id) && strlen($id) === 40 ? $this->registry->find($id) : null;

        return $session?->guard === config('keyring.guard') ? $session : null;
    }

    /**
     * Whether this response gives the browser Laravel's "remember me" cookie,
     * as an app's own Auth::login($user, remember: true) does. Signing out
     * queues one too, with nothing in it.
     */
    public function recallerQueued(): bool
    {
        $guard = $this->keyring->guard();

        return $guard instanceof SessionGuard && filled(Cookie::queued($guard->getRecallerName())?->getValue());
    }

    /**
     * Note that a "remember me" cookie signed the session in, as it happens.
     * The guard only knows for the rest of that request, and on a route
     * without Keyring's middleware the next one would find a signed-in
     * session with nothing to say how it started.
     *
     * The guard announces the cookie as a login that ticked "remember me",
     * and it can say it came by the cookie when the cookie was refused and
     * someone then signed in. A real login that ticked it has a new cookie
     * queued by now.
     */
    public function markRecalled(Login $event): void
    {
        $guard = $this->keyring->guard();

        if ($event->guard === config('keyring.guard') && $event->remember && $guard instanceof SessionGuard && $guard->viaRemember() && ! $this->recallerQueued()) {
            $guard->getSession()->put(self::REMEMBERED, true);
        }
    }

    /**
     * End the session with a sign-out the app does itself: Auth::logout(),
     * logoutCurrentDevice(), or a package that calls them. The guard only
     * forgets who is signed in. Left at that, the session's record would
     * stay good until it timed out, so a copy of a cookie session, or of
     * the "remember me" cookies, would carry on signed in, and a session
     * the app didn't also invalidate would hand what it proved to whoever
     * signed in on it next.
     *
     * Keyring's own sign-out (SignIn::out) has ended the record by the time
     * the guard announces it, and this finds nothing left to do.
     *
     * The record is announced as logged_out, unless the app gave a reason
     * of its own around the sign-out with because(). That includes Laravel's
     * auth.session middleware, which signs a browser out with
     * logoutCurrentDevice() when the user's password hash no longer matches
     * the one the session started with.
     */
    public function signedOut(Logout|CurrentDeviceLogout $event): void
    {
        $request = request();

        if ($event->guard !== config('keyring.guard') || ! $request->hasSession()) {
            return;
        }

        // The guard is signed out whatever becomes of the record: a
        // registry that can't be reached is reported, not thrown from the
        // middle of the app's sign-out. The record that would refuse the
        // "remember me" cookies is still open then, and logoutCurrentDevice()
        // leaves the token as it was, so it's cycled here instead. Not for
        // a user being impersonated: the cookies are the impersonator's,
        // whose token Impersonation::signedOut() cycles if their parked
        // session can't be ended. Signing out while impersonating leaves
        // nobody to come back to.
        $impersonation = app(Impersonation::class);

        rescue(fn () => $impersonation->signedOut($request));

        rescue(fn () => $this->unlessGiven(SessionEndReason::LoggedOut, fn () => $this->end($request)), function () use ($event, $request, $impersonation) {
            if ($event instanceof CurrentDeviceLogout && $event->user !== null && ! $impersonation->impersonates($request, $event->user)) {
                rescue(fn () => $this->cycleRememberToken($event->user));
            }
        });

        $request->session()->forget(['keyring', 'auth.password_confirmed_at']);
    }

    /**
     * "sessions.remember_cookie", or remembered_session with the prefix the
     * app's setup allows: __Host-remembered_session over HTTPS. Like the
     * device cookie's, the name says nothing of what set it.
     */
    public function rememberCookie(): string
    {
        return Cookies::name(config('keyring.sessions.remember_cookie'), 'remembered_session');
    }

    /**
     * Laravel's "remember me" cookie is the same in every browser a user
     * ticked it in, and nothing on the server makes it run out. This one
     * names the record it was issued with, so "remember me" can only bring
     * that session back, and only for as long as the record lasts.
     */
    protected function queueRememberCookie(Request $request, RegisteredSession $session): void
    {
        Cookies::queue($request, $this->rememberCookie(), $session->id, minutes: max(1, (int) ceil(($session->expiresAt - now()->getTimestamp()) / 60)));
    }

    protected function forgetRememberCookie(Request $request): void
    {
        Cookies::forget($request, $this->rememberCookie());
    }

    /**
     * Seconds of inactivity allowed before a session nobody asked to be
     * remembered ends, or with a level, before that level lapses. Null for
     * no limit (Laravel's own session lifetime still applies).
     */
    public function idle(?Assurance $level = null): ?int
    {
        $idle = $this->timeout($level, 'idle');

        return $idle === null ? null : Duration::seconds($idle);
    }

    /**
     * Whether the session has gone unused for too long to carry on. A
     * remembered one has a limit of its own ("sessions.remember_idle"):
     * held to the same one as the rest, "remember me" would bring nobody
     * back who had been away for longer than Laravel's session lasts anyway.
     */
    public function idledOut(RegisteredSession $session, ?int $now = null): bool
    {
        $idle = $this->idleLimit($session->remembered);

        return $idle !== null && ($now ?? now()->getTimestamp()) - $session->lastActivityAt > $idle;
    }

    /**
     * Seconds a session may go unused before it ends, for one that's
     * remembered or not. Null for no limit. The sweep ends sessions by this
     * too, so it ends what the session middleware would.
     */
    public function idleLimit(bool $remembered): ?int
    {
        $idle = $remembered ? config('keyring.sessions.remember_idle') : config('keyring.sessions.idle');

        return $idle === null ? null : Duration::seconds($idle);
    }

    /**
     * Whether a record that has ended did so by timing out: revoked once it
     * had expired, or had gone unused for too long, as the sweep and the
     * session middleware end them.
     */
    public function timedOut(RegisteredSession $session): bool
    {
        return $session->revokedAt !== null && ($session->expiresAt <= $session->revokedAt || $this->idledOut($session, $session->revokedAt));
    }

    /**
     * Seconds after sign in that the session ends, or with a level, that a
     * verification keeps counting toward it.
     */
    public function absolute(?Assurance $level = null): int
    {
        return Duration::seconds($this->timeout($level, 'absolute') ?? '30d');
    }

    /**
     * The level's own limit (sessions.levels.aal2.idle), else the session's.
     */
    protected function timeout(?Assurance $level, string $kind): int|string|null
    {
        $default = config('keyring.sessions.'.$kind);

        return $level === null ? $default : config('keyring.sessions.levels.'.strtolower($level->name).'.'.$kind, $default);
    }

    /**
     * Sign the user out everywhere but the given session, and close the other
     * ways back in without a full sign in: Laravel keeps one remember token
     * per user, so cycling it stops every "remember me" cookie, no other
     * device stays trusted, and an email change waiting for confirmation is
     * cancelled, though its "this wasn't me" link keeps working.
     *
     * When the registry fails part way, the rest is still done before the
     * failure is thrown: the sessions it ended stay ended, and the ways back
     * in close as they would have.
     */
    public function signOutEverywhere(Authenticatable $user, #[\SensitiveParameter] ?string $except = null): int
    {
        $keptDevice = $except === null ? null : $this->registry->find($except)?->deviceId;

        return $this->holdingThenThrow($user, fn () => $this->registry->revokeAll($user, $except), function () use ($user, $keptDevice) {
            $this->cycleRememberToken($user);
            $this->distrustDevices($user, except: $keptDevice);

            if ($user instanceof Model) {
                $this->emailChanges->cancel($user);
            }
        })->count();
    }

    /**
     * Sign the user out everywhere but here, and give this session a new ID,
     * so someone who copied its cookie doesn't get to stay either. Returns
     * how many sessions ended.
     */
    public function signOutOthers(Request $request, Authenticatable $user): int
    {
        // A copy of this session's cookie is shut out even when the
        // registry fails part way, as the sessions it ended stay ended. The
        // registry's failure is the one thrown, so a deadlock still reaches
        // a transaction of the app's that would retry it.
        try {
            $count = $this->because(SessionEndReason::SignedOutEverywhere, fn () => $this->signOutEverywhere($user, except: $this->current($request)?->id));
        } catch (Throwable $e) {
            rescue(fn () => $this->rotate($request));

            throw $e;
        }

        $this->rotate($request);

        SessionsRevoked::dispatch($user, $count);

        return $count;
    }

    /**
     * End the user's sessions on one device.
     */
    public function revokeDevice(Authenticatable $user, string $deviceId): int
    {
        return $this->holdingThenThrow($user, fn () => $this->registry->revokeDevice($user, $deviceId))->count();
    }

    public function cycleRememberToken(Authenticatable $user): void
    {
        if ($user->getRememberToken() !== null) {
            $user->setRememberToken(Str::random(60));

            if ($user instanceof Model) {
                $user->save();
            }
        }
    }

    /**
     * Stop trusting the user's devices, or all but one, and stop any of them
     * counting as a known browser for rate limits until it signs in again.
     *
     * With devices off the trust is still ended, in case it was given while
     * they were on and they're turned on again: a browser trusted before a
     * password reset would otherwise skip the second factor after it. That
     * one update is the only thing that reaches for the table then, and a
     * security change doesn't fail on an app that never made it.
     */
    public function distrustDevices(Authenticatable $user, ?string $except = null): void
    {
        if (! $user instanceof Model) {
            return;
        }

        $distrust = function () use ($user, $except) {
            app(Throttle::class)->forgetBrowsers($user);

            $this->keyring->deviceModel()::query()
                ->ownedBy($user)
                ->whereNotNull('trusted_until')
                ->when($except, fn (Builder $query) => $query->whereKeyNot($except))
                ->update(['trusted_until' => null]);
        };

        if (Features::enabled(Features::devices())) {
            $distrust();

            return;
        }

        // In a transaction of its own, so a table that isn't there leaves
        // the caller's usable where a failed statement would end it.
        rescue(fn () => $this->keyring->deviceModel()::query()->getConnection()->transaction($distrust), report: false);
    }

    /**
     * Run the callback with every session it ends announced for this
     * reason (RegisteredSessionEnded), whatever the registry is wrapped in.
     *
     * @template TResult
     *
     * @param  Closure(): TResult  $callback
     * @return TResult
     */
    public function because(SessionEndReason $reason, Closure $callback): mixed
    {
        return AnnouncingSessionRegistry::because($reason, $callback);
    }

    /**
     * Run the callback with every session it ends announced for this
     * reason, unless the code around it gave one already (because()), which
     * wins.
     *
     * @template TResult
     *
     * @param  Closure(): TResult  $callback
     * @return TResult
     */
    public function unlessGiven(SessionEndReason $reason, Closure $callback): mixed
    {
        return AnnouncingSessionRegistry::unlessGiven($reason, $callback);
    }

    /**
     * Take back a record nobody used: revoked on the driver underneath, so
     * no RegisteredSessionEnded goes out, and noted as announced, so
     * keyring:sweep doesn't announce it later either. A failure is
     * reported, not thrown: it's for a failure that's being thrown already.
     */
    public function withdraw(#[\SensitiveParameter] string $id): void
    {
        rescue(function () use ($id) {
            $announcing = $this->registry instanceof AnnouncingSessionRegistry ? $this->registry : null;

            ($announcing?->inner() ?? $this->registry)->revoke($id);
            $announcing?->sweeper()?->announced([$id], [], now()->getTimestamp());
        });
    }

    public function registry(): SessionRegistry
    {
        return $this->registry;
    }
}
