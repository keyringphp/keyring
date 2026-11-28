<?php

declare(strict_types=1);

namespace Keyring\Impersonation;

use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Session\Session;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Keyring\Activity\SecurityLog;
use Keyring\Enums\Assurance;
use Keyring\Enums\ImpersonationEndReason;
use Keyring\Enums\ImpersonationRefusal;
use Keyring\Enums\SessionEndReason;
use Keyring\Events\ImpersonationEnded;
use Keyring\Events\ImpersonationStarted;
use Keyring\Exceptions\ImpersonationRefused;
use Keyring\Http\Responses\ChoosesFormat;
use Keyring\KeyringManager;
use Keyring\Login\SignIn;
use Keyring\Login\Verification;
use Keyring\Sessions\RegisteredSession;
use Keyring\Sessions\SessionAssurance;
use Keyring\Sessions\Sessions;
use Keyring\Support\Duration;
use Keyring\Support\KeyedHash;
use LogicException;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * Signing in as another user, and coming back. Everything goes through
 * Keyring's own sessions rather than around them:
 *
 * - The impersonated session is a registered session of its own, on a new
 *   session ID, that proved nothing, is never remembered and is on no
 *   device. It names the impersonator and the record of their own session.
 * - The impersonator's session is parked, not ended: its record stays good
 *   (kept from idling out while they're active), and their "remember me"
 *   cookies are left as they are. What it proved is kept aside in the
 *   session, where nothing reads it until they come back. Its levels lapse
 *   on their own clocks as they would in that session: a request after a
 *   level's idle limit lapses it.
 * - Coming back takes that record still being good, the impersonator still
 *   being someone who may sign in, on the password they had when it
 *   started, and the browser's session still being the impersonation it
 *   started. Otherwise the browser is signed out, and
 *   the parked record ends with it. An impersonator who may no longer
 *   impersonate the user ends it too, and goes back. They come back at
 *   AAL1 at most, with nothing counting as fresh: a page of the user's
 *   could have sent them back, so anything behind keyring:aal2 asks for
 *   their second factor again. Under sessions.end_on_lapse, an
 *   impersonator whose session signed in above AAL1 is signed out instead,
 *   as a session there doesn't outlive the level it signed in at.
 *
 * The user's own sign-in events don't fire, so nothing that listens for a
 * sign in (new device emails, risk, "last signed in") takes it for one.
 *
 * @phpstan-type Parked array{impersonator: string, type: string, name: ?string, session: string, handle?: string, user: string, user_type: string, remembered: bool, started_at: int, expires_at: int, password: ?string, parked: array<string, mixed>, announced?: bool}
 */
class Impersonation
{
    use ChoosesFormat;

    /** Where the browser's session keeps what it needs to go back. */
    public const string KEY = 'keyring.impersonation';

    /** Where a request notes the impersonation it ended, once the session has forgotten it. */
    protected const string ENDED = 'keyring.impersonation_ended';

    /** Where a request notes it warned that impersonation isn't set up. */
    protected const string WARNED = 'keyring.impersonation_warned';

    /** What the impersonator's session proved, kept aside until they come back. */
    protected const array PROVED = [SessionAssurance::KEY, SessionAssurance::ACTIVE, SessionAssurance::LAPSED, SessionAssurance::SIGNED_IN];

    public function __construct(
        protected KeyringManager $keyring,
        protected Sessions $sessions,
        protected SecurityLog $log,
    ) {}

    /**
     * Sign the browser in as $user, on behalf of whoever is signed in now.
     *
     * The user's record is saved, and the start logged on both accounts,
     * before the browser changes hands, so a registry or a security log
     * that fails leaves the impersonator where they were: it never starts
     * unlogged. Handing the browser over that fails, an app's listener for
     * Laravel's Authenticated that throws say, leaves them where they were
     * too, with the end logged after the start, as failed. A refusal is
     * logged on the impersonator's account, as impersonation_refused.
     *
     * @throws ImpersonationRefused
     */
    public function start(Request $request, Authenticatable&Model $user): void
    {
        $impersonator = $this->keyring->user();
        $now = now()->getTimestamp();

        $refusal = $this->active($request) ? ImpersonationRefusal::Impersonating : $this->keyring->impersonationRefusal($impersonator, $user);

        // Logged on whoever is impersonating, when someone is, rather than
        // the user they're signed in as.
        if ($refusal !== null) {
            $this->warnIfNotSetUp($request, $refusal);
            $this->refused($this->impersonator($request) ?? $impersonator, (string) $user->getAuthIdentifier(), $refusal);
        }

        // Coming back takes a record to come back to.
        $own = $this->sessions->current($request);

        if ($own === null || ! $own->isActive($now) || ! $own->belongsTo($impersonator)) {
            $this->refused($impersonator, (string) $user->getAuthIdentifier(), ImpersonationRefusal::Unregistered);
        }

        $until = $now + Duration::seconds(config('keyring.impersonation.lifetime') ?? '1h');
        $session = $request->session();

        $parked = [
            'impersonator' => (string) $impersonator->getAuthIdentifier(),
            'type' => RegisteredSession::typeOf($impersonator),
            'name' => $this->nameOf($impersonator),
            'session' => $own->id,
            'user' => (string) $user->getAuthIdentifier(),
            'user_type' => RegisteredSession::typeOf($user),
            'remembered' => $session->get(Sessions::REMEMBERED) === true,
            'started_at' => $now,
            'expires_at' => $until,
            'password' => $this->passwordHash($impersonator),
            'parked' => $this->pick($session),
        ];

        $record = $this->sessions->startImpersonation($user, $impersonator, $own, $until);
        $parked['handle'] = $this->sessions->handle($record);

        // When it really ends: no later than a session could last either.
        $parked['expires_at'] = $record->expiresAt;

        // Logged here rather than by a listener, ahead of the app's: one of
        // those that throws, sending an email say, can't leave it unlogged.
        // A start that can't be logged, or can't hand the browser over,
        // takes its record back unannounced, now and by the sweep, as nobody
        // used the session. The browser is put back as it was, and a start
        // already logged is logged as ended, so the log doesn't show it
        // running on.
        $before = $session->all();
        $logged = false;

        try {
            $this->logStart($impersonator, $user);
            $logged = true;

            $this->switchTo($request, $user);
            $session->put(self::KEY, $parked);
            $request->attributes->set(self::KEY, $parked);
            $this->sessions->rebind($request, $record, remembered: false);
        } catch (Throwable $e) {
            $this->sessions->withdraw($record->id);

            if ($logged) {
                $this->putBack($request, $before, $own);
                $this->logFailed($impersonator, $user);
            }

            throw $e;
        }

        ImpersonationStarted::dispatch($impersonator, $user, $parked['handle']);
    }

    /**
     * Refuse starting as an ID nobody has: answered as one that may not be
     * impersonated, so the answer doesn't say which IDs have an account,
     * and logged as not_found, on whoever is impersonating when someone
     * is, as start() logs its refusals.
     *
     * @throws ImpersonationRefused
     */
    public function refuseUnknown(Request $request, string $id): never
    {
        $this->refused($this->impersonator($request) ?? $this->keyring->user(), $id, ImpersonationRefusal::NotFound, as: ImpersonationRefusal::NotAllowed);
    }

    /**
     * Stop impersonating: back to the impersonator's own session, or signed
     * out when that has ended. Returns the impersonator when they're back.
     *
     * @throws LogicException when nobody is being impersonated
     */
    public function stop(Request $request): (Authenticatable&Model)|null
    {
        throw_unless($this->active($request), LogicException::class, 'Nobody is being impersonated in this session.');

        return $this->end($request, ImpersonationEndReason::Stopped)->returns() ? $this->keyring->user() : null;
    }

    /**
     * End the impersonation for a reason, and say what it ended for. The
     * impersonated session ends whatever happens. For a reason that goes
     * back, the browser goes back to the impersonator's session, on a new
     * session ID, as long as that session and the impersonator are still
     * good. It goes back at AAL1 at most, with the second factor to prove
     * again and nothing counting as fresh (restore()). Otherwise, or for a
     * reason that doesn't, the browser is signed out and the impersonator's
     * session ends too. So does one that signed in above AAL1 under
     * sessions.end_on_lapse, where a session doesn't outlive the level it
     * signed in at (endsComingBack()).
     *
     * Only the impersonation this browser started goes back: the guard
     * still signed in as the user it parked the impersonator's session for,
     * and the session still on the impersonated record that parked it, or
     * on no record at all. Anything else (the user gone, someone else
     * signed in on the session) signs out, as Lost: what's parked isn't
     * this session's to go back to. With nothing parked, the impersonated
     * record still names the impersonator and their session, which ends.
     *
     * The reason it ended for is the one given, unless it couldn't go back:
     * then ImpersonatorSessionEnded or Lost. It went back when the reason
     * returns(). ImpersonationEnded says whether the browser did, which it
     * hasn't when handing it back throws. Then the impersonator's session
     * ends, and the browser is signed out, before it's thrown on.
     *
     * Only one request ends an impersonation, however many of the
     * browser's find it over at once, such as XHRs sent as its time ran
     * out, or a copy of the session from before another request ended it:
     * the one that claims its end (claim()). That's whoever revoked its
     * record, the user from their sessions list say, as only ending it
     * claims it. The rest leave it to that request (alreadyEnded()): Lost,
     * with nothing announced, logged, revoked or moved. A copy never goes
     * back, whoever claims it: the impersonator's record it parked has
     * moved on, or ended, by then (returnable()).
     */
    public function end(Request $request, ImpersonationEndReason $reason): ImpersonationEndReason
    {
        $parked = $this->parked($request);
        $current = $this->sessions->current($request);
        $user = $this->keyring->guard()->user();
        $target = $this->userFrom($parked, $current);
        $impersonated = $current?->isImpersonated() === true ? $current : null;
        $impersonator = match (true) {
            $parked !== null => $this->impersonatorFrom($parked),
            default => $impersonated === null ? null : $this->load((string) $impersonated->impersonatorId, $impersonated->impersonatorType),
        };
        $own = $parked['session'] ?? $impersonated?->impersonatorSession;
        $handle = $parked['handle'] ?? ($impersonated === null ? null : $this->sessions->handle($impersonated));

        $ours = $parked !== null && $user !== null
            && (string) $user->getAuthIdentifier() === $parked['user'] && RegisteredSession::typeOf($user) === $parked['user_type']
            && ($current === null || ($current->impersonatorSession === $parked['session'] && $current->belongsTo($user)));
        $back = $ours && $reason->returns() ? $this->returnable($parked, $impersonator) : null;

        if ($back === null && $reason->returns()) {
            $reason = $ours ? ImpersonationEndReason::ImpersonatorSessionEnded : ImpersonationEndReason::Lost;
        }

        if ($back !== null && $this->endsComingBack($parked)) {
            [$back, $reason] = [null, ImpersonationEndReason::ImpersonatorSessionEnded];
        }

        $this->sessions->because(SessionEndReason::ImpersonationEnded, fn () => $current === null ? null : $this->sessions->registry()->revoke($current->id));

        // Another request ended it first.
        if (! $this->claim($handle, $parked['expires_at'] ?? $current->expiresAt ?? now()->getTimestamp())) {
            $this->forget($request);

            return $this->alreadyEnded($request);
        }

        // Nobody is going back to it, so it ends with the browser. A
        // registry that fails leaves the end for the next request to claim.
        if ($back === null && $own !== null) {
            try {
                $this->sessions->because(SessionEndReason::ImpersonationEnded, fn () => $this->sessions->registry()->revoke($own));
            } catch (Throwable $e) {
                $this->unclaim($handle);

                throw $e;
            }
        }

        $this->forget($request);

        // It has ended by now, whatever the registry does next, so it's
        // announced, and logged, even when signing out or moving the record
        // throws. Once only: a sign-out the registry failed announced it.
        $returned = false;
        $announce = ($impersonator !== null || $target !== null) && ($parked['announced'] ?? false) !== true;

        try {
            if ($back === null) {
                app(SignIn::class)->out($request, onlyThisBrowser: true);
            } else {
                // Only what this browser parked goes back ($ours).
                try {
                    $this->switchTo($request, $back[0]);
                    $level = $this->restore($request, $this->catchUp($parked['parked'])[0]);
                    $this->sessions->rebind($request, $back[1], $parked['remembered']);

                    // A copy of the session from while impersonating would
                    // lead back here again with what was parked: a cookie
                    // session's, in the browser where regenerating can't
                    // destroy it, or a request that overlapped this one and
                    // saves the old session after it. The record moves, as
                    // on a step-up, so the copy's parked record has ended.
                    // The browser's "remember me" moves with it. One that
                    // couldn't move for having ended, by a sign-out
                    // everywhere say, or for having moved without this
                    // request, still went back, and the next request finds
                    // it ended. The new record has the level the session
                    // came back at, for the sessions list.
                    $this->sessions->reregister($request, ['assurance' => $level]);
                } catch (Throwable $e) {
                    // Nothing is parked to go back with now, and the record
                    // a copy of the session would go back to hasn't moved,
                    // so it ends as if it couldn't go back: the
                    // impersonator's session too, and the browser is signed
                    // out, rather than left as the user on a record that has
                    // ended, for the next request to end again, or as the
                    // impersonator on one a copy could come back to.
                    rescue(fn () => $this->sessions->because(SessionEndReason::ImpersonationEnded, fn () => $this->sessions->registry()->revoke($back[1]->id)));
                    rescue(fn () => app(SignIn::class)->out($request, onlyThisBrowser: true));

                    throw $e;
                }

                $returned = true;
            }
        } finally {
            if ($announce) {
                ImpersonationEnded::dispatch($impersonator, $target, $reason, $returned, $handle);
            }
        }

        return $reason;
    }

    /**
     * Claim the end of the impersonation with this handle for this request,
     * returning whether it's this one's: only the first request to ask is
     * given it. Kept in the rate limiter's cache store, as Keyring's other
     * one-time claims are, for as long as the impersonation had left and a
     * session lasts after that (session.lifetime), as no copy of the
     * session can still be sent later. A store that fails, or an
     * impersonation with no handle to claim it by, counts as this one's: a
     * second entry in the log does less harm than none.
     */
    protected function claim(?string $handle, int $expiresAt): bool
    {
        $for = max(0, $expiresAt - now()->getTimestamp()) + ((int) config('session.lifetime', 120) * 60) + 60;

        return $handle === null || rescue(fn () => cache()->store(config('cache.limiter'))->add($this->claimKey($handle), true, $for), true);
    }

    /**
     * Give up a claim this request couldn't see through, so the next
     * request that finds the impersonation over ends it.
     */
    protected function unclaim(?string $handle): void
    {
        if ($handle !== null) {
            rescue(fn () => cache()->store(config('cache.limiter'))->forget($this->claimKey($handle)));
        }
    }

    protected function claimKey(string $handle): string
    {
        return 'keyring:impersonation-ended:'.KeyedHash::make(KeyedHash::IMPERSONATION_ENDS, $handle);
    }

    /**
     * Leave an impersonation another request of the browser ended first,
     * to that one: nothing is announced, logged, revoked or moved here. This
     * request's copy of the session is a stale one, holding an impersonation
     * that's over, or the impersonator on a record that moved without it,
     * so it's emptied, as a guest's, to be signed out rather than end it
     * again. Nothing else is touched, "remember me" cookies included:
     * whichever answer the browser keeps last, the other request's leaves
     * it signed in, and a remembered impersonator is brought back by their
     * cookie when it's this one's.
     */
    protected function alreadyEnded(Request $request): ImpersonationEndReason
    {
        $guard = $this->keyring->guard();

        assert($guard instanceof SessionGuard);

        $request->session()->invalidate();
        $request->session()->regenerateToken();
        $request->attributes->remove(Sessions::KEY);
        $guard->forgetUser();

        return ImpersonationEndReason::Lost;
    }

    /**
     * The browser is being signed out while it impersonates: Keyring's own
     * sign-out, or the app's Auth::logout(). Or someone is signing in on a
     * session that still holds an impersonation (SignIn, and a sign in the
     * app started), which mustn't be left for the next request to go back
     * with. The impersonator's parked session ends with it, as nobody can
     * come back to it now.
     *
     * A session the app emptied before signing out, with invalidate() or
     * flush() ahead of Auth::logout(), is ended by what the request noted
     * (parked()), as Sessions::end() does for its own record.
     *
     * The parked session is ended before the impersonation is forgotten, so
     * a registry that fails leaves it for another go: the guard's sign-out
     * after SignIn::out(), or the next request. The browser's "remember me"
     * cookies are the impersonator's, and that session is what refuses
     * them, so their token is cycled when it can't be ended, as
     * Sessions::signedOut() cycles a user's for their own session. Then it
     * throws.
     *
     * The browser is signed out either way, so ImpersonationEnded fires
     * either way, and once: what's parked notes it was announced, so the
     * go that ends it later, in this request or the next, doesn't again.
     */
    public function signedOut(Request $request): void
    {
        if (($parked = $this->parked($request, orNoted: true)) === null) {
            return;
        }

        $impersonator = $this->impersonatorFrom($parked);
        $user = $this->userFrom($parked, null);
        $announce = ($parked['announced'] ?? false) !== true && ($impersonator !== null || $user !== null);

        try {
            $this->sessions->because(SessionEndReason::ImpersonationEnded, fn () => $this->sessions->registry()->revoke($parked['session']));
        } catch (Throwable $e) {
            if ($impersonator !== null) {
                rescue(fn () => $this->sessions->cycleRememberToken($impersonator));
            }

            if ($announce) {
                $this->noteAnnounced($request, $parked);

                ImpersonationEnded::dispatch($impersonator, $user, ImpersonationEndReason::SignedOut, false, $parked['handle'] ?? null);
            }

            throw $e;
        }

        $this->forget($request);

        if ($announce) {
            ImpersonationEnded::dispatch($impersonator, $user, ImpersonationEndReason::SignedOut, false, $parked['handle'] ?? null);
        }
    }

    /**
     * Whether $user is the one this request's browser is impersonating, or
     * was until this request ended it. Their "remember me" cookies aren't
     * the browser's then, the impersonator's are, so a sign-out the registry
     * fails mustn't cycle the user's token (Sessions::signedOut()). Nor are
     * the request's IP address and browser the user's, so the security log
     * leaves them off the user's entries (SecurityLog).
     */
    public function impersonates(Request $request, Authenticatable $user): bool
    {
        $parked = $this->parked($request, orNoted: true) ?? $request->attributes->get(self::ENDED);

        return is_array($parked) && (string) $user->getAuthIdentifier() === $parked['user'] && RegisteredSession::typeOf($user) === $parked['user_type'];
    }

    /**
     * Why the impersonation this request is part of has to end now, if it
     * does. Asked by the session middleware on every request, in place of
     * its own checks. Who may impersonate whom is asked again each time, so
     * an impersonator who loses the right, or a user the app protects
     * since, ends it on the next request. A callback that throws counts as
     * a no, and is reported: thrown, it would fail every request the
     * browser makes, stopping and signing out too, with no way back.
     */
    public function ending(Request $request, ?RegisteredSession $session, Authenticatable&Model $user): ?ImpersonationEndReason
    {
        $parked = $this->parked($request);
        $now = now()->getTimestamp();

        if ($parked === null || $session === null || $session->impersonatorSession !== $parked['session'] || ! $session->belongsTo($user)
            || $session->replacedBy !== null || ($session->revokedAt !== null && ! $this->sessions->timedOut($session))
            || ! $this->keyring->allowsSignIn($user)) {
            return ImpersonationEndReason::Ended;
        }

        $impersonator = $this->impersonatorFrom($parked);

        return match (true) {
            $impersonator !== null && ! rescue(fn () => $this->keyring->allowsImpersonation($impersonator, $user), false) => ImpersonationEndReason::Ended,
            $now >= $parked['expires_at'] || ! $session->isActive($now) || $this->sessions->idledOut($session, $now) => ImpersonationEndReason::Expired,
            $this->returnable($parked, $impersonator) === null => ImpersonationEndReason::ImpersonatorSessionEnded,
            default => null,
        };
    }

    /**
     * Note activity on the impersonated session and on the impersonator's,
     * so the one they'll come back to doesn't idle out while they're busy,
     * nor what it proved: the impersonator is using the browser all along.
     * The records at most once a minute, as for any session. What it proved
     * on every request, as their own session would note it, lapsing a level
     * whose idle limit passed since the last one.
     */
    public function touch(Request $request, RegisteredSession $session, int $now): void
    {
        if ($now - $session->lastActivityAt >= 60) {
            $this->sessions->registry()->update($session->id, ['lastActivityAt' => $now]);
            $this->sessions->registry()->update((string) $session->impersonatorSession, ['lastActivityAt' => $now]);
        }

        if (($parked = $this->parked($request)) !== null) {
            $parked['parked'] = $this->catchUp($parked['parked'])[0];

            $request->session()->put(self::KEY, $parked);
            $request->attributes->set(self::KEY, $parked);
        }
    }

    /**
     * Whether this request's session is impersonating someone, or was until
     * now and the session middleware hasn't caught up yet.
     */
    public function active(Request $request): bool
    {
        return $this->parked($request) !== null;
    }

    /**
     * Who is impersonating, while someone is. Null when nobody is, or when
     * they've since been deleted.
     */
    public function impersonator(Request $request): (Authenticatable&Model)|null
    {
        $parked = $this->parked($request);

        return $parked === null ? null : $this->impersonatorFrom($parked);
    }

    /**
     * The impersonation for a page to show, as in a banner with a way to
     * stop. Null when nobody is being impersonated. Read from the session,
     * so asking costs no query.
     *
     * @return array{impersonator: array{id: string, name: ?string}, startedAt: string, expiresAt: string, stopUrl: ?string}|null
     */
    public function toArray(Request $request): ?array
    {
        $parked = $this->parked($request);
        $time = fn (int $timestamp) => now()->setTimestamp($timestamp)->toIso8601String();

        return $parked === null ? null : [
            'impersonator' => ['id' => $parked['impersonator'], 'name' => $parked['name']],
            'startedAt' => $time($parked['started_at']),
            'expiresAt' => $time($parked['expires_at']),
            'stopUrl' => Route::has('keyring.impersonation.destroy') ? route('keyring.impersonation.destroy') : null,
        ];
    }

    /**
     * Who is in an impersonated session, as the user's sessions list shows
     * them: by name only, as the user has no use for the impersonator's ID.
     * Null for one nobody else is in, or whose impersonator is gone.
     *
     * @return array{name: ?string}|null
     */
    public function describe(RegisteredSession $session): ?array
    {
        $impersonator = $session->isImpersonated() ? $this->keyring->provider()->retrieveById($session->impersonatorId) : null;

        return $impersonator instanceof Model && RegisteredSession::typeOf($impersonator) === $session->impersonatorType ? ['name' => $this->nameOf($impersonator)] : null;
    }

    /**
     * Where starting goes: impersonation.redirect_url, or "home".
     */
    public function redirectTo(): string
    {
        return url()->to(config('keyring.impersonation.redirect_url') ?? config('keyring.home'));
    }

    /**
     * Where coming back goes: impersonation.return_url, or "home".
     */
    public function returnTo(): string
    {
        return url()->to(config('keyring.impersonation.return_url') ?? config('keyring.home'));
    }

    /**
     * The answer to anything Keyring refuses while impersonating: a 403,
     * with the "impersonating" status for JSON clients.
     */
    public function refuse(Request $request): Response
    {
        $message = $this->keyring->statusMessage('impersonating');

        return $this->wantsJson($request)
            ? new JsonResponse(['status' => 'impersonating', 'message' => $message], 403)
            : abort(403, (string) $message);
    }

    /**
     * Log a refused start on the impersonator's account, and throw it as
     * $as: what was refused is answered the same however it was logged.
     *
     * @throws ImpersonationRefused
     */
    protected function refused(Authenticatable $impersonator, string $id, ImpersonationRefusal $reason, ?ImpersonationRefusal $as = null): never
    {
        $this->log->recordRefusal('impersonation_refused', $impersonator, meta: ['reason' => $reason->value, 'user' => Str::limit($id, 64, '')]);

        throw new ImpersonationRefused($as ?? $reason);
    }

    /**
     * Tell the developer, in the app's log, that a refusal was for
     * impersonation not being set up, which the answer doesn't say: a
     * forgotten allowImpersonationWhen() looks like being turned down.
     * Once a request.
     */
    protected function warnIfNotSetUp(Request $request, ImpersonationRefusal $refusal): void
    {
        $missing = match ($refusal) {
            ImpersonationRefusal::Disabled => 'Features::impersonation() is not in the features in config/keyring.php',
            ImpersonationRefusal::NoCallback => 'Keyring::allowImpersonationWhen() was never called, in a service provider\'s boot() say',
            default => null,
        };

        if ($missing === null || $request->attributes->get(self::WARNED) === true) {
            return;
        }

        $request->attributes->set(self::WARNED, true);

        rescue(fn () => logger()->warning("Keyring refused an impersonation because it isn't set up: {$missing}, so nobody may impersonate anyone. The answer is the same as for one that isn't allowed."), report: false);
    }

    /**
     * Log the start on both accounts, each entry naming both: "role" says
     * which of them the entry's account was. In the table, both are
     * written or neither. A failure is thrown.
     */
    protected function logStart(Authenticatable $impersonator, Authenticatable $user): void
    {
        $meta = ['impersonator' => (string) $impersonator->getAuthIdentifier(), 'user' => (string) $user->getAuthIdentifier()];

        $this->keyring->securityEventModel()::query()->getConnection()->transaction(function () use ($impersonator, $user, $meta) {
            $this->log->recordOrFail('impersonation_started', $impersonator, meta: [...$meta, 'role' => 'impersonator']);
            $this->log->recordOrFail('impersonation_started', $user, meta: [...$meta, 'role' => 'impersonated']);
        });
    }

    /**
     * Put the browser back as it was before a start that failed handing it
     * over: the impersonator's session as it was, on the new session ID if
     * it got one, and the impersonator signed in, loaded again from it when
     * next asked for. Nothing of the impersonation is left parked.
     *
     * @param  array<string, mixed>  $before
     */
    protected function putBack(Request $request, array $before, RegisteredSession $own): void
    {
        $request->session()->flush();
        $request->session()->put($before);
        $request->attributes->remove(self::KEY);
        $request->attributes->set(Sessions::KEY, $own->id);

        $guard = $this->keyring->guard();

        assert($guard instanceof SessionGuard);

        $guard->forgetUser();
    }

    /**
     * Log the end of a start that was logged but couldn't hand the browser
     * over, on both accounts as an end is, as failed: the browser stayed
     * the impersonator's. ImpersonationEnded doesn't fire, as
     * ImpersonationStarted never did. A failure is reported, not thrown:
     * the start's own failure is being thrown already.
     */
    protected function logFailed(Authenticatable $impersonator, Authenticatable $user): void
    {
        $meta = ['impersonator' => (string) $impersonator->getAuthIdentifier(), 'user' => (string) $user->getAuthIdentifier(), 'reason' => ImpersonationEndReason::Failed->value, 'returned' => true];

        $this->log->record('impersonation_ended', $impersonator, meta: [...$meta, 'role' => 'impersonator']);
        $this->log->record('impersonation_ended', $user, meta: [...$meta, 'role' => 'impersonated']);
    }

    /**
     * Hand the browser to another user, on a new session ID, with nothing
     * of what the session held for the last one: what it proved, the
     * pending sign ins and confirms, Laravel's password confirmation, the
     * password hash Laravel's auth.session middleware compares, and where
     * Laravel's intended redirect would send them: a page of the user's
     * could otherwise choose where the impersonator's next confirm or sign
     * in goes. Their own Login event doesn't fire: nobody signed in.
     */
    protected function switchTo(Request $request, Authenticatable&Model $user): void
    {
        $guard = $this->keyring->guard();

        assert($guard instanceof SessionGuard);

        $session = $request->session();

        $session->regenerate(true);
        $session->forget(['keyring', 'auth.password_confirmed_at', 'url.intended', $this->passwordHashKey()]);
        $session->put($guard->getName(), $user->getAuthIdentifier());

        $guard->setUser($user);
    }

    /**
     * The impersonator and their session, when the browser can go back to
     * it: the record is still good and theirs, they may still sign in, with
     * no password change they're held for, their password is the one they
     * had when it started, and, under sessions.end_on_lapse, the level it
     * signed in at hasn't lapsed.
     *
     * @param  Parked  $parked
     * @return array{0: Authenticatable&Model, 1: RegisteredSession}|null
     */
    protected function returnable(array $parked, (Authenticatable&Model)|null $impersonator): ?array
    {
        $own = $impersonator === null ? null : $this->sessions->registry()->find($parked['session']);
        $now = now()->getTimestamp();

        if ($impersonator === null || $own === null || ! $own->isActive($now) || $this->sessions->idledOut($own, $now)
            || ! $own->belongsTo($impersonator) || ! $this->keyring->allowsSignIn($impersonator) || $this->keyring->requiresPasswordChange($impersonator)
            || $this->passwordChanged($parked, $impersonator) || $this->catchUp($parked['parked'])[1] !== null) {
            return null;
        }

        return [$impersonator, $own];
    }

    /**
     * Whether the impersonator's password changed since the impersonation
     * started: their password hash then, in the guard's keyed form that
     * Laravel's auth.session middleware compares, against theirs now. Any
     * change counts, a rehash too. Not the hash their session parked for
     * that middleware, which is from when they signed in, and which nothing
     * brings up to date when they change their password in that session
     * unless the middleware runs. Decided here rather than left to it,
     * whose step after the response stores the current hash over the one
     * put back, so a stop it wraps would come back signed in. A password
     * set or removed meanwhile is a change too. An impersonator who had
     * none then and has none now hasn't changed it.
     *
     * @param  Parked  $parked
     */
    protected function passwordChanged(array $parked, Authenticatable $impersonator): bool
    {
        $then = $parked['password'];
        $now = $this->passwordHash($impersonator);

        return ($then === null) !== ($now === null) || ($then !== null && $now !== null && ! hash_equals($then, $now));
    }

    /**
     * The impersonator's password hash in the guard's keyed form, as
     * Laravel's auth.session middleware compares it. Null without one.
     */
    protected function passwordHash(Authenticatable $impersonator): ?string
    {
        $password = $impersonator->getAuthPassword();
        $guard = $this->keyring->guard();

        assert($guard instanceof SessionGuard);

        return filled($password) ? $guard->hashPasswordForCookie($password) : null;
    }

    /**
     * What the impersonator's session parked, noted for a request now, by
     * the rules their own session goes by (SessionAssurance): a level whose
     * idle limit passed since the last request has lapsed. With why the
     * level it signed in at no longer holds, under sessions.end_on_lapse,
     * which ends it as it would end their own session.
     *
     * @param  array<string, mixed>  $parked
     * @return array{0: array<string, mixed>, 1: 'idle'|'expired'|null}
     */
    protected function catchUp(array $parked): array
    {
        $session = $this->parkedSession($parked);

        $assurance = new SessionAssurance($session, $this->sessions, $this->keyring);
        $assurance->touch();

        return [$this->pick($session), $assurance->lapse()];
    }

    /**
     * Whether coming back would end the impersonator's session where it
     * stands: under sessions.end_on_lapse, a session doesn't outlive the
     * level it signed in at, and it comes back at AAL1 at most (restore()).
     * So one that signed in above AAL1 ends instead, as a session "remember
     * me" brings back, or one a risk step-up asks to prove itself again,
     * does there. So does one at AAL1 that held it only by what coming back
     * takes away.
     *
     * @param  Parked  $parked
     */
    protected function endsComingBack(array $parked): bool
    {
        $assurance = new SessionAssurance($this->parkedSession($this->catchUp($parked['parked'])[0]), $this->sessions, $this->keyring);
        $assurance->lowerToAal1();

        return $assurance->lapse() !== null;
    }

    /**
     * What the impersonator's session parked, as a session of its own to
     * read it from by the rules their own session goes by.
     *
     * @param  array<string, mixed>  $parked
     */
    protected function parkedSession(array $parked): Store
    {
        $session = new Store('keyring-parked', new ArraySessionHandler(0));

        foreach ($parked as $key => $value) {
            $session->put($key, $value);
        }

        return $session;
    }

    /**
     * Put back what the impersonator's session had parked, at AAL1 at most,
     * and return the level it's back at. A page of the user's, a stored
     * script say, could have stopped the impersonation, and it would carry
     * on in the browser as the impersonator. So the second factor is
     * forgotten (SessionAssurance::lowerToAal1()), and anything behind
     * keyring:aal2 or aal3 asks for it again; what's kept, the password say,
     * still counts toward AAL1, so stepping up asks for the second factor
     * alone. None of it counts as fresh either: keyring.fresh and Laravel's
     * password.confirm ask again. The level the session signed in at stays
     * as it was: only sessions.end_on_lapse reads it, and there a session
     * that signed in above AAL1 doesn't come back (endsComingBack()).
     *
     * @param  array<string, mixed>  $parked
     */
    protected function restore(Request $request, array $parked): Assurance
    {
        foreach ($parked as $key => $value) {
            if ($key === SessionAssurance::KEY && is_array($value)) {
                $value = array_map(fn (mixed $verification) => is_array($verification) ? [...$verification, 'authenticated_at' => Verification::UNKNOWN] : $verification, $value);
            }

            $request->session()->put($key, $value);
        }

        $assurance = new SessionAssurance($request->session(), $this->sessions, $this->keyring);
        $assurance->lowerToAal1();

        return $assurance->level();
    }

    /**
     * @param  Parked  $parked
     */
    protected function impersonatorFrom(array $parked): (Authenticatable&Model)|null
    {
        return $this->load($parked['impersonator'], $parked['type']);
    }

    /**
     * The user being impersonated, as the parked state names them, or the
     * impersonated record when the session has lost that. Not the guard's
     * user: the app may have signed someone else in meanwhile.
     *
     * @param  Parked|null  $parked
     */
    protected function userFrom(?array $parked, ?RegisteredSession $session): (Authenticatable&Model)|null
    {
        return match (true) {
            $parked !== null => $this->load($parked['user'], $parked['user_type']),
            $session !== null => $this->load($session->userId, $session->userType),
            default => null,
        };
    }

    /**
     * The account with this ID, as long as it's the type named: two user
     * models can have the same IDs.
     */
    protected function load(string $id, ?string $type): (Authenticatable&Model)|null
    {
        $found = $this->keyring->provider()->retrieveById($id);

        return $found instanceof Model && RegisteredSession::typeOf($found) === $type ? $found : null;
    }

    /**
     * A user's name for people to read: their "name", else their username.
     */
    protected function nameOf(Authenticatable&Model $user): ?string
    {
        $name = $user->getAttribute('name') ?? $user->getAttribute($this->keyring->username());

        return is_scalar($name) ? (string) $name : null;
    }

    /**
     * What the session parked, if it's impersonating. Noted on the request
     * too, so signedOut() can still end it if the app empties the session
     * before signing out: $orNoted reads that when the session has none.
     *
     * @return Parked|null
     */
    protected function parked(Request $request, bool $orNoted = false): ?array
    {
        $parked = $request->hasSession() ? $request->session()->get(self::KEY) : null;

        if (is_array($parked)) {
            $request->attributes->set(self::KEY, $parked);
        } elseif ($orNoted) {
            $parked = $request->attributes->get(self::KEY);
        }

        // @phpstan-ignore return.type (only start() and touch() write it, and always whole)
        return is_array($parked) ? $parked : null;
    }

    /**
     * Note on what's parked that its end was announced, in the session, when
     * it still holds it, and on the request, as parked() reads them.
     *
     * @param  Parked  $parked
     */
    protected function noteAnnounced(Request $request, array $parked): void
    {
        $parked['announced'] = true;

        if ($request->session()->has(self::KEY)) {
            $request->session()->put(self::KEY, $parked);
        }

        foreach ([$request, request()] as $noted) {
            $noted->attributes->set(self::KEY, $parked);
        }
    }

    /**
     * Forget the impersonation, from the session and the request. From
     * request() too, when given a copy of it, like a form request: the
     * Logout listener reads the note from there, and would end it again.
     * Both note what ended instead, for impersonates().
     */
    protected function forget(Request $request): void
    {
        $parked = $this->parked($request, orNoted: true);

        $request->session()->forget(self::KEY);

        foreach ([$request, request()] as $noted) {
            $noted->attributes->remove(self::KEY);
            $noted->attributes->set(self::ENDED, $parked);
        }
    }

    /**
     * What a session holds of what the impersonator's keeps aside.
     *
     * @return array<string, mixed>
     */
    protected function pick(Session $session): array
    {
        return array_filter(array_combine($this->parkedKeys(), array_map($session->get(...), $this->parkedKeys())), fn (mixed $value) => $value !== null);
    }

    /**
     * What the impersonator's session keeps aside: what it proved, and the
     * password hash Laravel's auth.session middleware compares, put back as
     * it was for that middleware. What the impersonation compares is the
     * hash taken when it started (passwordChanged()).
     *
     * @return list<string>
     */
    protected function parkedKeys(): array
    {
        return [...self::PROVED, $this->passwordHashKey()];
    }

    protected function passwordHashKey(): string
    {
        return 'password_hash_'.config('keyring.guard');
    }
}
