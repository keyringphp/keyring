<?php

declare(strict_types=1);

namespace Keyring\Login;

use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Keyring\Activity\SecurityLog;
use Keyring\Devices\DeviceManager;
use Keyring\Enums\Purpose;
use Keyring\Events\Authenticated;
use Keyring\Events\Confirmed;
use Keyring\Events\NewDeviceSignedIn;
use Keyring\Features;
use Keyring\Impersonation\Impersonation;
use Keyring\KeyringManager;
use Keyring\Models\Authenticator;
use Keyring\Models\SecurityEvent;
use Keyring\Sessions\SessionAssurance;
use Keyring\Sessions\Sessions;
use Throwable;

/**
 * The one place a user becomes signed in (after a login or registration)
 * or confirms it's them (step-up). Everything that should happen at those
 * moments happens here.
 */
class SignIn
{
    public function __construct(
        protected KeyringManager $keyring,
        protected SessionAssurance $assurance,
        protected DeviceManager $devices,
        protected Sessions $sessions,
        protected SecurityLog $log,
        protected Detours $detours,
    ) {}

    public function complete(Request $request, Attempt $attempt): void
    {
        $user = $attempt->user();

        if (! $this->keyring->belongsToGuard($user) || ! $this->keyring->allowsSignIn($user)) {
            throw ValidationException::withMessages([$this->keyring->username() => __('auth.failed')]);
        }

        // Signing in on a session that still holds an impersonation, one
        // whose user was deleted say, leaves nothing parked for the next
        // request to go back to. When the registry fails at that, the
        // browser is signed out before it's thrown on, rather than carrying
        // on as whoever it was impersonating, on an impersonation that has
        // been announced as ended. The guard's sign-out tries the parked
        // session again.
        try {
            app(Impersonation::class)->signedOut($request);
        } catch (Throwable $e) {
            $this->signOutGuard($request);

            throw $e;
        }

        $this->keyring->guard()->login($user, $attempt->remember);

        // All of it or none: the guard is signed in from here, and a sign
        // in that failed before its session was registered and looked at
        // again would otherwise be left signed in, for the session
        // middleware to take up as one the app started itself.
        try {
            $request->session()->regenerate(true);
            $this->assurance->reset($attempt->verifications);
            $this->detours->forget($request);

            $device = $this->devices->signIn(
                $request,
                $user,
                provedSecondFactor: Requirement::aal2()->isMetBy($attempt->verifications),
                trust: $this->earnedTrust($attempt),
            );

            $new = $device?->wasRecentlyCreated === true;

            $this->sessions->start($request, $user, $device, $this->assurance->level(), remembered: $attempt->remember);

            $ended = $this->changedMeanwhile($user) || ! $attempt->keepsItsAuthenticators();
        } catch (Throwable $e) {
            // Whatever failed may fail again as the session is ended (the
            // registry, say), and the guard has to be signed out all the
            // same.
            try {
                $this->out($request, onlyThisBrowser: true);
            } catch (Throwable) {
                $this->signOutGuard($request);
            }

            throw $e;
        }

        // A password reset or change, an email change or its undo, or a
        // sign-in method taken off the account signs out the sessions
        // registered by then. This one was still being checked, and is only
        // registered now, so it was looked at again: with the new password
        // or address saved, or a method this sign in proved gone, it ends
        // here.
        if ($ended) {
            // The change stopped trusting every device before this one was
            // recorded, so whatever trust it was just given goes too.
            $this->sessions->distrustDevices($user);
            $this->out($request, onlyThisBrowser: true);

            throw ValidationException::withMessages([$this->keyring->username() => __('auth.failed')]);
        }

        Authenticated::dispatch($user, $attempt, $device);

        // "Was this you?" for anything suspicious since they last signed in.
        // A browser the account hasn't used before could be whoever caused
        // them, so they wait for one it has: one the account had already
        // used when they happened. A browser first seen since could be
        // whoever caused those, on its second visit.
        $request->session()->flash('keyring.alerts', $new ? [] : $this->log->pullAlerts($user, since: $device?->created_at)->map(fn (SecurityEvent $event) => [
            'type' => $event->type,
            'factor' => $event->factor,
            'at' => $event->created_at->toIso8601String(),
            'ip' => $event->ip,
        ])->all());

        if ($new) {
            NewDeviceSignedIn::dispatch($user, $device);
        }
    }

    /**
     * Sign the guard out of this browser, and empty its session, without
     * the registry: for when that is what failed. The "remember me" token
     * is left as it is.
     */
    protected function signOutGuard(Request $request): void
    {
        $guard = $this->keyring->guard();

        $guard instanceof SessionGuard ? $guard->logoutCurrentDevice() : $guard->logout();
        $request->session()->invalidate();
    }

    /**
     * Whether this login may mark the device trusted: the user asked, and it
     * verified two categories on an account whose email is proven. Otherwise
     * a second factor enrolled later would be skipped on a device that never
     * proved one.
     */
    protected function earnedTrust(Attempt $attempt): bool
    {
        $user = $attempt->user();

        return $attempt->trustDevice
            && Requirement::aal2()->isMetBy($attempt->verifications)
            && (! Features::enabled(Features::emailVerification()) || ! $user instanceof MustVerifyEmail || $user->hasVerifiedEmail());
    }

    /**
     * Whether the password or the email address is no longer the one this
     * request loaded and checked. Read after the session is registered: if
     * they're still the same, a change hasn't saved yet, and its sign-out
     * will find this session.
     */
    protected function changedMeanwhile(Authenticatable&Model $user): bool
    {
        $now = $user->newQuery()->whereKey($user->getKey())->first();
        $email = $this->keyring->email();

        return ! $now instanceof Authenticatable
            || ! hash_equals((string) $user->getAuthPassword(), (string) $now->getAuthPassword())
            || $user->getAttribute($email) !== $now->getAttribute($email);
    }

    public function confirm(Request $request, Attempt $attempt): void
    {
        // A copy of the session from before must not carry on signed in
        // beside the one that just proved more.
        $this->sessions->rotate($request);
        $this->assurance->confirm($attempt->verifications, $attempt->added());
        $this->sessions->elevate($request, $this->assurance->level());

        Confirmed::dispatch($attempt->user(), $attempt);
    }

    /**
     * Count a sign-in method the user just added as verified in this
     * session: confirming it took proving it, here and now. The recovery
     * codes that come with a first second factor are then handed to a
     * session that has proved two, as NIST SP 800-63B-4 asks of codes
     * delivered online (Sec. 3.1.2.1). Like any proof, it changes the
     * session ID. $verification is what adding it proved, for a factor
     * that knows better than "now": a link at an identity provider that
     * let the user straight through on an old session there.
     */
    public function enrolled(Request $request, Authenticator $authenticator, ?Verification $verification = null): void
    {
        $request->session()->regenerate(true);
        $this->assurance->record([$verification ?? Verification::of($authenticator)]);
        $this->sessions->elevate($request, $this->assurance->level());
    }

    /**
     * Sign the current user out of this session. Returns who it was.
     *
     * Signing out on purpose changes the "remember me" token, as Laravel
     * does. A session that ends on its own (a timeout, say) leaves the token
     * alone, or one ending would sign out every remembered browser: its
     * record is revoked, and that is what stops this browser's cookies
     * bringing it back (Sessions::end). Nor does signing out of an
     * impersonation: the token is the user's, and they didn't sign out.
     * When the registry fails then, it's the impersonator's token that's
     * cycled, if any: the browser's "remember me" cookies are theirs, and
     * their parked session, which would refuse them, may still be open
     * (Impersonation::signedOut).
     */
    public function out(Request $request, bool $onlyThisBrowser = false): ?Authenticatable
    {
        $guard = $this->keyring->guard();
        $user = $guard->user();
        $impersonating = app(Impersonation::class)->active($request);

        // Signing out of an impersonation is the impersonator's doing, so
        // the user's own "remember me" token is left alone.
        $onlyThisBrowser = $onlyThisBrowser || $impersonating;

        // Signed out whatever happens to the registry: a revocation that
        // fails is thrown on, but never leaves the browser signed in with no
        // record, for the next request to register afresh. The
        // impersonator's parked session ends with this one.
        try {
            if ($impersonating) {
                app(Impersonation::class)->signedOut($request);
            }

            $this->sessions->end($request);
        } finally {
            $onlyThisBrowser && $guard instanceof SessionGuard ? $guard->logoutCurrentDevice() : $guard->logout();
            $this->assurance->flush();

            $request->session()->invalidate();
            $request->session()->regenerateToken();
        }

        return $user;
    }

    /**
     * Sign in a user who just proved something outside the pipeline, like
     * choosing a password at registration.
     *
     * @param  list<Verification>  $verifications
     */
    public function as(Request $request, Authenticatable&Model $user, array $verifications, bool $remember = false): void
    {
        $this->complete($request, Attempt::start(Purpose::Login, $user, $remember, verifications: $verifications));
    }
}
