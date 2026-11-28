<?php

declare(strict_types=1);

namespace Keyring\Activity;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Events\Dispatcher;
use Illuminate\Support\Str;
use Keyring\Events;
use Keyring\Factors\RecoveryCodes;
use Keyring\KeyringManager;
use Keyring\Support\Duration;

/**
 * Turns Keyring's events into security log entries.
 */
class RecordSecurityEvents
{
    public function __construct(
        protected SecurityLog $log,
        protected KeyringManager $keyring,
    ) {}

    /**
     * @return array<class-string, string>
     */
    public function subscribe(Dispatcher $events): array
    {
        return [
            Events\Authenticated::class => 'authenticated',
            Events\Confirmed::class => 'confirmed',
            Events\FactorFailed::class => 'factorFailed',
            Events\Lockout::class => 'lockout',
            Events\RateLimited::class => 'rateLimited',
            Events\AccountLocked::class => 'accountLocked',
            Events\LoggedOut::class => 'loggedOut',
            Events\AuthenticatorAdded::class => 'authenticatorAdded',
            Events\AuthenticatorRemoved::class => 'authenticatorRemoved',
            Events\RecoveryCodeUsed::class => 'recoveryCodeUsed',
            Events\RecoveryCodesGenerated::class => 'recoveryCodesGenerated',
            Events\NewDeviceSignedIn::class => 'newDevice',
            Events\DeviceRevoked::class => 'deviceRevoked',
            Events\SessionsRevoked::class => 'sessionsRevoked',
            Events\SessionEnded::class => 'sessionEnded',
            Events\RememberMeReused::class => 'rememberMeReused',
            Events\SessionResumed::class => 'sessionResumed',
            Events\EmailChangeRequested::class => 'emailChangeRequested',
            Events\EmailChanged::class => 'emailChanged',
            Events\EmailChangeReverted::class => 'emailChangeReverted',
            Events\PasswordChanged::class => 'passwordChanged',
            Events\PasswordReset::class => 'passwordReset',
            Events\ProtectionBypassed::class => 'protectionBypassed',
            Events\CloneSuspected::class => 'cloneSuspected',
            Events\RiskAssessed::class => 'riskAssessed',
            Events\AccessRefused::class => 'accessRefused',
            Events\EnrollmentRefused::class => 'enrollmentRefused',
            Events\AuthenticatorRemovalRefused::class => 'authenticatorRemovalRefused',
            Events\LinkRefused::class => 'linkRefused',
            Events\VerificationRefused::class => 'verificationRefused',
            Events\ImpersonationEnded::class => 'impersonationEnded',
        ];
    }

    public function authenticated(Events\Authenticated $event): void
    {
        $this->log->record('signed_in', $event->user, device: $event->device?->id, meta: [
            'factors' => array_column($event->attempt->verifications, 'factor'),
        ]);
    }

    public function confirmed(Events\Confirmed $event): void
    {
        $this->log->record('confirmed', $event->user, meta: [
            'factors' => array_column($event->attempt->verifications, 'factor'),
        ]);
    }

    /**
     * A failed second factor after a correct password is the classic sign of
     * a stolen password, so it's logged as an alert for the user.
     *
     * An account's own limits bound how often it can fail. A name nobody
     * has can be made up without end, so those failures are a refusal like
     * any other, and only so many are kept per IP address.
     */
    public function factorFailed(Events\FactorFailed $event): void
    {
        $user = $event->attempt?->user();

        if ($user === null) {
            $this->log->recordRefusal('factor_failed', factor: $event->factor);

            return;
        }

        $this->log->record('factor_failed', $user, $event->factor);

        if ($event->afterFirstFactor()) {
            $this->log->record('second_factor_failed', $user, $event->factor);
        }
    }

    /**
     * The event fires for every request a lock refuses, and a client can
     * send those as fast as it likes. The log says once that the lock is
     * there: one entry per factor and IP address, until the wait the lock
     * gave is over. A refusal that waiting won't end, at the cap on
     * failures in a row, is noted once for as long as the longest lock.
     */
    public function lockout(Events\Lockout $event): void
    {
        $this->log->recordRefusal('locked_out', factor: $event->factor, meta: ['retry_after' => $event->retryAfter], once: $event->factor, for: $event->retryAfter ?? Duration::seconds(config('keyring.limits.longest_lock')));
    }

    /**
     * Like a lock, a full limiter refuses every request until it has room
     * again, and is logged once for that wait: per limiter and route, for
     * the account that's signed in or the IP address that asked.
     */
    public function rateLimited(Events\RateLimited $event): void
    {
        $this->log->recordRefusal('rate_limited', $event->user, meta: [
            'limiter' => $event->limiter,
            'route' => $event->route,
            'retry_after' => $event->retryAfter,
        ], once: $event->limiter.'|'.$event->route, for: $event->retryAfter);
    }

    public function accountLocked(Events\AccountLocked $event): void
    {
        $this->log->record('account_locked', $event->user, $event->factor);
    }

    public function loggedOut(Events\LoggedOut $event): void
    {
        $this->log->record('signed_out', $event->user);
    }

    public function authenticatorAdded(Events\AuthenticatorAdded $event): void
    {
        $this->log->record('authenticator_added', $event->user, $event->authenticator->factor, meta: ['name' => $event->authenticator->name]);
    }

    public function authenticatorRemoved(Events\AuthenticatorRemoved $event): void
    {
        $this->log->record('authenticator_removed', $event->user, $event->authenticator->factor, meta: ['name' => $event->authenticator->name]);
    }

    public function recoveryCodeUsed(Events\RecoveryCodeUsed $event): void
    {
        $this->log->record('recovery_code_used', $event->authenticator->user(), RecoveryCodes::KEY, meta: ['remaining' => $event->remaining]);
    }

    public function recoveryCodesGenerated(Events\RecoveryCodesGenerated $event): void
    {
        $this->log->record('recovery_codes_generated', $event->user, RecoveryCodes::KEY);
    }

    public function newDevice(Events\NewDeviceSignedIn $event): void
    {
        $this->log->record('new_device', $event->user, device: $event->device->id, meta: ['device' => $event->device->description()]);
    }

    public function deviceRevoked(Events\DeviceRevoked $event): void
    {
        $this->log->record($event->reported ? 'device_reported' : 'device_revoked', $event->user, device: $event->device->id, meta: ['device' => $event->device->description()]);
    }

    public function sessionsRevoked(Events\SessionsRevoked $event): void
    {
        $this->log->record('sessions_revoked', $event->user, meta: ['count' => $event->count]);
    }

    public function sessionEnded(Events\SessionEnded $event): void
    {
        $this->log->record('session_ended', $event->user, meta: ['reason' => $event->reason]);
    }

    /**
     * The entry's own address and browser are the request that brought the
     * used cookie. The device is the one the ended session was on.
     */
    public function rememberMeReused(Events\RememberMeReused $event): void
    {
        $this->log->record('remember_me_reused', $event->user, device: $event->session->deviceId, meta: [
            'device' => $this->keyring->describeDevice($event->session->userAgent),
        ]);
    }

    /**
     * "Remember me" signed a browser in again. It proved nothing, so the
     * entry says so by being its own type and not a sign in.
     */
    public function sessionResumed(Events\SessionResumed $event): void
    {
        $this->log->record('session_resumed', $event->user, device: $event->session->deviceId);
    }

    public function emailChangeRequested(Events\EmailChangeRequested $event): void
    {
        $this->log->record('email_change_requested', $event->user);
    }

    public function emailChanged(Events\EmailChanged $event): void
    {
        $this->log->record('email_changed', $event->user);
    }

    public function emailChangeReverted(Events\EmailChangeReverted $event): void
    {
        $this->log->record('email_change_reverted', $event->user);
    }

    public function passwordChanged(Events\PasswordChanged $event): void
    {
        $this->log->record('password_changed', $event->user);
    }

    public function passwordReset(Events\PasswordReset $event): void
    {
        $this->log->record('password_reset', $event->user, meta: ['sign_in_locks_cleared' => true]);
    }

    /**
     * A bypass is never left unlogged: if the entry can't be written this
     * throws, before the protected attributes are touched.
     */
    public function protectionBypassed(Events\ProtectionBypassed $event): void
    {
        $actor = $this->keyring->guard()->user();

        $this->log->recordOrFail('protection_bypassed', $actor instanceof Authenticatable ? $actor : null, meta: ['reason' => $event->reason]);
    }

    public function cloneSuspected(Events\CloneSuspected $event): void
    {
        $this->log->record('clone_suspected', $event->authenticator->user(), $event->authenticator->factor, meta: ['name' => $event->authenticator->name]);
    }

    public function riskAssessed(Events\RiskAssessed $event): void
    {
        $this->log->record('risk_'.$event->action->name(), $event->user, meta: [
            'checkpoint' => $event->checkpoint->value,
            'score' => $event->risk->score,
            'reasons' => $event->risk->reasons(),
        ]);
    }

    public function accessRefused(Events\AccessRefused $event): void
    {
        $this->log->recordRefusal('access_refused', $event->user, meta: ['resource' => $event->resource, 'id' => Str::limit($event->id, 64, '')]);
    }

    public function enrollmentRefused(Events\EnrollmentRefused $event): void
    {
        $this->log->recordRefusal('enrollment_refused', $event->user, $event->factor, meta: ['reason' => $event->reason]);
    }

    public function authenticatorRemovalRefused(Events\AuthenticatorRemovalRefused $event): void
    {
        $this->log->recordRefusal('authenticator_removal_refused', $event->user, $event->authenticator->factor, meta: ['name' => $event->authenticator->name, 'reason' => $event->reason]);
    }

    /**
     * Which link and why, never the token or signature that came with it.
     */
    public function linkRefused(Events\LinkRefused $event): void
    {
        $this->log->recordRefusal('link_refused', $event->user, meta: ['link' => $event->link, 'reason' => $event->reason]);
    }

    public function verificationRefused(Events\VerificationRefused $event): void
    {
        $this->log->recordRefusal('verification_refused', $event->attempt->user(), $event->factor, meta: [
            'skipped' => array_map(class_basename(...), $event->skipped),
        ]);
    }

    /**
     * On both accounts, as it started (Impersonation::start() logs that
     * itself, before the browser changes hands), but for one that can no
     * longer be loaded, deleted say: then on the other's alone. "role" says
     * which of them the entry's account was.
     */
    public function impersonationEnded(Events\ImpersonationEnded $event): void
    {
        $meta = [...$this->impersonation($event->impersonator, $event->user), 'reason' => $event->reason->value, 'returned' => $event->returned];

        if ($event->impersonator !== null) {
            $this->log->record('impersonation_ended', $event->impersonator, meta: [...$meta, 'role' => 'impersonator']);
        }

        if ($event->user !== null) {
            $this->log->record('impersonation_ended', $event->user, meta: [...$meta, 'role' => 'impersonated']);
        }
    }

    /**
     * @return array{impersonator: ?string, user: ?string}
     */
    protected function impersonation(?Authenticatable $impersonator, ?Authenticatable $user): array
    {
        return [
            'impersonator' => $impersonator === null ? null : (string) $impersonator->getAuthIdentifier(),
            'user' => $user === null ? null : (string) $user->getAuthIdentifier(),
        ];
    }
}
