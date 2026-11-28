<?php

declare(strict_types=1);

namespace Keyring\Enums;

/**
 * How much attention a security log entry wants. The values are PSR-3 log
 * levels, so an entry written to a log channel goes out at its own level.
 */
enum Severity: string
{
    /** Someone did what they were allowed to: signed in, signed out. */
    case Info = 'info';

    /** Worth a look when it wasn't expected: a new device, a changed password. */
    case Notice = 'notice';

    /** Something was refused, or looks like someone else at work. */
    case Warning = 'warning';

    /** A sign-in method or a safeguard can no longer be relied on. */
    case Critical = 'critical';

    /**
     * The severity of one of Keyring's entry types. A type of the app's own
     * is informational unless it says otherwise when it's recorded.
     */
    public static function of(string $type): self
    {
        return match ($type) {
            'new_device', 'authenticator_added', 'authenticator_removed', 'recovery_code_used', 'email_changed',
            'password_changed', 'password_reset', 'risk_step_up', 'risk_reauthenticate', 'risk_notified',
            'risk_password_change', 'impersonation_started' => self::Notice,

            'factor_failed', 'second_factor_failed', 'locked_out', 'rate_limited', 'account_locked', 'device_reported',
            'remember_me_reused', 'email_change_reverted', 'protection_bypassed', 'access_refused',
            'enrollment_refused', 'authenticator_removal_refused', 'link_refused', 'refusals_limited',
            'risk_denied', 'risk_locked', 'risk_revoked_sessions', 'impersonation_refused' => self::Warning,

            'clone_suspected', 'verification_refused' => self::Critical,

            default => self::Info,
        };
    }
}
