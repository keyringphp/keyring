<?php

declare(strict_types=1);

namespace Keyring;

/**
 * The features an app turns on in config/keyring.php. Signing in and out,
 * challenges and step-up are always there; everything else is a feature.
 *
 *     'features' => [
 *         Features::registration(),
 *         Features::resetPasswords(),
 *         Features::emailVerification(),
 *         Features::updatePasswords(),
 *     ],
 */
final class Features
{
    public static function enabled(string $feature): bool
    {
        return in_array($feature, config('keyring.features'), true);
    }

    /**
     * Every feature, e.g. for a test that turns them all on.
     *
     * @return list<string>
     */
    public static function all(): array
    {
        return [
            self::registration(),
            self::resetPasswords(),
            self::emailVerification(),
            self::updatePasswords(),
            self::manageAuthenticators(),
            self::devices(),
            self::emailChanges(),
            self::securityLog(),
            self::impersonation(),
        ];
    }

    /**
     * Sign up at /register, through your CreatesNewUsers action. Needs
     * emailVerification() too, unless "registration.reveal_taken" is on.
     */
    public static function registration(): string
    {
        return 'registration';
    }

    /**
     * Reset a forgotten password by email.
     */
    public static function resetPasswords(): string
    {
        return 'reset-passwords';
    }

    /**
     * Verify the email address, with Laravel's MustVerifyEmail.
     */
    public static function emailVerification(): string
    {
        return 'email-verification';
    }

    /**
     * Change the password while signed in. Keyring then owns the password
     * attribute: changing it anywhere else throws.
     */
    public static function updatePasswords(): string
    {
        return 'update-passwords';
    }

    /**
     * Add, rename and remove authenticators (passkeys, authenticator apps,
     * recovery codes) under /user/authenticators.
     */
    public static function manageAuthenticators(): string
    {
        return 'manage-authenticators';
    }

    /**
     * Recognise browsers with a cookie: "trust this device", a list of where
     * the user is signed in, and the "this wasn't me" link in emails.
     */
    public static function devices(): string
    {
        return 'devices';
    }

    /**
     * Change the email address by confirming the new one, with a link to
     * undo it sent to the old one. Keyring then owns the email attribute.
     */
    public static function emailChanges(): string
    {
        return 'email-changes';
    }

    /**
     * Record sign ins, failures, refusals and changes in keyring_events, and
     * show "was this you?" alerts at the next sign in. On by default.
     * Without it the same events are written to the app's log instead.
     */
    public static function securityLog(): string
    {
        return 'security-log';
    }

    /**
     * Let someone sign in as another user, to see the app as they do, and
     * come back to their own account. Nobody may until
     * Keyring::allowImpersonationWhen() says who may impersonate whom.
     */
    public static function impersonation(): string
    {
        return 'impersonation';
    }
}
