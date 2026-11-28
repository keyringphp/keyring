<?php

declare(strict_types=1);

namespace Keyring\Support;

use Illuminate\Encryption\MissingAppKeyException;

/**
 * HMAC-SHA256 for values Keyring stores only to look up or compare later.
 *
 * APP_KEY is never the HMAC key itself. Each purpose gets a key of its own,
 * derived from it with HKDF and the purpose's name, so a hash made for one
 * thing means nothing as another, and none is made with the key Laravel
 * encrypts and signs with.
 */
final class KeyedHash
{
    /** A user's recovery codes. */
    public const string RECOVERY_CODES = 'recovery-codes';

    /** Codes sent by email, or by a code factor of the app's. */
    public const string ONE_TIME_CODES = 'one-time-codes';

    /** Addresses an email change holds for the account that had them. */
    public const string RESERVED_ADDRESSES = 'reserved-addresses';

    /** The handle a passkey knows its user by. */
    public const string USER_HANDLES = 'webauthn-user-handles';

    /** The handle a page knows one of a user's sessions by. */
    public const string SESSION_HANDLES = 'session-handles';

    /** The claim on announcing an impersonation's end. */
    public const string IMPERSONATION_ENDS = 'impersonation-ends';

    public static function make(string $purpose, #[\SensitiveParameter] string $value): string
    {
        return self::candidates($purpose, $value)[0];
    }

    /**
     * The value hashed with the current key and every previous one, so
     * rotating APP_KEY (with APP_PREVIOUS_KEYS) keeps stored hashes working.
     *
     * @return non-empty-list<string>
     */
    public static function candidates(string $purpose, #[\SensitiveParameter] string $value): array
    {
        return array_map(
            fn (string $key) => hash_hmac('sha256', $value, hash_hkdf('sha256', $key, 32, 'keyring:'.$purpose)),
            self::keys(),
        );
    }

    /**
     * The app's keys as Laravel's encrypter reads them, the current one
     * first.
     *
     * @return non-empty-list<string>
     */
    private static function keys(): array
    {
        if (blank($current = config('app.key'))) {
            throw new MissingAppKeyException;
        }

        return array_map(
            fn (string $key) => str_starts_with($key, 'base64:') ? base64_decode(substr($key, 7)) : $key,
            array_values([$current, ...config('app.previous_keys', [])]),
        );
    }
}
