<?php

declare(strict_types=1);

use Illuminate\Encryption\MissingAppKeyException;
use Illuminate\Http\Request;
use Keyring\Enums\Purpose;
use Keyring\Facades\Keyring;
use Keyring\Factors\EmailCode;
use Keyring\Login\Attempt;
use Keyring\Models\Authenticator;
use Keyring\Models\PendingChange;
use Keyring\Support\KeyedHash;
use Keyring\WebAuthn\Ceremonies;

/**
 * Every purpose Keyring hashes for.
 *
 * @return list<string>
 */
function keyedHashPurposes(): array
{
    return array_values(new ReflectionClass(KeyedHash::class)->getConstants());
}

it('never gives two purposes the same hash for the same value', function (string $value) {
    $hashes = array_map(fn (string $purpose) => KeyedHash::make($purpose, $value), keyedHashPurposes());

    expect(keyedHashPurposes())->toHaveCount(6)
        ->and(array_unique($hashes))->toHaveCount(6);
})->with(['taylor@example.com', '1', '', 'abcd-efgh-ijkl-mnop-qrst-uvwx-yz']);

it('never hashes with the app key itself', function (string $purpose) {
    $key = config('app.key');
    $hash = KeyedHash::make($purpose, 'value');

    expect($hash)->toMatch('/^[0-9a-f]{64}$/')
        ->not->toBe(hash_hmac('sha256', 'value', $key))
        ->not->toBe(hash_hmac('sha256', 'value', base64_decode(substr($key, 7))))
        ->toBe(hash_hmac('sha256', 'value', hash_hkdf('sha256', base64_decode(substr($key, 7)), 32, 'keyring:'.$purpose)));
})->with(fn () => keyedHashPurposes());

it('still finds a hash made under a key that has since been rotated out', function (string $purpose) {
    $before = KeyedHash::make($purpose, 'value');

    config(['app.previous_keys' => [config('app.key')], 'app.key' => 'base64:'.base64_encode(random_bytes(32))]);

    expect(KeyedHash::make($purpose, 'value'))->not->toBe($before)
        ->and(KeyedHash::candidates($purpose, 'value'))->toHaveCount(2)->toContain($before)
        ->and(KeyedHash::candidates($purpose, 'value')[0])->toBe(KeyedHash::make($purpose, 'value'));

    // And only for the purpose it was made for.
    foreach (array_diff(keyedHashPurposes(), [$purpose]) as $other) {
        expect(KeyedHash::candidates($other, 'value'))->not->toContain($before);
    }
})->with(fn () => keyedHashPurposes());

it('reads a key that is not base64 as laravel does', function () {
    config(['app.key' => str_repeat('k', 32)]);

    expect(KeyedHash::make(KeyedHash::RECOVERY_CODES, 'value'))
        ->toBe(hash_hmac('sha256', 'value', hash_hkdf('sha256', str_repeat('k', 32), 32, 'keyring:recovery-codes')));
});

it('has nothing to hash with when the app has no key', function () {
    config(['app.key' => null]);

    KeyedHash::make(KeyedHash::RECOVERY_CODES, 'value');
})->throws(MissingAppKeyException::class);

it('hashes each kind of stored value under its own purpose', function () {
    $user = taylor();

    $recovery = Keyring::factor('recovery')->secretFor(['abcd-efgh-ijkl-mnop-qrst-uvwx-yz']);

    $factor = EmailCode::asExtraStep();
    $code = (fn () => $this->hash('12345678'))->call($factor);

    expect(json_decode($recovery))->toBe([KeyedHash::make(KeyedHash::RECOVERY_CODES, 'abcdefghijklmnopqrstuvwxyz')])
        ->and($code)->toBe(KeyedHash::make(KeyedHash::ONE_TIME_CODES, $factor->key().'|12345678'))
        ->and(PendingChange::lookupHash('Taylor@Example.com'))->toBe(KeyedHash::make(KeyedHash::RESERVED_ADDRESSES, 'taylor@example.com'))
        ->and(app(Ceremonies::class)->userHandle($user))->toBe(KeyedHash::make(KeyedHash::USER_HANDLES, $user->getMorphClass().':'.$user->id));
});

it('will not take one kind of stored hash for another', function () {
    $user = taylor();

    // A recovery set whose stored hash is the right code hashed as something else.
    $forged = Authenticator::factory()->for($user, 'authenticatable')->create([
        'factor' => 'recovery',
        'secret' => json_encode([KeyedHash::make(KeyedHash::ONE_TIME_CODES, 'abcdefghijklmnopqrstuvwxyz'), KeyedHash::make(KeyedHash::USER_HANDLES, 'abcdefghijklmnopqrstuvwxyz')]),
    ]);

    expect(Keyring::factor('recovery')->verify(Attempt::start(Purpose::Login, $user), $forged, Request::create('/', 'POST', ['code' => 'abcd-efgh-ijkl-mnop-qrst-uvwx-yz'])))->toBeNull();
});
