<?php

declare(strict_types=1);

use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Process;
use Illuminate\Support\Sleep;
use Keyring\Changes\EmailChanges;
use Keyring\Changes\PasswordChanges;
use Keyring\Contracts\SessionRegistry;
use Keyring\Enums\Assurance;
use Keyring\Events\RegisteredSessionEnded;
use Keyring\Facades\Keyring;
use Keyring\Factors\SingleSignOn;
use Keyring\Impersonation\Impersonation;
use Keyring\Models\Authenticator;
use Keyring\Models\FailureCount;
use Keyring\Models\PendingChange;
use Keyring\Sessions\RegisteredSession;
use Keyring\Sessions\SessionAssurance;
use Keyring\Sessions\Sessions;
use Keyring\Testing\VirtualAuthenticator;
use Keyring\Tests\Fixtures\User;
use Keyring\WebAuthn\Ceremonies;
use Keyring\WebAuthn\Profile;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Webauthn\AuthenticatorSelectionCriteria;

beforeEach(function () {
    if (DB::getDriverName() === 'sqlite') {
        $this->markTestSkipped('SQLite has no row locks; CI runs these on PostgreSQL and MySQL.');
    }

    useRaceFactors();
});

it('never lets two removals at once take the last way in', function () {
    $user = taylor(['password' => null]);
    $first = Authenticator::factory()->passkey()->for($user, 'authenticatable')->create();
    $second = Authenticator::factory()->passkey()->for($user, 'authenticatable')->create();

    $results = contend($user, [
        ['remove-authenticator', $user->id, $first->id],
        ['remove-authenticator', $user->id, $second->id],
    ]);

    expect(outcomes($results, true))->toBe(1)
        ->and(outcomes($results, 'refused'))->toBe(1)
        ->and(Authenticator::query()->where('factor', 'passkey')->count())->toBe(1);
});

it('lets one of two removals at once take a sign-in method the account counts on, and freezes the other', function () {
    $user = taylor();
    $first = Authenticator::factory()->totp()->established()->for($user, 'authenticatable')->create();
    $second = Authenticator::factory()->totp()->established()->for($user, 'authenticatable')->create();
    Authenticator::factory()->passkey()->established()->for($user, 'authenticatable')->create();

    $results = contend($user, [
        ['remove-authenticator', $user->id, $first->id],
        ['remove-authenticator', $user->id, $second->id],
    ]);

    expect(outcomes($results, true))->toBe(1)
        ->and(outcomes($results, 'refused'))->toBe(1)
        ->and(Authenticator::query()->where('factor', 'totp')->count())->toBe(1);
});

it('spends a recovery code once, however many requests bring it', function () {
    $user = taylor();
    $codes = Authenticator::factory()->recoveryCodes(['aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aa', 'bbbb-bbbb-bbbb-bbbb-bbbb-bbbb-bb'])->for($user, 'authenticatable')->create();

    $results = contend($codes, [
        ['use-recovery-code', $codes->id, 'aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aa'],
        ['use-recovery-code', $codes->id, 'aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aa'],
    ]);

    expect(outcomes($results, true))->toBe(1)
        ->and(outcomes($results, false))->toBe(1);
});

it('lets one of two assertions with the same count through, and keeps that count', function () {
    $user = taylor();
    $ceremonies = app(Ceremonies::class);
    $key = new VirtualAuthenticator;

    $creation = $ceremonies->creationOptions($user, Profile::passkeys(), []);
    $record = $ceremonies->register(json_encode($key->register($ceremonies->toBrowser($creation))), $ceremonies->toJson($creation), Profile::passkeys());

    $passkey = Authenticator::factory()->passkey()->for($user, 'authenticatable')->create([
        'credential_id' => Base64UrlSafe::encodeUnpadded($record->publicKeyCredentialId),
        'public_key' => $ceremonies->toJson($record),
        'sign_count' => $record->counter,
    ]);

    $options = $ceremonies->requestOptions([], AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED);
    $browser = $ceremonies->toBrowser($options);
    $json = $ceremonies->toJson($options);

    // A clone answers with the same counter as the original.
    $results = contend($passkey, [
        ['use-passkey', $passkey->id, (string) json_encode(['options' => $json, 'credential' => (clone $key)->assert($browser)])],
        ['use-passkey', $passkey->id, (string) json_encode(['options' => $json, 'credential' => (clone $key)->assert($browser)])],
    ]);

    expect(outcomes($results, true))->toBe(1)
        ->and(outcomes($results, false))->toBe(1)
        ->and($passkey->fresh()->sign_count)->toBe($record->counter + 1);
});

it('takes one of two answers to the same challenge, though the passkey\'s count never moves', function () {
    $user = taylor();
    $ceremonies = app(Ceremonies::class);
    // A synced passkey: its count stays at zero, so only the challenge
    // tells a second use of an answer from the first.
    $key = new VirtualAuthenticator(synced: true, counts: false);

    $creation = $ceremonies->creationOptions($user, Profile::passkeys(), []);
    $record = $ceremonies->register(json_encode($key->register($ceremonies->toBrowser($creation))), $ceremonies->toJson($creation), Profile::passkeys());

    $passkey = Authenticator::factory()->passkey()->for($user, 'authenticatable')->create([
        'credential_id' => Base64UrlSafe::encodeUnpadded($record->publicKeyCredentialId),
        'public_key' => $ceremonies->toJson($record),
        'sign_count' => $record->counter,
    ]);

    $options = $ceremonies->requestOptions([], AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED);
    $answer = (string) json_encode(['options' => $ceremonies->toJson($options), 'credential' => $key->assert($ceremonies->toBrowser($options))]);

    // The same signed answer, twice. One uses the challenge up and goes on
    // to wait for the key's row. The other is turned away before it.
    $results = contend($passkey, [
        ['answer-challenge', $passkey->id, $answer],
        ['answer-challenge', $passkey->id, $answer],
    ], waiting: 1);

    expect(outcomes($results, true))->toBe(1)
        ->and(outcomes($results, false))->toBe(1)
        ->and($passkey->fresh()->sign_count)->toBe(0);
});

it('checks one more proof at the last failure the cap allows, however many arrive together', function () {
    $user = taylor();

    // One short of the 80 failures in a row browsers the account hasn't
    // signed in from may make.
    $count = new FailureCount(['factor' => 'password', 'authenticator' => 'password', 'failures' => 79]);
    $count->authenticatable()->associate($user)->save();

    $results = contend($count, [
        ['guess-password', $user->id],
        ['guess-password', $user->id],
        ['guess-password', $user->id],
    ]);

    expect(outcomes($results, 'checked'))->toBe(1)
        ->and(outcomes($results, 'refused'))->toBe(2)
        ->and($count->fresh())
        ->failures->toBe(80)
        ->locked_at->not->toBeNull();
});

it('ends with the old address whichever of confirm and revert wins', function () {
    $user = taylor();
    $change = new PendingChange([
        'attribute' => 'email',
        'value' => 'new@example.com',
        'previous_value' => 'taylor@example.com',
        'confirm_token' => PendingChange::hashToken('confirm'),
        'revert_token' => PendingChange::hashToken('revert'),
        'expires_at' => now()->addDay(),
    ]);
    $change->authenticatable()->associate($user)->save();

    [$confirmed, $reverted] = contend($change, [
        ['confirm-email-change', $change->id, 'confirm'],
        ['revert-email-change', $change->id, 'revert'],
    ]);

    // Confirming first applies the change and the revert undoes it; reverting
    // first leaves nothing to confirm.
    expect($confirmed)->toBeIn(['Applied', 'Invalid'])
        ->and($reverted)->toBeTrue()
        ->and($user->fresh()->email)->toBe('taylor@example.com')
        ->and($change->fresh()->reverted_at)->not->toBeNull();
});

it('puts the address back when a later change is confirmed while an earlier one is being reverted', function () {
    $user = taylor();
    $pending = fn (string $address) => tap(new PendingChange([
        'attribute' => 'email',
        'value' => $address,
        'previous_value' => 'taylor@example.com',
        'confirm_token' => PendingChange::hashToken('confirm'),
        'revert_token' => PendingChange::hashToken('revert'),
        'expires_at' => now()->addDay(),
    ]), fn (PendingChange $change) => $change->authenticatable()->associate($user)->save());

    // Asked for and then replaced by a second request: its "this wasn't me"
    // link still works.
    $first = $pending('first@example.com');
    $first->forceFill(['cancelled_at' => now(), 'revertable_until' => now()->addDay()])->save();
    $second = $pending('second@example.com');

    // The second change's confirmation holds its row. The revert waits for
    // it, and the confirmation finishes before letting go.
    [$reverted] = contend($second, [['revert-email-change', $first->id, 'revert']], function () use ($user, $second) {
        Keyring::withoutProtection(fn () => $user->forceFill(['email' => 'second@example.com'])->save());
        $second->forceFill(['confirmed_at' => now(), 'applied_at' => now(), 'revertable_until' => now()->addDay()])->save();
    });

    expect($reverted)->toBeTrue()
        ->and($user->fresh()->email)->toBe('taylor@example.com')
        ->and($second->fresh()->canRevert())->toBeFalse();
});

// An undo, a reset and "this wasn't me" end the sessions holding the user's
// row. A request that was let through before waits there, and looks again.
it('refuses an email change from a session that is signed out while its request waits', function (bool $signedOut, mixed $expected) {
    $user = taylor();
    $now = now()->getTimestamp();
    app(SessionRegistry::class)->save(new RegisteredSession('asking', (string) $user->id, RegisteredSession::typeOf($user), 'web', null, Assurance::AAL1, null, null, $now, $now, $now + 3600));

    [$requested] = contend($user, [['request-email-change', $user->id, 'asking']], fn () => $signedOut && app(SessionRegistry::class)->revokeAll($user));

    expect($requested)->toBe($expected)
        ->and(PendingChange::query()->count())->toBe($signedOut ? 0 : 1);
})->with([
    'signed out meanwhile' => [true, 'signed out'],
    'still signed in' => [false, true],
]);

// The same for a sign-in method: one saved by a request that was let through
// before its session ended would be the one thing an undo left behind.
it('refuses a sign-in method from a session that is signed out while its request waits', function (bool $signedOut, string $expected) {
    $user = taylor();
    $now = now()->getTimestamp();
    app(SessionRegistry::class)->save(new RegisteredSession('asking', (string) $user->id, RegisteredSession::typeOf($user), 'web', null, Assurance::AAL1, null, null, $now, $now, $now + 3600));

    [$added] = contend($user, [['add-authenticator', $user->id, 'asking']], fn () => $signedOut && app(SessionRegistry::class)->revokeAll($user));

    expect($added)->toBe($expected)
        ->and(Authenticator::query()->where('factor', 'totp')->count())->toBe($signedOut ? 0 : 1);
})->with([
    'signed out meanwhile' => [true, 'signed out'],
    'still signed in' => [false, 'added'],
]);

// A password saved while the change waits for the user's row: a reset's
// UPDATE, or another session's change. The change then finds a password it
// didn't check, and is refused.
it('refuses a password change whose current password is replaced while its request waits', function (string $meanwhile, string $expected, string $stored) {
    $user = taylor();
    $now = now()->getTimestamp();
    app(SessionRegistry::class)->save(new RegisteredSession('asking', (string) $user->id, RegisteredSession::typeOf($user), 'web', null, Assurance::AAL1, null, null, $now, $now, $now + 3600));

    [$changed] = contend($user, [['change-password', $user->id, 'asking']], fn () => match ($meanwhile) {
        'reset' => app(PasswordChanges::class)->reset($owner = $user->fresh(), fn () => $owner->forceFill(['password' => 'the reset password'])->save()),
        'change' => app(PasswordChanges::class)->change($other = $user->fresh(), fn () => $other->forceFill(['password' => 'the reset password'])->save(), currentSession: 'asking', signOutOthers: false),
        default => null,
    });

    expect($changed)->toBe($expected)
        ->and(Hash::check($stored, $user->fresh()->password))->toBeTrue();
})->with([
    'reset meanwhile' => ['reset', 'signed out', 'the reset password'],
    'changed elsewhere meanwhile' => ['change', 'refused', 'the reset password'],
    'nothing meanwhile' => ['', 'changed', 'a passphrase sent a moment later'],
]);

it('lets one of two requests use a "remember me" cookie, and starts one session between them', function () {
    $user = taylor();
    $now = now()->getTimestamp();
    $registry = app(SessionRegistry::class);
    $registry->save(new RegisteredSession('remembered', (string) $user->id, RegisteredSession::typeOf($user), 'web', null, Assurance::AAL1, null, null, $now, $now, $now + 3600));

    // Both read the record before either can replace it.
    $results = contend(sessionRow('remembered'), [
        ['resume-session', 'remembered'],
        ['resume-session', 'remembered'],
    ]);

    // The one that lost is told so, and joins the other's session (the
    // middleware looks the record up again).
    $resumed = $registry->find('remembered')->replacedBy;

    expect(outcomes($results, null))->toBe(1)
        ->and(outcomes($results, $resumed))->toBe(1)
        ->and($registry->forUser($user)->map->id->all())->toBe([$resumed])
        ->and(DB::table('keyring_sessions')->count())->toBe(2);
});

it('keeps an account to its session limit when two sign ins land at once', function () {
    $user = taylor();
    $now = now()->getTimestamp();
    $registry = app(SessionRegistry::class);

    foreach (['older' => 120, 'newer' => 60] as $id => $ago) {
        $registry->save(new RegisteredSession($id, (string) $user->id, RegisteredSession::typeOf($user), 'web', null, Assurance::AAL1, null, null, $now - $ago, $now - $ago, $now + 3600));
    }

    // Each waits for the user's row, so the second counts the first's session.
    $started = contend($user, [
        ['start-session', $user->id, 2],
        ['start-session', $user->id, 2],
    ]);

    expect($registry->forUser($user)->map->id->all())->toEqualCanonicalizing($started)
        ->and($registry->find('older')->revokedAt)->not->toBeNull()
        ->and($registry->find('newer')->revokedAt)->not->toBeNull();
});

it('leaves nothing signed in when a sign-out everywhere meets a "remember me" cookie coming back', function () {
    $user = taylor();
    $now = now()->getTimestamp();
    $registry = app(SessionRegistry::class);
    $registry->save(new RegisteredSession('remembered', (string) $user->id, RegisteredSession::typeOf($user), 'web', null, Assurance::AAL1, null, null, $now, $now, $now + 3600, remembered: true));

    // Both wait for the user's row. Whichever goes first, the session ends:
    // signed out and then refused, or carried on and then signed out.
    [$resumed, $revoked] = contend($user, [
        ['resume-session', 'remembered'],
        ['sign-out', $user->id],
    ]);

    expect($revoked)->toBe(1)
        ->and($registry->forUser($user))->toBeEmpty()
        ->and($registry->find($resumed ?? 'remembered')->revokedAt)->not->toBeNull();
});

// A used cookie means two browsers held it, and the session ends for both.
// The one still on it may be carrying it on to a new record at that moment.
it('ends a reused "remember me" session wherever it has moved to by the time it is ended', function () {
    $user = taylor();
    $now = now()->getTimestamp();
    $registry = app(SessionRegistry::class);
    $registry->save(new RegisteredSession('remembered', (string) $user->id, RegisteredSession::typeOf($user), 'web', null, Assurance::AAL1, null, null, $now, $now, $now + 3600, remembered: true));

    // Both wait for the user's row. Carried on first, it's followed to the
    // new record and ended there. Ended first, there's nothing to carry on.
    [$resumed, $ended] = contend($user, [
        ['resume-session', 'remembered'],
        ['end-latest', 'remembered'],
    ]);

    expect($ended)->toBe($resumed ?? 'remembered')
        ->and($registry->forUser($user))->toBeEmpty()
        ->and($registry->find($ended)->revokedAt)->not->toBeNull();
});

it('signs out a session that moved to a new record while everyone was being signed out', function () {
    $user = taylor();
    $now = now()->getTimestamp();
    $registry = app(SessionRegistry::class);
    $registry->save($session = new RegisteredSession('remembered', (string) $user->id, RegisteredSession::typeOf($user), 'web', null, Assurance::AAL1, null, null, $now, $now, $now + 3600, remembered: true));

    // The sign-out comes to the record while "remember me" is carrying its
    // session on, and waits. By the time it gets the record, the session is
    // on another one it hasn't seen.
    contend(sessionRow('remembered'), [['sign-out-everyone', 'everyone']], function () use ($registry, $session) {
        expect($registry->replace('remembered', $session->with(['id' => 'resumed'])))->toBeTrue();
    });

    expect($registry->find('resumed')->revokedAt)->not->toBeNull()
        ->and($registry->find('remembered')->revokedAt)->not->toBeNull()
        ->and($registry->forUser($user))->toBeEmpty();
});

// Stopping moves the admin's record as they come back, holding their
// row, so a sign-out everywhere that overlaps it either ends the record it
// moved to, or ends the one it moves from first, which it then can't move.
it('leaves nothing of the admin signed in when they stop impersonating as they\'re signed out everywhere', function () {
    $admin = taylor();
    $user = User::create(['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => 'password']);
    $now = now()->getTimestamp();
    $registry = app(SessionRegistry::class);
    $registry->save($own = new RegisteredSession('admins-own', (string) $admin->id, RegisteredSession::typeOf($admin), 'web', null, Assurance::AAL2, null, null, $now, $now, $now + 3600));
    $impersonated = app(Sessions::class)->startImpersonation($user, $admin, $own, $now + 3600);

    $browser = [
        Sessions::KEY => $impersonated->id,
        Impersonation::KEY => [
            'impersonator' => (string) $admin->id,
            'type' => RegisteredSession::typeOf($admin),
            'name' => 'Taylor',
            'session' => $own->id,
            'handle' => app(Sessions::class)->handle($impersonated),
            'user' => (string) $user->id,
            'user_type' => RegisteredSession::typeOf($user),
            'remembered' => false,
            'started_at' => $now,
            'expires_at' => $now + 3600,
            'password' => Keyring::guard()->hashPasswordForCookie($admin->getAuthPassword()),
            'parked' => [SessionAssurance::ACTIVE => $now],
        ],
    ];

    $results = contend($admin, [['stop-impersonating', $user->id, json_encode($browser)], ['sign-out', $admin->id]]);

    expect($results[0])->toBe('back')
        ->and($registry->find($own->id)->revokedAt)->not->toBeNull()
        ->and($registry->find($impersonated->id)->revokedAt)->not->toBeNull()
        ->and($registry->forUser($admin))->toBeEmpty();
});

// Two of the browser's requests that find it over at once, XHRs sent as its
// time ran out say, both revoke the impersonated record, which locks it,
// then claim its end. Only the one that claims it goes back and logs the
// end. The other leaves it, without signing the admin out of the record
// the first moved to.
it('ends an impersonation two requests end at once once, leaving the admin signed in', function () {
    $admin = taylor();
    $user = User::create(['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => 'password']);
    $now = now()->getTimestamp();
    $registry = app(SessionRegistry::class);
    $registry->save($own = new RegisteredSession('admins-own', (string) $admin->id, RegisteredSession::typeOf($admin), 'web', null, Assurance::AAL2, null, null, $now, $now, $now + 3600));
    $impersonated = app(Sessions::class)->startImpersonation($user, $admin, $own, $now + 3600);

    $browser = json_encode([
        Sessions::KEY => $impersonated->id,
        Impersonation::KEY => [
            'impersonator' => (string) $admin->id,
            'type' => RegisteredSession::typeOf($admin),
            'name' => 'Taylor',
            'session' => $own->id,
            'handle' => app(Sessions::class)->handle($impersonated),
            'user' => (string) $user->id,
            'user_type' => RegisteredSession::typeOf($user),
            'remembered' => false,
            'started_at' => $now,
            'expires_at' => $now + 3600,
            'password' => Keyring::guard()->hashPasswordForCookie($admin->getAuthPassword()),
            'parked' => [SessionAssurance::ACTIVE => $now],
        ],
    ]);

    $results = contend(sessionRow($impersonated->id), [['stop-impersonating', $user->id, $browser], ['stop-impersonating', $user->id, $browser]]);

    expect(outcomes($results, 'back'))->toBe(1)
        ->and(outcomes($results, 'signed out'))->toBe(1)
        ->and(DB::table('keyring_events')->where('type', 'impersonation_ended')->count())->toBe(2)
        ->and($registry->find($impersonated->id)->revokedAt)->not->toBeNull()
        ->and($registry->find($registry->find($own->id)->replacedBy)->isActive(now()->getTimestamp()))->toBeTrue()
        ->and($registry->forUser($admin))->toHaveCount(1);
});

// The record is read with a lock, so the second waits for the first, then
// finds it revoked: only one of them is given it.
it('gives a record two revokes reach at once to one of them', function () {
    $user = taylor();
    $now = now()->getTimestamp();
    app(SessionRegistry::class)->save(new RegisteredSession('phone', (string) $user->id, RegisteredSession::typeOf($user), 'web', null, Assurance::AAL1, null, null, $now, $now, $now + 3600));

    $results = contend(sessionRow('phone'), [['revoke', 'phone'], ['revoke', 'phone']]);

    expect(outcomes($results, 'phone'))->toBe(1)
        ->and(outcomes($results, null))->toBe(1);
});

// The records are read with a lock, so of two at once the second waits for
// the first, then finds them revoked: each is reported once, by one of them.
it('reports every record two sign-outs at once revoke, once between them', function () {
    $user = taylor();
    $now = now()->getTimestamp();
    $registry = app(SessionRegistry::class);

    foreach (['first', 'second', 'third'] as $id) {
        $registry->save(new RegisteredSession($id, (string) $user->id, RegisteredSession::typeOf($user), 'web', null, Assurance::AAL1, null, null, $now, $now, $now + 3600));
    }

    // Both wait for the record held here.
    $results = contend(sessionRow('second'), [
        ['revoke-all', $user->id],
        ['revoke-all', $user->id],
    ]);

    expect(collect($results)->sortBy(fn (array $ids) => count($ids))->values()->all())->toBe([[], ['first', 'second', 'third']])
        ->and(DB::table('keyring_sessions')->whereNull('revoked_at')->count())->toBe(0);
});

// Each announces what it revoked, so between them every record is announced
// once: none twice, none missed.
it('announces every record two sign-outs at once revoke, once between them', function () {
    $user = taylor();
    $now = now()->getTimestamp();
    $registry = app(SessionRegistry::class);

    $handles = array_map(function (string $id) use ($user, $registry, $now) {
        $registry->save($session = new RegisteredSession($id, (string) $user->id, RegisteredSession::typeOf($user), 'web', null, Assurance::AAL1, null, null, $now, $now, $now + 3600));

        return app(Sessions::class)->handle($session);
    }, ['first', 'second', 'third']);

    $results = contend(sessionRow('second'), [
        ['announce-revoke-all', $user->id],
        ['announce-revoke-all', $user->id],
    ]);

    expect(collect($results)->flatten()->sort()->values()->all())->toBe(collect($handles)->sort()->values()->all());
});

// A record another request revokes while a sign-out waits for it is that
// request's to report, not the sign-out's.
it('leaves out a record revoked by another request while a sign-out waits for it', function () {
    $user = taylor();
    $now = now()->getTimestamp();
    $registry = app(SessionRegistry::class);

    foreach (['first', 'second', 'third'] as $id) {
        $registry->save(new RegisteredSession($id, (string) $user->id, RegisteredSession::typeOf($user), 'web', null, Assurance::AAL1, null, null, $now, $now, $now + 3600));
    }

    [$revoked] = contend(sessionRow('second'), [['revoke-all', $user->id]], fn () => expect($registry->revoke('second')?->id)->toBe('second'));

    expect($revoked)->toBe(['first', 'third'])
        ->and(DB::table('keyring_sessions')->whereNull('revoked_at')->count())->toBe(0);
});

// An app's own transaction around a sign-out everywhere may have read before
// another browser signed in. On MySQL a plain read there sees the database
// as it was then; the sign-out still has to find and end the new session.
it('signs out a session that signed in after the caller\'s transaction began', function () {
    $user = taylor();
    $now = now()->getTimestamp();
    $registry = app(SessionRegistry::class);
    $registry->save(new RegisteredSession('before', (string) $user->id, RegisteredSession::typeOf($user), 'web', null, Assurance::AAL1, null, null, $now, $now, $now + 3600));

    $connection = DB::connection();
    $env = ['DB_CONNECTION' => $connection->getName(), 'DB_DATABASE' => $connection->getDatabaseName()];

    $connection->beginTransaction();

    try {
        // Takes this transaction's snapshot, on MySQL.
        expect($registry->forUser($user)->map->id->all())->toBe(['before']);

        $signIn = Process::env($env)->timeout(30)->run([PHP_BINARY, __DIR__.'/worker.php', 'start-session', (string) $user->id, '100']);
        expect($signIn->successful())->toBeTrue($signIn->output().$signIn->errorOutput());
        $after = json_decode(str($signIn->output())->afterLast('ready')->trim()->value(), true)['result'];

        $count = app(Sessions::class)->signOutEverywhere($user);
        $connection->commit();
    } catch (Throwable $e) {
        $connection->rollBack();

        throw $e;
    }

    expect($count)->toBe(2)
        ->and($registry->find($after)->revokedAt)->not->toBeNull()
        ->and($registry->forUser($user))->toBeEmpty();
});

/**
 * Records of the user's that the sweep would end, each with its handle.
 *
 * @return array<string, string>
 */
function timedOutSessions(User $user, int $count): array
{
    $then = now()->getTimestamp() - 3 * 3600;

    return collect(range(1, $count))->mapWithKeys(function (int $i) use ($user, $then) {
        $session = new RegisteredSession("timed-out-{$i}", (string) $user->id, RegisteredSession::typeOf($user), 'web', null, Assurance::AAL1, null, null, $then, $then, $then + 86400);
        app(SessionRegistry::class)->save($session);

        return [$session->id => app(Sessions::class)->handle($session)];
    })->all();
}

// Each locks what it ends, in ID order, so the second waits for the first,
// then finds them ended: each is announced once between the two.
it('announces each timed-out session once when two sweeps run at once', function () {
    $handles = timedOutSessions(taylor(), 3);

    $results = contend(sessionRow('timed-out-2'), [['sweep', 0], ['sweep', 0]]);

    expect(collect($results)->flatten()->sort()->values()->all())->toBe(collect($handles)->sort()->values()->all())
        ->and(DB::table('keyring_sessions')->whereNull('revoked_at')->count())->toBe(0);
});

// A request that used the session while the sweep waited for it wins: the
// sweep looks again once it has the row, and leaves it.
it('leaves a session a request used while the sweep waited for it', function () {
    timedOutSessions(taylor(), 1);

    [$announced] = contend(sessionRow('timed-out-1'), [['sweep', 0]], fn () => DB::table('keyring_sessions')->where('id', 'timed-out-1')->update(['last_activity_at' => now()->getTimestamp()]));

    expect($announced)->toBe([])
        ->and(DB::table('keyring_sessions')->where('id', 'timed-out-1')->value('revoked_at'))->toBeNull();
});

// One signed out while the sweep waits is that sign-out's to announce.
it('leaves a session signed out while the sweep waited for it to the sign-out', function () {
    $handles = timedOutSessions(taylor(), 2);
    $signedOut = new Collection;
    Event::listen(fn (RegisteredSessionEnded $event) => $signedOut->push($event->handle));

    [$swept] = contend(sessionRow('timed-out-1'), [['sweep', 0]], fn () => app(SessionRegistry::class)->revoke('timed-out-1'));

    expect($signedOut->all())->toBe([$handles['timed-out-1']])
        ->and($swept)->toBe([$handles['timed-out-2']]);
});

// A sign in past sessions.max ends the account's idle sessions in ID order,
// as the sweep does, so the two wait for each other rather than deadlock,
// and each session is ended, and announced, by one of them.
it('announces each session once when the sweep and a sign in past the limit end the same ones', function () {
    $user = taylor();
    $handles = timedOutSessions($user, 3);

    $results = contend(sessionRow('timed-out-2'), [['sweep', 0], ['start-session-announcing', $user->id, '1']]);

    expect(collect($results)->flatten()->sort()->values()->all())->toBe(collect($handles)->sort()->values()->all())
        ->and(DB::table('keyring_sessions')->whereNull('revoked_at')->count())->toBe(1);
});

// On the cache driver a revocation that lands while "remember me" moves the
// same record either waits for the move, and finds the session carried on,
// or ends it, and says so: never ends it with nothing announced.
it('announces a session a sign-out ends on the cache driver while it moves', function () {
    config(['keyring.sessions.driver' => 'cache', 'keyring.sessions.store' => 'database']);
    $user = taylor();
    $now = now()->getTimestamp();
    $registry = app(SessionRegistry::class);
    $registry->save(new RegisteredSession('moving', (string) $user->id, RegisteredSession::typeOf($user), 'web', null, Assurance::AAL1, null, null, $now, $now, $now + 3600));
    $ended = new Collection;
    Event::listen(fn (RegisteredSessionEnded $event) => $ended->push($event));

    $connection = DB::connection();
    $mover = Process::env(['DB_CONNECTION' => $connection->getName(), 'DB_DATABASE' => $connection->getDatabaseName()])->timeout(30)->start([PHP_BINARY, __DIR__.'/worker.php', 'cache-replace-paused', 'moving']);

    for ($deadline = microtime(true) + 15; ! Cache::store('database')->has('race:paused') && $mover->running() && microtime(true) < $deadline;) {
        Sleep::usleep(50_000);
    }

    expect(Cache::store('database')->has('race:paused'))->toBeTrue($mover->output().$mover->errorOutput());

    $registry->revoke('moving');
    $result = $mover->wait();
    expect($result->successful())->toBeTrue($result->output().$result->errorOutput());

    $successor = $registry->find('successor');

    expect($successor?->isActive(now()->getTimestamp()) === true ? 0 : 1)->toBe($ended->count());
});

/**
 * Sign the user in on a registered session, for a worker to link an account
 * at a provider on.
 */
function registeredSessionFor(User $user, string $id): void
{
    $now = now()->getTimestamp();

    app(SessionRegistry::class)->save(new RegisteredSession($id, (string) $user->id, RegisteredSession::typeOf($user), 'web', null, Assurance::AAL1, null, null, $now, $now, $now + 3600));
}

/**
 * An email change the user hasn't confirmed, with "this wasn't me" still
 * to click: undoing it removes what was added since it was asked for.
 */
function revertableChange(User $user): PendingChange
{
    return tap(new PendingChange([
        'attribute' => 'email',
        'value' => 'new@example.com',
        'previous_value' => 'taylor@example.com',
        'confirm_token' => PendingChange::hashToken('confirm'),
        'revert_token' => PendingChange::hashToken('revert'),
        'expires_at' => now()->addDay(),
    ]), fn (PendingChange $change) => $change->authenticatable()->associate($user)->save());
}

// Each link waits for its own user's row, by when both have looked for the
// account and found nobody has it. The account's unique credential ID turns
// the second away, as linked to someone else: never an error, nor two links.
it('links an account at a provider to one of two users linking it at once', function () {
    useRaceFactors(SingleSignOn::class);
    $taylor = taylor();
    $abigail = User::create(['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => 'password', 'email_verified_at' => now()]);
    registeredSessionFor($taylor, 'taylor');
    registeredSessionFor($abigail, 'abigail');

    $results = contend([$taylor, $abigail], [
        ['link-sso', $taylor->id, 'taylor'],
        ['link-sso', $abigail->id, 'abigail'],
    ]);

    expect(outcomes($results, 'added'))->toBe(1)
        ->and(outcomes($results, 'linked elsewhere'))->toBe(1)
        ->and(Authenticator::query()->where('factor', 'sso')->count())->toBe(1);
});

// A reset and "this wasn't me" each remove the links that could be an
// intruder's, sign out everywhere, and look again. A link whose callback
// waits for the user's row while the sign-out holds it is refused once it
// gets there; one that got there first is the second look's to find.
it('leaves no link from a session a reset or "this wasn\'t me" signs out while the link waits', function (string $meanwhile, string $expected) {
    useRaceFactors(SingleSignOn::class);
    $user = taylor();
    registeredSessionFor($user, 'intruder');
    $change = revertableChange($user);

    [$linked] = contend($user, [['link-sso', $user->id, 'intruder']], fn () => match ($meanwhile) {
        'reset' => app(PasswordChanges::class)->reset($owner = $user->fresh(), fn () => $owner->forceFill(['password' => 'the reset password'])->save()),
        'undo' => expect(app(EmailChanges::class)->revert($change, 'revert'))->toBeTrue(),
        default => null,
    });

    expect($linked)->toBe($expected)
        ->and(Authenticator::query()->where('factor', 'sso')->count())->toBe($meanwhile === '' ? 1 : 0);
})->with([
    'reset meanwhile' => ['reset', 'signed out'],
    'undone meanwhile' => ['undo', 'signed out'],
    'nothing meanwhile' => ['', 'added'],
]);

// The other way round: the first look has found an older link and waits to
// remove it, while the session that's about to be signed out links another.
// That one was saved before the sign-out, so the second look finds it.
it('removes a link saved between a reset\'s or "this wasn\'t me"\'s first look and its sign-out', function (string $undo) {
    useRaceFactors(SingleSignOn::class);
    $user = taylor();
    // So the session links without the password, which the reset has
    // already replaced by then.
    Authenticator::factory()->totp()->established()->for($user, 'authenticatable')->create();
    registeredSessionFor($user, 'intruder');
    $older = Authenticator::factory()->sso(subject: 'linked a moment earlier')->for($user, 'authenticatable')->create();

    [$undone] = contend($older, [match ($undo) {
        'reset' => ['reset-password', $user->id],
        'undo' => ['revert-email-change', revertableChange($user)->id, 'revert'],
    }], fn () => expect(work(['link-sso', $user->id, 'intruder']))->toBe('added'));

    expect($undone)->toBe($undo === 'reset' ? 'reset' : true)
        ->and(Authenticator::query()->where('factor', 'sso')->exists())->toBeFalse()
        ->and(app(SessionRegistry::class)->forUser($user))->toBeEmpty();
})->with(['reset', 'undo']);
