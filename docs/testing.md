# Testing

- [Introduction](#introduction)
- [Setting Up](#setting-up)
- [Acting at an Assurance Level](#acting-at-an-assurance-level)
- [Acting With Real Authenticators](#acting-with-real-authenticators)
- [Impersonating](#impersonating)
- [Faking Factors](#faking-factors)
- [Factories](#factories)
- [Virtual Authenticators](#virtual-authenticators)
- [Identity Providers](#identity-providers)
- [The Conformance Suite](#the-conformance-suite)

## Introduction

Keyring ships helpers in the `Keyring\Testing` namespace, so your tests can exercise your application's rules, such as who needs which factors and which routes require step-up. You don't need real codes, signatures, or any waiting to do it.

## Setting Up

To keep your tests fast and offline, add the `InteractsWithKeyring` trait to your base `TestCase` class:

```php
use Keyring\Testing\InteractsWithKeyring;

abstract class TestCase extends BaseTestCase
{
    use InteractsWithKeyring;
}
```

New passwords are only checked against Have I Been Pwned in production, so your tests don't make any network calls. See [Passwords](configuration.md#passwords).

The trait also swaps in an instant timebox for every test that uses it, so failed factor checks don't wait the usual 500ms. Tests without the trait wait the full `timebox` on every failed verification.

## Acting at an Assurance Level

The `InteractsWithKeyring` trait adds methods for tests where a user is signed in, along with one for reading errors:

```php
use Keyring\Enums\Assurance;

$this->actingAs($user)->withAssurance(Assurance::AAL2)->get('/billing')->assertOk();

$this->actingAs($user)->freshAt(now()->subHour())->deleteJson('/account')->assertStatus(423);
```

Here, `/billing` and `/account` stand for routes of your own, behind `keyring:aal2` and `keyring.fresh`.

- The `withAssurance` method pretends the session proved enough to reach the level you pass. For example, a password is enough for AAL1, a password and a TOTP code reach AAL2, and an attested security key that verified the user reaches AAL3. `Assurance::None` proves nothing.
- The `freshAt` method pretends those verifications happened at the time you pass, which matters for [`keyring.fresh`](step-up.md#fresh-verification). Without it, they happen now.

You may chain both methods, in either order. The level defaults to AAL1, so calling `freshAt` on its own gives the user a password verification at that time.

A plain `actingAs($user)` proves nothing, so routes behind `keyring.fresh`, including Keyring's own routes for managing sign-in methods, ask for step-up. A JSON request gets a `423` status, and any other request is redirected to the confirm page. For those routes, add `withAssurance`. A user with only a password also sends it to add their first second factor (see [Factories](#factories)):

```php
$this->actingAs($user)->withAssurance(Assurance::AAL1)
    ->postJson(route('keyring.authenticators.store', 'totp'), ['password' => 'password'])
    ->assertOk();
```

A plain request that needs step-up, such as a `delete` instead of a `deleteJson`, is redirected rather than answered with a `423`:

```php
$this->actingAs($user)->freshAt(now()->subHour())
    ->delete('/account')
    ->assertRedirect(route('keyring.confirm.challenge'));
```

The `sessionErrors` method returns the validation errors the last request flashed, as a `MessageBag`. Prefer it over `session('errors')`. Right after a request, `session('errors')` is a plain array when the session is serialized as JSON, which is the default in new Laravel applications:

```php
$this->post('/login', ['email' => $user->email, 'password' => 'wrong']);

expect($this->sessionErrors()->first('email'))->toBe(__('auth.failed'));
```

## Acting With Real Authenticators

The `withAssurance` method only pretends, so its verifications aren't tied to any authenticator. Code that looks up the authenticator behind a verification, such as the [email change](protected-changes.md#confirming) check for an established second factor, won't find one. In that case, tell the test which of the user's authenticators the session verified:

```php
use Keyring\Models\Authenticator;

// Added a month ago, so it's established and older than the session.
$totp = Authenticator::factory()->totp()->for($user, 'authenticatable')->create(['created_at' => now()->subMonth()]);

$this->actingAs($user)->verifiedWith($totp)->post('/user/email', ['email' => 'new@example.com']);
```

The factory's `established` method does the same, a month back. An authenticator made without it was added just now, so it isn't [established](authenticators.md#established-authenticators). A passkey made that way doesn't make `noDowngrade()` ask for a passkey, and the account's other sign-in methods are [frozen](authenticators.md#frozen-sign-in-methods) while it's there. Use `established` for one the user has had a while:

```php
Authenticator::factory()->passkey()->established()->for($user, 'authenticatable')->create();
```

A test that adds a second factor to an account with none established sends the user's password when it begins, as a real user does. See [The Password for a First Second Factor](authenticators.md#the-password-for-a-first-second-factor):

```php
$this->actingAs($user)->withAssurance(Assurance::AAL1)
    ->postJson(route('keyring.authenticators.store', 'totp'), ['password' => 'password'])
    ->assertOk();
```

The `verifiedWith` method accepts any number of authenticators and pretends the session verified the password and each one you pass. The level is whatever those reach, so a password and an authenticator app give AAL2. This means `verifiedWith` takes the place of `withAssurance`, and you may still chain `freshAt` with it, as before. Reach for `verifiedWith` when a test's user has a passkey or security key and calls a route behind `keyring.fresh`, such as adding another sign-in method. That route asks for the key, which `withAssurance(Assurance::AAL2)` doesn't pretend to have proved.

## Impersonating

[Starting an impersonation](impersonation.md#starting) takes two factors proved in the last 15 minutes by default, so act at AAL2 to start one, once your callback says who may:

```php
use Keyring\Enums\Assurance;
use Keyring\Facades\Keyring;

$this->actingAs($admin)->withAssurance(Assurance::AAL2)
    ->post(route('keyring.impersonation.store', $user))
    ->assertRedirect('/dashboard');

$this->assertAuthenticatedAs($user);
expect(Keyring::impersonating())->toBeTrue()
    ->and(Keyring::impersonator()->is($admin))->toBeTrue();
```

`/dashboard` is your `impersonation.redirect_url`, or `home`. Later requests in the same test carry on as the user, and `delete(route('keyring.impersonation.destroy'))` goes back to the admin. Remember that step-up can't be met while impersonating, so a route of yours behind `keyring:aal2` or `keyring.fresh` answers `403` until it stops. The admin comes back at AAL1, with nothing counting as fresh, so after the stop that route sends them to confirm. A test that stops and then visits one needs `withAssurance()` again first.

## Faking Factors

The `Keyring::fake` method decides factor checks without any real proofs. For example, to pass the `passkey` and `totp` factors and fail `email-code`, you may write:

```php
use Keyring\Facades\Keyring;

Keyring::fake()->pass('passkey', 'totp')->fail('email-code');
```

- Passed factors verify with whatever is posted, even nothing at all. Their validation rules are skipped.
- Failed factors always fail.
- Any factor you don't name is checked for real.
- Passing `sso` skips the provider, so no `ProviderIdentityAccepted` is dispatched and the verification has no `providerAmr` or `providerAcr`. Use `FakeIdentityProvider` to test those.

Identifying the user still happens for real. For example, posting an unknown email to `/login` fails even when `password` passes. Rate limiting, devices, risk, and your policy all run as normal.

To sign in with a faked factor, your test might look like this:

```php
Keyring::fake()->pass('totp');

$this->post('/login', ['email' => $user->email, 'password' => 'password'])
    ->assertRedirect(route('keyring.login.challenge'));

$this->post(route('keyring.login.verify', 'totp'))->assertRedirect('/dashboard');
```

The fake also records every factor check made once the account is known, whether faked or real. This lets a test assert what a request asked for:

```php
$fake = Keyring::fake()->pass('totp');

// ...

$fake->assertVerified('totp');
$fake->assertFailed('password', times: 2);
$fake->assertNotChecked('recovery');
```

| Method | Asserts |
|---|---|
| `assertVerified($factor, $times = null)` | The factor was checked and verified, that many times if given. |
| `assertFailed($factor, $times = null)` | The factor was checked and failed, that many times if given. |
| `assertNotChecked($factor)` | The factor was never checked. |
| `assertNothingChecked()` | No factor was checked. |

The `Keyring::fake` method throws a `LogicException` when the app environment is `production`, and nothing you bind by hand in the container can fake a check there. Other environments may use it, so a browser suite running against `local` or `staging` keeps working.

## Factories

The `Keyring\Models\Authenticator` model has a factory. To attach authenticators to a user, use the `authenticatable` relationship:

```php
use Keyring\Models\Authenticator;

Authenticator::factory()->totp()->for($user, 'authenticatable')->create();
Authenticator::factory()->securityKey()->default()->for($user, 'authenticatable')->create();
```

| State | Creates |
|---|---|
| `totp($secret = null)` | An authenticator app with a random secret, or the one you give. This is also the default state. |
| `recoveryCodes($codes = ['aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aa', 'bbbb-bbbb-bbbb-bbbb-bbbb-bbbb-bb', 'cccc-cccc-cccc-cccc-cccc-cccc-cc'])` | A set of recovery codes that accepts the codes you give. Each must be in the form Keyring makes them, 26 base32 characters (`a`-`z` and `2`-`7`), with or without dashes, or in Fortify's form, 20 letters and digits. Anything else throws an `InvalidArgumentException`. |
| `emailCode()` | Email codes. |
| `passkey($synced = true)` | A user-verified passkey, which is synced unless you pass `false`. One that isn't synced is device bound, and it reaches AAL3 when it's `attested()` and its factor requires attestation. |
| `securityKey($userVerified = false)` | A security key. |
| `attested($aaguid, $type = 'basic')` | Chain it onto either of those, for a key whose model was checked by attestation. |
| `sso($provider = 'fake', $subject = '248289761001', $issuer = 'https://idp.test', $email = 'taylor@example.com')` | An account at an identity provider, linked for [single sign-on](sso.md). The defaults are the account a plain `FakeIdentityProvider` signs in. |
| `default()` | Marks it as the default. |
| `unconfirmed()` | Not yet confirmed, so it doesn't count. |

The `totpCode` method, which comes from `InteractsWithKeyring`, gives you the code an authenticator app would show right now. It accepts a TOTP authenticator or a secret:

```php
$totp = Authenticator::factory()->totp()->for($user, 'authenticatable')->create();

$this->post(route('keyring.login.verify', 'totp'), ['code' => $this->totpCode($totp)]);
```

Each code works once, as in real life, so enrolling an app and then signing in with it within the same 30 seconds fails. Keyring keeps TOTP time on Laravel's clock. To move on to the next code, call `$this->travel(30)->seconds()`, or pass a later step, such as `$this->totpCode($totp, step: 1)`. An authenticator's code uses the digest it was set up with. For a bare secret, that's SHA-1 unless you pass `algorithm: 'sha256'`.

The `passkey` and `securityKey` states have no real public key, so they only verify with `Keyring::fake`. For real WebAuthn responses, enroll a virtual authenticator instead.

## Virtual Authenticators

The `Keyring\Testing\VirtualAuthenticator` class is a software WebAuthn key. It answers the options Keyring gives the browser with real, signed responses, so the whole ceremony runs without a browser or a hardware key. In a test, that looks like this:

```php
use Keyring\Testing\VirtualAuthenticator;

$key = new VirtualAuthenticator;

// Register it, with the password, as the user's first second factor.
$this->actingAs($user)->withAssurance(Assurance::AAL1);
$options = $this->postJson(route('keyring.authenticators.store', 'passkey'), ['password' => 'password'])->json('enrollment.options');
$this->postJson(route('keyring.authenticators.confirm', 'passkey'), ['credential' => $key->register($options)])->assertOk();
$this->post('/logout');

// Sign in with it, without a username.
$options = $this->getJson(route('keyring.login.options', 'passkey'))->json('options');
$this->post(route('keyring.login.factor', 'passkey'), ['credential' => $key->assert($options)])
    ->assertRedirect('/dashboard');
```

If the key is used on the challenge page, read the options from the page props instead. With Inertia, send the `X-Inertia` header to receive the page as JSON:

```php
$options = $this->withHeaders(['X-Inertia' => 'true'])
    ->get(route('keyring.login.challenge'))
    ->json('props.challenge.options');

$this->flushHeaders();

$this->post(route('keyring.login.verify', 'security-key'), ['credential' => $key->assert($options)]);
```

The constructor accepts these options:

| Option | Default | |
|---|---|---|
| `origin` | The first origin Keyring accepts | The origin the key claims to be on. Unless you set `webauthn.origins`, that's your `APP_URL`'s origin. |
| `userVerification` | `true` | Whether the key reports that it verified the user. Use `false` for a basic security key. |
| `aaguid` | 16 zero bytes | The AAGUID the key reports, as raw bytes. |
| `algorithm` | `ES256` | `ES256`, `EdDSA`, or `RS256`. |
| `bits` | `2048` | How long an `RS256` key is. |
| `backedUp` | `null` | Whether a `synced` key reports that it has been backed up yet. `null` means it has. |
| `synced` | `false` | Whether the key reports that it is a passkey that syncs between devices. |
| `counts` | `true` | Whether the key counts its signatures. Pass `false` for a key whose counter stays at zero, as a synced passkey's usually does. Then only the challenge tells its answer apart from the same answer sent again. |

The `VirtualAuthenticator::eddsa` method makes a key that signs with Ed25519 instead of P-256. It needs PHP's `sodium` extension, as does Keyring's support for Ed25519 keys. The `VirtualAuthenticator::rsa` method makes a key that signs with RS256. Keyring only accepts that algorithm once [`webauthn.algorithms`](passkeys.md#signature-algorithms) lists it. Calling `rsa(1024)` makes a key too short to be accepted.

You may call `$key->assert($options, $origin)` to answer from another origin, which lets you test that Keyring rejects it. The `$key->rewindCounter` method makes the next response reuse an old counter, as a cloned key would.

### Keys That Attest

A factor that [requires attestation](passkeys.md#requiring-attestation) refuses a plain virtual authenticator, the same as it would refuse any key that doesn't say who made it. The `Keyring\Testing\VirtualManufacturer` class makes keys with a throwaway root certificate. Trust its root, and its keys attest the way hardware does:

```php
use Keyring\Testing\VirtualManufacturer;

$maker = new VirtualManufacturer;
config(['keyring.webauthn.attestation_roots' => [$maker->root]]);

$key = $maker->key('2fc0579f-8113-47ea-b116-bb5a8db9202a');

$options = $this->postJson(route('keyring.authenticators.store', 'security-key'), ['password' => 'password'])->json('enrollment.options');
$this->postJson(route('keyring.authenticators.confirm', 'security-key'), ['credential' => $key->register($options)])->assertOk();
```

The `key` method takes the model's AAGUID, the format (`packed` by default, or `fido-u2f`, which has no AAGUID), and whether the key verifies the user. Create the manufacturer with `new VirtualManufacturer(intermediate: true)` to sign its keys' certificates with an intermediate certificate instead of the root. The `days:` argument sets how long its certificates last.

To check that your application turns keys away, use a key from a second `VirtualManufacturer` that you don't trust, or `new VirtualAuthenticator()->selfAttested()`, which attests with its own key pair.

## Identity Providers

`Keyring\Testing\FakeIdentityProvider` stands in for Google, Microsoft, GitHub, or any OpenID Connect provider, through `Http::fake()`, with really signed ID tokens. `register()` adds it to `sso.providers`, `signIn()` says who signs in, and `approve()` turns the URL Keyring sent the browser to into the callback the provider would send it back to:

```php
$google = FakeIdentityProvider::google()->register('google');
Authenticator::factory()->sso('google', subject: '42', issuer: GoogleProvider::ISSUER)->for($user, 'authenticatable')->create();

$url = $this->get(route('keyring.sso.redirect', 'google'))->headers->get('Location');

$this->get($google->signIn(['sub' => '42'])->approve($url))->assertRedirect('/dashboard');
```

Keyring only registers the `/auth` routes when `sso.providers` lists a provider as the app boots, so keep the provider in `config/keyring.php` too. `register()` only changes the config afterwards. Its ID tokens carry an `auth_time` (the fake Google's only when the request asks for it, as Google's do, and the fake Microsoft's only after `withAuthTimeClaim()`, as Microsoft's only do with the optional claim): `signedInAt()` gives the user an older session at the provider, which a sign in counts from when the provider's [`freshness`](sso.md#freshness) is `reauthenticate`, and a confirm with such a provider asks it to sign them in again. Google's and GitHub's sign ins are never fresh by default: register them with `['freshness' => 'reauthenticate']` or `['freshness' => 'round_trip']` to test a confirm with them. See [Testing](sso.md#testing) in Single Sign-On for linking, confirming, and for what it can be told to get wrong.

## The Conformance Suite

The `Keyring\Testing\KeyringConformance` trait provides a set of tests that check your setup still keeps Keyring's guarantees. The tests cover your policy, your factors, swapped responses, and pipeline changes. Checks for features that are turned off are skipped, along with the reason, so a skipped check means your setup doesn't use that feature. It doesn't count as a pass. To get started, add the trait to a test class and tell it how to make a user:

```php
namespace Tests\Feature;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Notification;
use Keyring\Testing\KeyringConformance;
use Tests\TestCase;

class KeyringConformanceTest extends TestCase
{
    use KeyringConformance, RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        Notification::fake();
    }

    protected function keyringUser(): User
    {
        return User::factory()->create(['password' => 'password', 'email_verified_at' => now()]);
    }
}
```

The `keyringUser` method must return a user whose password is `password`. To use a different password, override the `keyringPassword` method. The user's email must be verified, and the user must have no extra factors. Faking notifications stops the email code factor from sending real mail when the suite begins enrolling it.

The suite checks that:

- a correct password either signs the user in or leads to the challenge page,
- a wrong password and an unknown account give the same error,
- registering with an address that has an account is answered the same way as one that hasn't, and signs nobody in (skipped with `registration.reveal_taken`),
- protected attributes can't change outside Keyring's flows,
- changing sign-in methods needs a fresh verification,
- every enrollable factor can begin enrolling, apart from single sign-on, which needs a provider to send the user to,
- signing out revokes the registered session,
- the registry's `revoke()`, `revokeDevice()` and `revokeAll()` return exactly the records they revoked, each as it now stands, and nothing they didn't revoke. It fails when a [driver of your own](devices-and-sessions.md#writing-a-driver) gets that wrong,
- signing out announces the session that ended, once, with a [`RegisteredSessionEnded`](devices-and-sessions.md#hearing-about-ended-sessions). It fails when a `SessionRegistry` is bound in the container in place of the one Keyring's manager gives, which nothing announces,
- the `database` driver's table has the columns that note which ended sessions were announced (`announced_at`, `end_reason`, `announce_attempts`, `announce_after`), so [`keyring:sweep`](devices-and-sessions.md#sweeping-ended-sessions) can run. It's skipped on other drivers,
- the session registry keeps the record a session started on (`origin`) when the session moves, so the session keeps its [handle](devices-and-sessions.md#listing-and-ending-sessions). It fails when the `database` driver's table is missing the column, or when a [driver of your own](devices-and-sessions.md#writing-a-driver) doesn't store it,
- every route that uses the `auth` middleware for Keyring's guard also runs [`keyring.session`](devices-and-sessions.md#the-session-middleware), so a session that was revoked or timed out stops working there,
- passwords of 64 characters are allowed: `passwords.max` is at least 64, and the hasher isn't bcrypt, which stops at 72 bytes,
- the password broker Keyring uses has a `throttle`, so one account can't be sent [a reset link](protected-changes.md#resetting-the-password) as often as anyone asks (skipped without `Features::resetPasswords()`),
- one password hash takes less time than [`timebox`](configuration.md#pending-logins-timebox-and-rate-limits), which is what keeps a refusal that hashes from taking longer than one that doesn't,
- no mandatory pipeline step was removed or replaced with `dangerouslyRemove` or `dangerouslyReplace`.

The timing check times a hash where the tests run, so it's a guide to your servers, not a measurement of them. Bcrypt is timed at 12 rounds, or at your own setting if that's higher, since a test suite usually runs with fewer. If production hashes with different options, return those from `keyringProductionHashOptions`.

If you remove a [mandatory step](sign-in-flow.md#mandatory-steps) on purpose, return its class from the `keyringAcknowledgedDangerousSteps` method in your test class. If your `CreatesNewUsers` action validates fields other than `name`, `email`, `password`, and `password_confirmation`, return a form it accepts from `keyringRegistration(string $email)`.

The route check reads your application's routes as they're registered. It looks for `auth:{guard}` by name, plain `auth` when Keyring's guard is the default, and `auth:sanctum` on routes with Sanctum's `statefulApi()`, where a single-page app is signed in by its session. The check fails and lists the URIs that are missing the middleware. Add `keyring.session` to their group. For a route you leave unchecked on purpose, return its URI from the `keyringAcknowledgedUncheckedRoutes` method:

```php
protected function keyringAcknowledgedUncheckedRoutes(): array
{
    return ['internal/health'];
}
```

A new Laravel application hashes with bcrypt, so the password length check fails until you set `HASH_DRIVER=argon2id` (see [Passwords](configuration.md#passwords)). If your tests run on bcrypt for speed but production doesn't, set the driver for this test class. To keep bcrypt and its limit, say so:

```php
protected function keyringAcknowledgesBcryptLimit(): bool
{
    return true;
}
```

The `KeyringConformance` trait includes `InteractsWithKeyring`, and its tests are ordinary `test_*` methods.
