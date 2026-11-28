<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use Keyring\Enums\Assurance;
use Keyring\Enums\SsoFailure;
use Keyring\Enums\SsoFreshness;
use Keyring\Exceptions\SsoFailed;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\SingleSignOn;
use Keyring\Factors\Totp;
use Keyring\Login\Registration;
use Keyring\Login\SignIn;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;
use Keyring\Notifications\AuthenticatorAdded;
use Keyring\Notifications\PasswordChanged;
use Keyring\Sso\AuthorizationRequest;
use Keyring\Sso\Identity;
use Keyring\Sso\Providers\GitHubProvider;
use Keyring\Sso\Providers\GoogleProvider;
use Keyring\Testing\FakeIdentityProvider;
use Keyring\Tests\Fixtures\Sso\BitbucketProvider;
use Keyring\Tests\Fixtures\Sso\DiscordProvider;
use Keyring\Tests\Fixtures\Sso\FacebookProvider;
use Keyring\Tests\Fixtures\Sso\LinkedInProvider;
use Keyring\Tests\Fixtures\User;
use ParagonIE\ConstantTime\Base64UrlSafe;

// The examples docs/sso.md gives, run as it writes them.
beforeEach(function () {
    Http::preventStrayRequests();
    Keyring::factors([Password::class, SingleSignOn::class]);
});

it('moves the Socialite recipe\'s github_id into links that sign in', function () {
    Schema::table('users', fn (Blueprint $table) => $table->string('github_id')->nullable()->unique());
    $idp = FakeIdentityProvider::github()->register('github');
    reloadRoutes();
    $user = taylor(['github_id' => '583231']);
    taylor(['email' => 'abigail@example.com']);

    // "Migrating From the Socialite Recipe"
    User::query()->whereNotNull('github_id')->eachById(function (User $user) {
        $subject = (string) $user->github_id;

        $user->authenticators()->firstOrCreate(
            ['factor' => SingleSignOn::KEY, 'credential_id' => SingleSignOn::credentialId(GitHubProvider::ISSUER, $subject)],
            ['name' => 'GitHub', 'confirmed_at' => now(), 'meta' => ['provider' => 'github', 'issuer' => GitHubProvider::ISSUER, 'subject' => $subject, 'email' => null]],
        );
    });

    expect(Authenticator::query()->where('factor', 'sso')->count())->toBe(1);

    $url = $this->get(route('keyring.sso.redirect', 'github'))->headers->get('Location');
    $this->get($idp->approve($url))->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($user);
    expect($user->keyring->refresh()->of('sso')->sole()->meta('email'))->toBe('taylor@example.com')
        ->and(Keyring::factor('sso')->present($user->keyring->of('sso')->sole()))->toMatchArray(['provider' => 'github', 'name' => 'GitHub']);
});

/**
 * The routes "Signing Up With a Provider" gives, as it writes them.
 */
function signUpWithGoogleRoutes(): void
{
    Route::middleware(['web', 'guest'])->group(function () {
        Route::get('/sign-up/google', fn () => redirect()->away(
            Keyring::sso()->start('google', 'sign-up', route('sign-up.google.callback')),
        ))->name('sign-up.google');

        Route::get('/sign-up/google/callback', function (Request $request) {
            try {
                $identity = Keyring::sso()->complete($request, 'google');
            } catch (SsoFailed) {
                return to_route('register')->withErrors(['email' => 'We couldn\'t sign you up with Google.']);
            }

            abort_unless($identity->request->purpose === 'sign-up', 404);

            try {
                // Someone who already signed up: an ordinary sign in.
                if (Keyring::factor(SingleSignOn::KEY)->linked($identity) !== null) {
                    $request->attributes->set(SingleSignOn::IDENTITY, $identity);

                    return Keyring::attempt($request, SingleSignOn::KEY);
                }

                $email = $identity->email === null ? null : Keyring::normalizeUsername($identity->email);

                // Google only vouches for who owns a Gmail address, or one in a
                // Google Workspace domain (the "hd" claim). Any other address
                // was verified once, when the Google account was made, and may
                // have changed hands since.
                $vouched = $identity->emailVerified && $email !== null
                    && (str_ends_with($email, '@gmail.com') || (is_string($identity->claims['hd'] ?? null) && $identity->claims['hd'] !== ''));

                if (! $vouched || app(Registration::class)->taken($email)) {
                    return to_route('register')->withErrors(['email' => 'Sign up with your email address, then link Google from your settings.']);
                }

                [$user, $link] = DB::transaction(function () use ($identity, $email) {
                    $user = User::create(['name' => $identity->name ?? $email, 'email' => $email, 'password' => null]);
                    $user->forceFill(['email_verified_at' => now()])->save();

                    return [$user, $user->authenticators()->create([
                        'factor' => SingleSignOn::KEY,
                        'name' => "Google ({$email})",
                        'credential_id' => SingleSignOn::credentialId($identity->issuer, $identity->subject),
                        'confirmed_at' => now(),
                        'meta' => ['provider' => 'google', 'issuer' => $identity->issuer, 'subject' => $identity->subject, 'email' => $identity->email],
                    ])];
                });

                // The account didn't exist until this request, so this sign
                // in counts as fresh: long enough to choose a password or
                // add a passkey.
                app(SignIn::class)->as($request, $user, [Verification::of($link)]);
            } catch (ValidationException $e) {
                return to_route('login')->withErrors($e->errors());
            }

            return redirect('/settings/security');
        })->middleware('throttle:keyring-login-options')->block()->name('sign-up.google.callback');
    });
}

it('signs people up with a provider from routes of the app\'s own', function () {
    $idp = FakeIdentityProvider::google()->register('google');
    reloadRoutes();

    signUpWithGoogleRoutes();

    $url = $this->get('/sign-up/google')->assertRedirect()->headers->get('Location');
    expect(authorizationQuery($url)['redirect_uri'])->toBe('http://localhost/sign-up/google/callback');

    $this->get($idp->signIn(['sub' => 'new', 'email' => 'new@gmail.com'])->approve($url))->assertRedirect('/settings/security');

    $user = User::query()->where('email', 'new@gmail.com')->sole();
    $this->assertAuthenticatedAs($user);
    expect($user->password)->toBeNull()
        ->and($user->email_verified_at)->not->toBeNull()
        ->and($user->keyring->of('sso')->sole()->name)->toBe('Google (new@gmail.com)');

    // The sign up is fresh, so the new account can choose a password,
    // which is announced to the address Google vouched for.
    Notification::fake();
    $this->putJson(route('user-password.update'), ['password' => 'a long new passphrase', 'password_confirmation' => 'a long new passphrase'])->assertOk();
    Notification::assertSentTo($user, PasswordChanged::class);

    // The same account through Keyring's own button signs the same user
    // in, but Google's sign ins are never fresh.
    Auth::logout();
    $this->get($idp->approve($this->get(route('keyring.sso.redirect', 'google'))->headers->get('Location')))->assertRedirect('/dashboard');
    $this->assertAuthenticatedAs($user);
    $this->postJson(route('keyring.authenticators.store', 'sso'), ['provider' => 'google'])->assertStatus(423);
    Auth::logout();
    $this->flushSession();

    // So does the sign-up button, once they've signed up.
    $this->get($idp->approve($this->get('/sign-up/google')->headers->get('Location')))->assertRedirect('/dashboard');
    $this->assertAuthenticatedAs($user);
    $this->postJson(route('keyring.authenticators.store', 'sso'), ['provider' => 'google'])->assertStatus(423);
    Auth::logout();

    // An address someone already has is never taken over, however the
    // provider writes it.
    taylor(['email' => 'taylor@gmail.com']);
    $this->get($idp->signIn(['sub' => 'other', 'email' => 'Taylor@Gmail.com'])->approve($this->get('/sign-up/google')->headers->get('Location')))
        ->assertRedirect(route('register'))
        ->assertSessionHasErrors('email');
    $this->assertGuest();
});

it('signs up a Google Workspace account, and announces a method added while the sign up is fresh', function () {
    Keyring::factors([Password::class, Totp::class, SingleSignOn::class]);
    $idp = FakeIdentityProvider::google()->register('google');
    reloadRoutes();
    signUpWithGoogleRoutes();
    Notification::fake();

    $this->get($idp->signIn(['sub' => 'new', 'email' => 'new@example.com', 'hd' => 'example.com'])->approve($this->get('/sign-up/google')->headers->get('Location')))
        ->assertRedirect('/settings/security');

    $user = User::query()->where('email', 'new@example.com')->sole();
    $this->assertAuthenticatedAs($user);

    $secret = $this->postJson(route('keyring.authenticators.store', 'totp'))->assertOk()->json('enrollment.secret');
    $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => totpCode($secret)])->assertOk();
    Notification::assertSentTo($user, AuthenticatorAdded::class);
});

it('signs nobody up with an address Google verified once but isn\'t the authority for', function (array $claims) {
    $idp = FakeIdentityProvider::google()->register('google');
    reloadRoutes();
    signUpWithGoogleRoutes();

    // Not Gmail, and no Workspace domain: the address may have changed hands.
    $this->get($idp->signIn(['sub' => 'new', 'email' => 'new@example.com', 'email_verified' => true, ...$claims])->approve($this->get('/sign-up/google')->headers->get('Location')))
        ->assertRedirect(route('register'))
        ->assertSessionHasErrors('email');

    $this->assertGuest();
    expect(User::query()->where('email', 'new@example.com')->exists())->toBeFalse()
        ->and(Authenticator::query()->where('factor', 'sso')->exists())->toBeFalse();
})->with([
    'no hd' => [[]],
    'an empty hd' => [['hd' => '']],
]);

it('has a user who only has GitHub enroll first, and confirm with a round trip once GitHub is opted into one', function () {
    // "Step-Up"
    Keyring::factors([Password::class, Totp::class, RecoveryCodes::class, SingleSignOn::class]);
    $github = FakeIdentityProvider::github()->register('github');
    reloadRoutes();
    $user = taylor(['password' => null]);
    Authenticator::factory()->sso('github', '583231', GitHubProvider::ISSUER)->for($user, 'authenticatable')->create();

    $this->actingAs($user)->withAssurance(Assurance::AAL1)->freshAt(now()->subHour());
    $this->postJson(route('keyring.authenticators.store', 'totp'))->assertForbidden()->assertJsonPath('status', 'enroll-first');

    config(['keyring.sso.providers.github.freshness' => 'round_trip']);

    $this->postJson(route('keyring.authenticators.store', 'totp'))->assertStatus(423);
    $page = $this->getJson(route('keyring.confirm.challenge'))->assertJsonPath('props.factor', 'sso')->json('props.challenge.url');
    $url = $this->get($page)->headers->get('Location');
    expect(authorizationQuery($url))->not->toHaveKeys(['max_age', 'prompt']);

    $this->get($github->approve($url))->assertRedirect();
    $this->postJson(route('keyring.authenticators.store', 'totp'))->assertOk();
});

it('confirms as "Testing" shows', function () {
    // "Testing"
    Keyring::factors([Password::class, Totp::class, RecoveryCodes::class, SingleSignOn::class]);
    $google = FakeIdentityProvider::google()->register('google', ['freshness' => 'reauthenticate']);
    reloadRoutes();
    $user = taylor(['password' => null]);
    Authenticator::factory()->sso('google', subject: '42', issuer: GoogleProvider::ISSUER)->for($user, 'authenticatable')->create();

    $this->actingAs($user)->withAssurance(Assurance::AAL1)->freshAt(now()->subHour());
    $this->postJson(route('keyring.authenticators.store', 'totp'))->assertStatus(423);

    $page = $this->getJson(route('keyring.confirm.challenge'))->json('props.challenge.url');
    $url = $this->get($page)->headers->get('Location');

    $this->get($google->signIn(['sub' => '42'])->approve($url))->assertRedirect();
    $this->postJson(route('keyring.authenticators.store', 'totp'))->assertOk();
});

it('signs in as "Testing" shows', function () {
    // "Testing"
    $google = FakeIdentityProvider::google()->register('google');
    reloadRoutes();
    $user = taylor();
    Authenticator::factory()->sso('google', subject: '42', issuer: GoogleProvider::ISSUER)->for($user, 'authenticatable')->create();

    $url = $this->get(route('keyring.sso.redirect', 'google'))->headers->get('Location');

    $this->get($google->signIn(['sub' => '42'])->approve($url))->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($user);
});

it('links as "Testing" shows', function () {
    $google = FakeIdentityProvider::google()->register('google');
    reloadRoutes();
    $user = taylor();

    $url = $this->actingAs($user)->withAssurance(Assurance::AAL1)
        ->postJson(route('keyring.authenticators.store', 'sso'), ['provider' => 'google', 'password' => 'password'])
        ->json('enrollment.url');

    $this->get($google->approve($url))->assertSessionHas('status', 'authenticator-added');
});

it('lets in one workspace\'s accounts with the custom driver "Custom Drivers" shows', function () {
    // "Custom Drivers"
    Keyring::sso()->extend('workspace', fn (array $config, string $name) => new class($name, $config) extends GoogleProvider
    {
        protected function identityFrom(AuthorizationRequest $request, array $tokens, array $query): Identity
        {
            $identity = parent::identityFrom($request, $tokens, $query);

            if (($identity->claims['hd'] ?? null) !== $this->config['domain']) {
                throw SsoFailed::because(SsoFailure::InvalidToken, "[{$this->name}] signed in an account outside the workspace.");
            }

            return $identity;
        }
    });

    $idp = FakeIdentityProvider::google()->register('staff', ['driver' => 'workspace', 'name' => 'Acme Staff', 'domain' => 'acme.com', 'parameters' => ['hd' => 'acme.com']]);

    $url = ssoStart('staff');
    expect(authorizationQuery($url)['hd'])->toBe('acme.com')
        ->and(Keyring::sso()->provider('staff')->label())->toBe('Acme Staff')
        ->and(ssoComplete($idp->signIn(['hd' => 'acme.com'])->approve($url), 'staff')->subject)->toBe('248289761001')
        ->and(ssoFailure(fn () => ssoComplete($idp->signIn(['hd' => 'elsewhere.com'])->approve(ssoStart('staff')), 'staff'))[0])->toBe(SsoFailure::InvalidToken);
});

// The examples docs/sso-providers.md gives, run as it writes them.

/**
 * An OAuth 2.0 provider without OpenID Connect, through Http::fake(): its
 * token endpoint swaps a code for $tokens once, for the verifier of the
 * challenge the code was given for, and its API answers that access token
 * from $api, keyed by URL, with a body or a response. It gives back what
 * approve() gives for FakeIdentityProvider: the callback URL for a user who
 * signed in at the authorization URL.
 *
 * @param  array<string, mixed>  $tokens
 * @param  array<string, mixed>  $api
 * @param  (Closure(ClientRequest): bool)|null  $authenticates  how the client has to prove who it is
 * @return Closure(string): string
 */
function fakeOAuth2Provider(string $tokenEndpoint, array $tokens, array &$api, ?Closure $authenticates = null): Closure
{
    $codes = new ArrayObject;
    $authenticates ??= fn (ClientRequest $request) => $request->header('Authorization')[0] === 'Basic '.base64_encode(FakeIdentityProvider::CLIENT_ID.':'.FakeIdentityProvider::CLIENT_SECRET);

    Http::fake(function (ClientRequest $request) use ($codes, $tokenEndpoint, $tokens, &$api, $authenticates) {
        $url = Str::before($request->url(), '?');

        if ($url === $tokenEndpoint) {
            $data = $request->data();
            $challenge = $codes[$data['code'] ?? ''] ?? null;
            unset($codes[$data['code'] ?? '']);

            return $challenge !== null && $authenticates($request) && is_string($data['code_verifier'] ?? null)
                && Base64UrlSafe::encodeUnpadded(hash('sha256', $data['code_verifier'], true)) === $challenge
                ? Http::response($tokens)
                : Http::response(['error' => 'invalid_grant'], 400);
        }

        if (! array_key_exists($url, $api)) {
            return null;
        }

        if (($request->header('Authorization')[0] ?? null) !== 'Bearer '.$tokens['access_token']) {
            return Http::response(['error' => 'invalid_token'], 401);
        }

        return is_array($api[$url]) ? Http::response($api[$url]) : $api[$url];
    });

    return function (string $authorizationUrl) use ($codes): string {
        $query = authorizationQuery($authorizationUrl);
        $codes[$code = Str::random(32)] = $query['code_challenge'];

        return $query['redirect_uri'].'?'.http_build_query(['code' => $code, 'state' => $query['state']]);
    };
}

it('signs in with the GitLab, Okta, Auth0, Keycloak, Cognito and Salesforce config "More Identity Providers" gives', function (array $config, string $subject, SsoFreshness $freshness) {
    $idp = new FakeIdentityProvider($config['issuer'], algorithm: 'RS256')->register('provider', [...$config, 'client_id' => FakeIdentityProvider::CLIENT_ID, 'client_secret' => FakeIdentityProvider::CLIENT_SECRET]);

    $identity = ssoComplete($idp->signIn(['sub' => $subject])->approve(ssoStart('provider')), 'provider');

    expect($identity->issuer)->toBe($config['issuer'])
        ->and($identity->subject)->toBe($subject)
        ->and($identity->emailVerified)->toBeTrue()
        ->and(Keyring::sso()->provider('provider')->label())->toBe($config['name'])
        ->and(Keyring::sso()->provider('provider')->freshness())->toBe($freshness);
})->with([
    'gitlab' => [[
        'driver' => 'oidc',
        'name' => 'GitLab',
        'issuer' => 'https://gitlab.com',
        'freshness' => 'never',
        'client_id' => env('GITLAB_CLIENT_ID'),
        'client_secret' => env('GITLAB_CLIENT_SECRET'),
    ], '1234567', SsoFreshness::Never],
    'okta' => [[
        'driver' => 'oidc',
        'name' => 'Okta',
        'issuer' => 'https://example.okta.com',
        'client_id' => env('OKTA_CLIENT_ID'),
        'client_secret' => env('OKTA_CLIENT_SECRET'),
    ], '00u1a2b3c4D5e6F7g8h9', SsoFreshness::Reauthenticate],
    'auth0' => [[
        'driver' => 'oidc',
        'name' => 'Auth0',
        'issuer' => 'https://example.us.auth0.com/',
        'client_id' => env('AUTH0_CLIENT_ID'),
        'client_secret' => env('AUTH0_CLIENT_SECRET'),
    ], 'auth0|64f1c0ffee0123456789abcd', SsoFreshness::Reauthenticate],
    'keycloak' => [[
        'driver' => 'oidc',
        'name' => 'Keycloak',
        'issuer' => 'https://keycloak.example.com/realms/acme',
        'client_id' => env('KEYCLOAK_CLIENT_ID'),
        'client_secret' => env('KEYCLOAK_CLIENT_SECRET'),
    ], '5c7d1b2e-8f3a-4b6c-9d0e-1f2a3b4c5d6e', SsoFreshness::Reauthenticate],
    'cognito' => [[
        'driver' => 'oidc',
        'name' => 'Acme',
        'issuer' => 'https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_AbCdEf123',
        'client_id' => env('COGNITO_CLIENT_ID'),
        'client_secret' => env('COGNITO_CLIENT_SECRET'),
        'freshness' => 'never',
    ], 'a1b2c3d4-5678-90ab-cdef-EXAMPLE11111', SsoFreshness::Never],
    'salesforce' => [[
        'driver' => 'oidc',
        'name' => 'Salesforce',
        'issuer' => 'https://login.salesforce.com',
        'client_id' => env('SALESFORCE_CLIENT_ID'),
        'client_secret' => env('SALESFORCE_CLIENT_SECRET'),
        'freshness' => 'never',
    ], 'https://login.salesforce.com/id/00D5e000000abcdEAA/0055e000001AbCdAAK', SsoFreshness::Never],
]);

it('reads a GitLab sign in, and keeps no address without the email scope', function () {
    // "GitLab": its discovery lists neither auth_time nor the claims
    // parameter, but its ID tokens carry auth_time.
    $gitlab = new FakeIdentityProvider('https://gitlab.com', algorithm: 'RS256')
        ->withDiscovery(['claims_supported' => ['iss', 'sub', 'aud', 'exp', 'iat', 'name', 'email', 'email_verified']])
        ->register('gitlab', ['name' => 'GitLab', 'scopes' => ['openid', 'profile']]);
    $gitlab->signedInAt($signedInAt = now()->subMinutes(3))->signIn(['sub' => '1234567', 'email' => null, 'email_verified' => null, 'nickname' => 'taylor']);

    $url = ssoStart('gitlab');
    expect(authorizationQuery($url))->not->toHaveKey('claims')
        ->and(authorizationQuery($url)['scope'])->toBe('openid profile');

    $identity = ssoComplete($gitlab->approve($url), 'gitlab');

    expect($identity->authTime)->toBe($signedInAt->getTimestamp())
        ->and($identity->email)->toBeNull()
        ->and($identity->emailVerified)->toBeFalse();

    // With the email scope, an address GitLab hasn't verified isn't.
    $gitlab->signIn(['email' => 'taylor@example.com', 'email_verified' => false]);
    expect(ssoComplete($gitlab->approve(ssoStart('gitlab')), 'gitlab')->emailVerified)->toBeFalse();
});

it('refuses Auth0\'s issuer without its trailing slash', function () {
    // "Auth0"
    new FakeIdentityProvider('https://example.us.auth0.com/', algorithm: 'RS256')->register('auth0', ['issuer' => 'https://example.us.auth0.com']);

    expect(ssoFailure(fn () => ssoStart('auth0')))->toBe([SsoFailure::Unavailable, 'Single sign-on failed (unavailable): [auth0]\'s discovery document is for another issuer.']);
});

it('signs in with Slack, whose token endpoint answers as its Web API does', function () {
    // "Slack": {"ok": true, ...} beside the tokens, and a refused code with
    // a 200 and {"ok": false, "error": "invalid_code"}.
    $slack = new class('https://slack.com', algorithm: 'RS256') extends FakeIdentityProvider
    {
        protected function token(ClientRequest $request): mixed
        {
            $answer = parent::token($request)->wait();
            $body = json_decode((string) $answer->getBody(), true);

            return Http::response(['ok' => ! isset($body['error']), ...$body], 200);
        }
    };
    $slack->withDiscovery(['claims_parameter_supported' => false, 'claims_supported' => ['sub', 'auth_time', 'iss'], 'response_modes_supported' => ['query']]);

    config(['keyring.sso.providers.slack' => [
        'driver' => 'oidc',
        'name' => 'Slack',
        'issuer' => 'https://slack.com',
        'client_id' => FakeIdentityProvider::CLIENT_ID,
        'client_secret' => FakeIdentityProvider::CLIENT_SECRET,
        'freshness' => 'never',
    ]]);

    $slack->signIn([
        'sub' => 'U123ABC456',
        'https://slack.com/user_id' => 'U123ABC456',
        'https://slack.com/team_id' => 'T0123ABC456',
        'email' => 'alice@example.com',
        'email_verified' => true,
        'name' => 'Alice',
    ]);

    $url = ssoStart('slack');
    expect(authorizationQuery($url))->not->toHaveKeys(['claims', 'max_age', 'prompt']);

    $identity = ssoComplete($slack->approve($url), 'slack');

    expect($identity->issuer)->toBe('https://slack.com')
        ->and($identity->subject)->toBe('U123ABC456')
        ->and($identity->claims['https://slack.com/team_id'])->toBe('T0123ABC456')
        ->and($identity->emailVerified)->toBeTrue()
        ->and(Keyring::sso()->provider('slack')->freshness())->toBe(SsoFreshness::Never);

    $slack->failExchange(200, 'invalid_code');
    expect(ssoFailure(fn () => ssoComplete($slack->approve(ssoStart('slack')), 'slack')))
        ->toBe([SsoFailure::ExchangeFailed, 'Single sign-on failed (exchange_failed): [slack]\'s token endpoint refused the code (200) with the error [invalid_code].']);
});

it('signs in with Twitch, asking for the address with the claims parameter', function () {
    // "Twitch"
    $twitch = new FakeIdentityProvider('https://id.twitch.tv/oauth2', algorithm: 'RS256')
        ->authMethods(['client_secret_post'])
        ->withDiscovery(['claims_parameter_supported' => true]);

    config(['keyring.sso.providers.twitch' => [
        'driver' => 'oidc',
        'name' => 'Twitch',
        'issuer' => 'https://id.twitch.tv/oauth2',
        'client_id' => FakeIdentityProvider::CLIENT_ID,
        'client_secret' => FakeIdentityProvider::CLIENT_SECRET,
        'scopes' => ['openid', 'user:read:email'],
        'parameters' => ['claims' => '{"id_token":{"email":null,"email_verified":null}}'],
        'freshness' => 'never',
    ]]);

    $url = ssoStart('twitch');

    expect(authorizationQuery($url))->toMatchArray(['scope' => 'openid user:read:email', 'claims' => '{"id_token":{"email":null,"email_verified":null}}']);

    $identity = ssoComplete($twitch->signIn(['sub' => '12345678', 'azp' => FakeIdentityProvider::CLIENT_ID, 'preferred_username' => 'taylor', 'email' => 'foo@justin.tv', 'email_verified' => true])->approve($url), 'twitch');

    expect($identity->subject)->toBe('12345678')
        ->and($identity->email)->toBe('foo@justin.tv')
        ->and($identity->emailVerified)->toBeTrue();

    // Twitch leaves email_verified out for an address it hasn't verified.
    $twitch->signIn(['email_verified' => null]);
    expect(ssoComplete($twitch->approve(ssoStart('twitch')), 'twitch')->emailVerified)->toBeFalse();
});

it('signs in, and links, with the Discord driver', function () {
    // "Registering a Driver" and "Discord"
    Keyring::sso()->extend('discord', fn (array $config, string $name) => new DiscordProvider($name, $config));

    config(['keyring.sso.providers.discord' => [
        'driver' => 'discord',
        'client_id' => FakeIdentityProvider::CLIENT_ID,
        'client_secret' => FakeIdentityProvider::CLIENT_SECRET,
    ]]);
    reloadRoutes();

    // Discord's example user object.
    $nelly = ['id' => '80351110224678912', 'username' => 'Nelly', 'discriminator' => '1337', 'global_name' => null, 'avatar' => '8342729096ea3675442027381ff50dfe', 'verified' => true, 'email' => 'nelly@discord.com', 'flags' => 64, 'premium_type' => 1, 'public_flags' => 64];
    $api = ['https://discord.com/api/v10/users/@me' => $nelly];
    $approve = fakeOAuth2Provider('https://discord.com/api/oauth2/token', ['access_token' => '6qrZcUqja7812RVdnEKjpzOL4CvHBFG', 'token_type' => 'Bearer', 'expires_in' => 604800, 'refresh_token' => 'D43f5y0ahjqew82jZ4NViEr2YafMKhue', 'scope' => 'identify email'], $api);

    $url = ssoStart('discord');
    expect($url)->toStartWith('https://discord.com/oauth2/authorize?')
        ->and(authorizationQuery($url))->toMatchArray(['scope' => 'identify email', 'code_challenge_method' => 'S256']);

    $identity = ssoComplete($approve($url), 'discord');

    expect($identity->issuer)->toBe(DiscordProvider::ISSUER)
        ->and($identity->subject)->toBe('80351110224678912')
        ->and($identity->email)->toBe('nelly@discord.com')
        ->and($identity->emailVerified)->toBeTrue()
        ->and($identity->name)->toBe('Nelly')
        ->and(Keyring::sso()->provider('discord')->label())->toBe('Discord')
        ->and(Keyring::sso()->provider('discord')->freshness())->toBe(SsoFreshness::Never)
        ->and(Keyring::sso()->provider('discord')->supportsReauthentication())->toBeFalse();

    // An address Discord hasn't verified, and none without the email scope.
    $api['https://discord.com/api/v10/users/@me'] = [...$nelly, 'verified' => false, 'global_name' => 'Nelly N'];
    expect(ssoComplete($approve(ssoStart('discord')), 'discord'))
        ->emailVerified->toBeFalse()
        ->name->toBe('Nelly N');

    $api['https://discord.com/api/v10/users/@me'] = Arr::except($nelly, ['email', 'verified']);
    expect(ssoComplete($approve(ssoStart('discord')), 'discord'))
        ->email->toBeNull()
        ->emailVerified->toBeFalse();

    // A username, or no account at all, is never taken for the ID.
    $api['https://discord.com/api/v10/users/@me'] = [...$nelly, 'id' => 'Nelly'];
    expect(ssoFailure(fn () => ssoComplete($approve(ssoStart('discord')), 'discord'))[0])->toBe(SsoFailure::Unavailable);

    $api['https://discord.com/api/v10/users/@me'] = Http::response(['message' => '401: Unauthorized', 'code' => 0], 401);
    expect(ssoFailure(fn () => ssoComplete($approve(ssoStart('discord')), 'discord'))[0])->toBe(SsoFailure::Unavailable);

    // Through Keyring's own button, for a user who linked it.
    $api['https://discord.com/api/v10/users/@me'] = $nelly;
    $user = taylor();
    Authenticator::factory()->sso('discord', '80351110224678912', DiscordProvider::ISSUER)->for($user, 'authenticatable')->create();

    $this->get($approve($this->get(route('keyring.sso.redirect', 'discord'))->headers->get('Location')))->assertRedirect('/dashboard');
    $this->assertAuthenticatedAs($user);
});

it('signs in with the Bitbucket driver, taking the primary address only when it\'s confirmed', function () {
    // "Bitbucket"
    Keyring::sso()->extend('bitbucket', fn (array $config, string $name) => new BitbucketProvider($name, $config));
    config(['keyring.sso.providers.bitbucket' => ['driver' => 'bitbucket', 'client_id' => FakeIdentityProvider::CLIENT_ID, 'client_secret' => FakeIdentityProvider::CLIENT_SECRET]]);

    $user = [
        'type' => 'user',
        'uuid' => '{d301aafa-d676-4ee0-88be-962be7417567}',
        'account_id' => '557058:c0b72ad0-1cb5-4018-9cdc-0cde8492c443',
        'nickname' => 'taylor',
        'display_name' => 'Taylor Otwell',
        'created_on' => '2014-03-01T15:31:07.427406+00:00',
        'links' => ['avatar' => ['href' => 'https://avatar-management--avatars.us-west-2.prod.public.atl-paas.net/initials/TO-0.png']],
    ];
    $address = fn (string $email, bool $primary, bool $confirmed) => ['type' => 'email', 'email' => $email, 'is_primary' => $primary, 'is_confirmed' => $confirmed, 'links' => ['self' => ['href' => 'https://api.bitbucket.org/2.0/user/emails/'.$email]]];
    $api = [
        BitbucketProvider::API.'/user' => $user,
        BitbucketProvider::API.'/user/emails' => ['pagelen' => 10, 'values' => [$address('old@example.com', false, true), $address('taylor@example.com', true, true)], 'page' => 1, 'size' => 2],
    ];
    $approve = fakeOAuth2Provider('https://bitbucket.org/site/oauth2/access_token', ['access_token' => 'bb-access-token', 'scopes' => 'account email', 'expires_in' => 7200, 'refresh_token' => 'bb-refresh-token', 'token_type' => 'bearer', 'state' => 'authorization_code'], $api);

    $url = ssoStart('bitbucket');
    expect($url)->toStartWith('https://bitbucket.org/site/oauth2/authorize?');

    expect(ssoComplete($approve($url), 'bitbucket'))
        ->issuer->toBe(BitbucketProvider::ISSUER)
        ->subject->toBe('{d301aafa-d676-4ee0-88be-962be7417567}')
        ->email->toBe('taylor@example.com')
        ->emailVerified->toBeTrue()
        ->name->toBe('Taylor Otwell')
        ->and(Keyring::sso()->provider('bitbucket')->freshness())->toBe(SsoFreshness::Never);

    // A primary address Bitbucket hasn't confirmed.
    $api[BitbucketProvider::API.'/user/emails']['values'] = [$address('taylor@example.com', true, false)];
    expect(ssoComplete($approve(ssoStart('bitbucket')), 'bitbucket'))
        ->email->toBe('taylor@example.com')
        ->emailVerified->toBeFalse();

    // A consumer without the email permission.
    $api[BitbucketProvider::API.'/user/emails'] = Http::response(['type' => 'error', 'error' => ['message' => 'Your credentials lack one or more required privilege scopes.']], 403);
    expect(ssoComplete($approve(ssoStart('bitbucket')), 'bitbucket'))
        ->subject->toBe('{d301aafa-d676-4ee0-88be-962be7417567}')
        ->email->toBeNull()
        ->emailVerified->toBeFalse();

    // An API that's down is no sign in, nor one that names no account.
    $api[BitbucketProvider::API.'/user/emails'] = Http::response(null, 503);
    expect(ssoFailure(fn () => ssoComplete($approve(ssoStart('bitbucket')), 'bitbucket'))[0])->toBe(SsoFailure::Unavailable);

    $api[BitbucketProvider::API.'/user'] = Arr::except($user, 'uuid');
    expect(ssoFailure(fn () => ssoComplete($approve(ssoStart('bitbucket')), 'bitbucket'))[0])->toBe(SsoFailure::Unavailable);

    $api[BitbucketProvider::API.'/user'] = fn () => throw new RuntimeException('Connection refused.');
    expect(ssoFailure(fn () => ssoComplete($approve(ssoStart('bitbucket')), 'bitbucket'))[0])->toBe(SsoFailure::Unavailable);
});

it('signs in with the Facebook driver, whose addresses are never verified', function () {
    // "Facebook"
    Keyring::sso()->extend('facebook', fn (array $config, string $name) => new FacebookProvider($name, $config));
    config(['keyring.sso.providers.facebook' => ['driver' => 'facebook', 'client_id' => FakeIdentityProvider::CLIENT_ID, 'client_secret' => FakeIdentityProvider::CLIENT_SECRET]]);

    $me = FacebookProvider::GRAPH.'/me';
    $api = [$me => fn (ClientRequest $request) => $request['fields'] === 'id,name,email' ? Http::response(['id' => '10224873958746201', 'name' => 'Taylor Otwell', 'email' => 'taylor@example.com']) : Http::response(null, 400)];
    $approve = fakeOAuth2Provider(FacebookProvider::GRAPH.'/oauth/access_token', ['access_token' => 'EAAB-facebook-token', 'token_type' => 'bearer', 'expires_in' => 5183944], $api, fn (ClientRequest $request) => ! $request->hasHeader('Authorization') && $request['client_secret'] === FakeIdentityProvider::CLIENT_SECRET);

    $url = ssoStart('facebook');
    expect($url)->toStartWith('https://www.facebook.com/v27.0/dialog/oauth?')
        ->and(authorizationQuery($url)['scope'])->toBe('public_profile email');

    expect(ssoComplete($approve($url), 'facebook'))
        ->issuer->toBe(FacebookProvider::ISSUER)
        ->subject->toBe('10224873958746201')
        ->email->toBe('taylor@example.com')
        ->emailVerified->toBeFalse()
        ->name->toBe('Taylor Otwell');

    // Without the email permission, or a valid address, there's none.
    $api[$me] = ['id' => '10224873958746201', 'name' => 'Taylor Otwell'];
    expect(ssoComplete($approve(ssoStart('facebook')), 'facebook')->email)->toBeNull();

    $api[$me] = Http::response(['error' => ['message' => 'Invalid OAuth access token.', 'type' => 'OAuthException', 'code' => 190]], 400);
    expect(ssoFailure(fn () => ssoComplete($approve(ssoStart('facebook')), 'facebook'))[0])->toBe(SsoFailure::Unavailable);

    $api[$me] = ['name' => 'Taylor Otwell'];
    expect(ssoFailure(fn () => ssoComplete($approve(ssoStart('facebook')), 'facebook'))[0])->toBe(SsoFailure::Unavailable);
});

it('signs in with the LinkedIn driver, from its userinfo endpoint', function () {
    // "LinkedIn"
    Keyring::sso()->extend('linkedin', fn (array $config, string $name) => new LinkedInProvider($name, $config));
    config(['keyring.sso.providers.linkedin' => ['driver' => 'linkedin', 'client_id' => FakeIdentityProvider::CLIENT_ID, 'client_secret' => FakeIdentityProvider::CLIENT_SECRET]]);

    // LinkedIn's sample userinfo response.
    $member = ['sub' => '782bbtaQ', 'name' => 'John Doe', 'given_name' => 'John', 'family_name' => 'Doe', 'picture' => 'https://media.licdn-ei.com/dms/image/C5F03AQHqK8v7tB1HCQ/profile-displayphoto-shrink_100_100/0/', 'locale' => 'en-US', 'email' => 'doe@email.com', 'email_verified' => true];
    $api = ['https://api.linkedin.com/v2/userinfo' => $member];
    $approve = fakeOAuth2Provider('https://www.linkedin.com/oauth/v2/accessToken', ['access_token' => 'AQUvlL_DYEzvT2wz1QJiEPeLioeA', 'expires_in' => 5184000, 'scope' => 'email,openid,profile', 'token_type' => 'Bearer', 'id_token' => 'not.read.here'], $api, fn (ClientRequest $request) => $request['client_id'] === FakeIdentityProvider::CLIENT_ID && $request['client_secret'] === FakeIdentityProvider::CLIENT_SECRET);

    $url = ssoStart('linkedin');
    expect($url)->toStartWith('https://www.linkedin.com/oauth/v2/authorization?')
        ->and(authorizationQuery($url))->toMatchArray(['scope' => 'openid profile email'])->not->toHaveKey('nonce');

    expect(ssoComplete($approve($url), 'linkedin'))
        ->issuer->toBe('https://www.linkedin.com/oauth')
        ->subject->toBe('782bbtaQ')
        ->email->toBe('doe@email.com')
        ->emailVerified->toBeTrue()
        ->name->toBe('John Doe');

    // email and email_verified are optional.
    $api['https://api.linkedin.com/v2/userinfo'] = Arr::except($member, 'email_verified');
    expect(ssoComplete($approve(ssoStart('linkedin')), 'linkedin')->emailVerified)->toBeFalse();

    $api['https://api.linkedin.com/v2/userinfo'] = Arr::except($member, ['email', 'email_verified']);
    expect(ssoComplete($approve(ssoStart('linkedin')), 'linkedin'))->email->toBeNull()->emailVerified->toBeFalse();

    $api['https://api.linkedin.com/v2/userinfo'] = Arr::except($member, 'sub');
    expect(ssoFailure(fn () => ssoComplete($approve(ssoStart('linkedin')), 'linkedin'))[0])->toBe(SsoFailure::Unavailable);

    $api['https://api.linkedin.com/v2/userinfo'] = Http::response(['serviceErrorCode' => 65600, 'message' => 'Invalid access token', 'status' => 401], 401);
    expect(ssoFailure(fn () => ssoComplete($approve(ssoStart('linkedin')), 'linkedin'))[0])->toBe(SsoFailure::Unavailable);
});
