<?php

declare(strict_types=1);

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\RateLimiter as Limiter;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Foundation\Auth\User;
use Illuminate\Routing\RouteCollection;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Route;
use Inertia\ServiceProvider;
use Keyring\Changes\ProtectedAttributes;
use Keyring\Enrollment\EnrollmentStore;
use Keyring\Enums\Purpose;
use Keyring\Exceptions\MissingPage;
use Keyring\Exceptions\MissingTrait;
use Keyring\Exceptions\UnknownFeature;
use Keyring\Facades\Keyring;
use Keyring\Factors\EmailCode;
use Keyring\Factors\FactorRegistry;
use Keyring\Factors\Password;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\Features;
use Keyring\KeyringManager;
use Keyring\KeyringServiceProvider;
use Keyring\Login\AttemptStore;
use Keyring\Pipeline\Context;
use Keyring\Risk\RiskEngine;
use Keyring\Sessions\SessionAssurance;
use Keyring\Sessions\SessionRegistryManager;
use Keyring\Support\EncryptedSession;
use Keyring\WebAuthn\Ceremonies;
use Keyring\WebAuthn\SpentChallenges;

it('lets apps register the routes themselves, e.g. under a prefix', function () {
    Route::prefix('account')->group(fn () => Keyring::routes());

    $this->inertia()->get('/account/login')->assertOk()->assertJsonPath('component', 'auth/login');
});

it('takes the session lock on routes that spend session state', function (string $name) {
    expect(Route::getRoutes()->getByName($name)->locksFor())->toBeGreaterThan(0);
})->with([
    'login.store', 'keyring.login.factor', 'keyring.login.challenge', 'keyring.login.verify', 'keyring.login.send',
    'keyring.confirm.challenge', 'keyring.confirm.verify', 'keyring.confirm.send', 'keyring.authenticators.confirm',
]);

it('limits routes that check a secret outside the sign in limits', function (string $name) {
    expect(Route::getRoutes()->getByName($name)->gatherMiddleware())->toContain('throttle:keyring');
})->with([
    'register.store', 'password.email', 'password.update', 'user-password.update',
    'keyring.authenticators.confirm', 'keyring.authenticators.destroy', 'keyring.email.store', 'keyring.email.revert.store',
]);

it('keeps one of each service for the app\'s lifetime, or the request\'s', function (string $service, bool $perRequest) {
    $first = app($service);

    expect(app($service))->toBe($first);

    app()->forgetScopedInstances();

    $perRequest
        ? expect(app($service))->not->toBe($first)
        : expect(app($service))->toBe($first);
})->with([
    [KeyringManager::class, false],
    [FactorRegistry::class, false],
    [ProtectedAttributes::class, false],
    [Ceremonies::class, false],
    [SessionRegistryManager::class, false],
    [RiskEngine::class, false],
    [AttemptStore::class, true],
    [EnrollmentStore::class, true],
    [SessionAssurance::class, true],
    [EncryptedSession::class, true],
]);

it('keeps a service the app replaced for as long as its own', function () {
    $replacement = new class(app(FactorRegistry::class), app(ProtectedAttributes::class)) extends KeyringManager {};

    app()->bind(KeyringManager::class, $replacement::class);

    expect(app(KeyringManager::class))->toBeInstanceOf($replacement::class)->toBe(app(KeyringManager::class));
});

it('says which guard has no user provider', function () {
    config(['keyring.guard' => 'api']);

    expect(fn () => Keyring::provider())->toThrow(InvalidArgumentException::class, "Keyring's guard [api] has no user provider.");
});

it('tells a step that needs the attempt to run after the one that starts it', function () {
    $context = new Context(request(), Purpose::Login, Keyring::factor('password'));

    expect(fn () => $context->attempt())->toThrow(LogicException::class, 'has to run after VerifyFactor')
        ->and(fn () => $context->authenticator())->toThrow(LogicException::class, 'has to run after VerifyFactor');
});

it('registers custom factors with extend, under the key they report', function () {
    Keyring::extend('totp', fn ($app) => $app->make(Totp::class));
    expect(Keyring::factor('totp'))->toBeInstanceOf(Totp::class);

    Keyring::extend('sms', fn ($app) => $app->make(Totp::class));
    expect(fn () => Keyring::registered())->toThrow(InvalidArgumentException::class, 'Factor registered as [sms] reports the key [totp].');
});

it('says which blade view a page needs and what it receives', function () {
    expect(MissingPage::forBlade('login', 'auth.login', ['canResetPassword', 'status'])->getMessage())
        ->toContain('resources/views/auth/login.blade.php')
        ->toContain('$canResetPassword, $status')
        ->toContain("Keyring::page('login', ...)");
});

it('says which inertia component a page needs when inertia checks that pages exist', function () {
    $this->app->register(ServiceProvider::class);
    config(['inertia.pages.ensure_pages_exist' => true]);

    $this->withoutExceptionHandling()->inertia()->get('/login');
})->throws(MissingPage::class, 'Create [auth/login] in your pages directory (it receives canResetPassword');

it('says which trait a user model is missing', function () {
    Keyring::for(new class extends User {});
})->throws(MissingTrait::class, 'needs the [Keyring\\Concerns\\HasKeyring] trait');

it('merges the app\'s config over its defaults key by key, but replaces lists whole', function () {
    config(['keyring' => ['sessions' => ['absolute' => '7d', 'levels' => ['aal2' => ['idle' => '30m']]], 'features' => [Features::devices()]]]);

    new KeyringServiceProvider($this->app)->register();

    expect(config('keyring.sessions.absolute'))->toBe('7d')
        ->and(config('keyring.sessions.middleware'))->toBeTrue()
        ->and(config('keyring.sessions.levels.aal2'))->toBe(['idle' => '30m', 'absolute' => '24h'])
        ->and(config('keyring.sessions.levels.aal3'))->toBe(['idle' => '15m', 'absolute' => '12h'])
        ->and(config('keyring.features'))->toBe([Features::devices()])
        ->and(config('keyring.limits.per_ip'))->toBe(20);
});

it('leaves a cached config as config:cache saved it, already merged', function () {
    $this->app->instance('config_loaded_from_cache', true);
    config(['keyring' => ['sessions' => ['absolute' => '7d']]]);

    new KeyringServiceProvider($this->app)->register();

    expect(config('keyring'))->toBe(['sessions' => ['absolute' => '7d']]);
});

it('leaves its routes to the route cache once routes are cached', function () {
    $this->app->instance('routes.cached', true);
    Route::setRoutes(new RouteCollection);

    new KeyringServiceProvider($this->app)->boot();

    expect(Route::has('login'))->toBeFalse()
        ->and(Route::getRoutes()->count())->toBe(0);
});

it('refuses a feature it doesn\'t know, rather than leaving it off', function () {
    config(['keyring.features' => [Features::registration(), 'device']]);

    new KeyringServiceProvider($this->app)->boot();
})->throws(UnknownFeature::class, 'Unknown Keyring features in config/keyring.php: [device]');

it('refuses an impersonation.lifetime that isn\'t a duration at boot, with the feature on', function (mixed $lifetime) {
    config(['keyring.features' => [Features::impersonation()], 'keyring.impersonation.lifetime' => $lifetime]);

    expect(fn () => new KeyringServiceProvider($this->app)->boot())
        ->toThrow(InvalidArgumentException::class, 'Keyring\'s [keyring.impersonation.lifetime] option is '.json_encode($lifetime).'.');
})->with(['a typo' => ['1 hour'], 'nothing' => ['0'], 'not text' => [[3600]]]);

it('takes any duration for impersonation.lifetime, or null for an hour, and doesn\'t look with the feature off', function () {
    foreach (['30m', 3600, '90', null] as $lifetime) {
        config(['keyring.features' => [Features::impersonation()], 'keyring.impersonation.lifetime' => $lifetime]);

        expect(fn () => new KeyringServiceProvider($this->app)->boot())->not->toThrow(InvalidArgumentException::class);
    }

    config(['keyring.features' => [], 'keyring.impersonation.lifetime' => 'forever']);

    expect(fn () => new KeyringServiceProvider($this->app)->boot())->not->toThrow(InvalidArgumentException::class);
});

/**
 * The app as it is before anything has asked for the rate limiter, kept in
 * a cache store that only exists once another package has booted: Octane
 * adds its "octane" store when its provider boots, which is after Keyring's.
 */
function withALateCacheStoreForRateLimits(): void
{
    config(['cache.stores.late' => ['driver' => 'late'], 'cache.limiter' => 'late']);

    unset(app()[Limiter::class]);
    app()->singleton(Limiter::class, fn () => new Limiter(Cache::driver(config('cache.limiter'))));
    RateLimiter::clearResolvedInstance(Limiter::class);
}

it('boots before the cache store its rate limits are kept in is registered', function () {
    withALateCacheStoreForRateLimits();

    new KeyringServiceProvider($this->app)->boot();

    Cache::extend('late', fn () => Cache::repository(new ArrayStore));

    expect(RateLimiter::limiter('keyring')(request())->maxAttempts)->toBe(6)
        ->and(RateLimiter::limiter('keyring-pages')(request())->maxAttempts)->toBe(60)
        ->and(RateLimiter::limiter('keyring-login-options')(request())->maxAttempts)->toBe(60);
});

it('keeps a rate limiter the app defines in place of its own', function () {
    withALateCacheStoreForRateLimits();

    new KeyringServiceProvider($this->app)->boot();

    Cache::extend('late', fn () => Cache::repository(new ArrayStore));
    RateLimiter::for('keyring', fn () => Limit::perMinute(10));

    expect(RateLimiter::limiter('keyring')(request())->maxAttempts)->toBe(10);
});

it('registers a factor that sends codes before the cache store its codes are kept in exists', function () {
    withALateCacheStoreForRateLimits();

    Keyring::factors([Password::class, EmailCode::asExtraStep()]);

    expect(Keyring::registered()->keys()->all())->toBe(['password', 'email-code']);
});

it('registers passkeys before the cache store their answered challenges are kept in exists', function () {
    withALateCacheStoreForRateLimits();

    Keyring::factors([Password::class, WebAuthn::passkeys(), WebAuthn::securityKeys()]);

    expect(Keyring::registered()->keys()->all())->toBe(['password', 'passkey', 'security-key']);

    // Nothing asks for the store until a challenge is answered.
    app(SpentChallenges::class);

    Cache::extend('late', fn () => Cache::repository(new ArrayStore));

    expect(app(SpentChallenges::class)->spend('{"challenge":"once"}', now()->addMinute()->getTimestamp()))->toBeTrue()
        ->and(app(SpentChallenges::class)->spend('{"challenge":"once"}', now()->addMinute()->getTimestamp()))->toBeFalse();
});
