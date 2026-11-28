<?php

declare(strict_types=1);

use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Auth\Events\Authenticated as LaravelAuthenticated;
use Illuminate\Auth\Events\Login;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Middleware\AuthenticateSession as LaravelAuthenticateSession;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\URL;
use Illuminate\Testing\TestResponse;
use Keyring\Activity\SecurityLog;
use Keyring\Changes\PasswordHolds;
use Keyring\Contracts\Responses\SignedOutResponse;
use Keyring\Contracts\SessionRegistry;
use Keyring\Enums\Assurance;
use Keyring\Enums\Category;
use Keyring\Enums\ImpersonationEndReason;
use Keyring\Enums\ImpersonationRefusal;
use Keyring\Enums\SessionEndReason;
use Keyring\Events\Authenticated;
use Keyring\Events\ImpersonationEnded;
use Keyring\Events\ImpersonationStarted;
use Keyring\Events\NewDeviceSignedIn;
use Keyring\Events\RegisteredSessionEnded;
use Keyring\Exceptions\ImpersonationRefused;
use Keyring\Facades\Keyring;
use Keyring\Features;
use Keyring\Http\Middleware\AuthenticateSession;
use Keyring\Impersonation\Impersonation;
use Keyring\KeyringManager;
use Keyring\Login\SignIn;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;
use Keyring\Models\SecurityEvent;
use Keyring\Sessions\DatabaseSessionRegistry;
use Keyring\Sessions\RegisteredSession;
use Keyring\Sessions\SessionAssurance;
use Keyring\Sessions\SessionRegistryManager;
use Keyring\Sessions\Sessions;
use Keyring\Sessions\Sweep;
use Keyring\Tests\Fixtures\PlainFormRequest;
use Keyring\Tests\Fixtures\User;
use Monolog\Handler\AbstractProcessingHandler;
use Monolog\Logger;
use Monolog\LogRecord;

beforeEach(function () {
    Route::middleware(['web', 'auth'])->get('/whoami', fn () => (string) Auth::id());
    Route::middleware('web')->get('/welcome', fn () => Auth::check() ? (string) Auth::id() : 'guest');
    Route::middleware(['web', 'auth', 'keyring:aal2'])->get('/billing', fn () => 'billing');
    Route::middleware(['web', 'auth', 'keyring.not-impersonating'])->delete('/account', fn () => 'deleted');

    $this->admin = taylor(['name' => 'Ada Admin', 'email' => 'admin@example.com']);
    $this->totp = Authenticator::factory()->totp()->for($this->admin, 'authenticatable')->create();
    $this->user = User::create(['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => 'password', 'email_verified_at' => now()]);

    Keyring::allowImpersonationWhen(fn (User $impersonator, User $user) => $impersonator->is($this->admin));
});

/**
 * The admin signs in with their password and authenticator app, so their
 * session has just proved two factors.
 */
function adminSignsIn(bool $remember = false): void
{
    test()->post('/login', ['email' => 'admin@example.com', 'password' => 'password', 'remember' => $remember]);
    test()->post(route('keyring.login.verify', 'totp'), ['code' => totpCode(test()->totp->secret)])->assertRedirect('/dashboard');
}

function impersonate(Model $user, bool $json = false): TestResponse
{
    $url = route('keyring.impersonation.store', $user->getKey());

    return $json ? test()->postJson($url) : test()->post($url);
}

function stopImpersonating(bool $json = false): TestResponse
{
    return $json ? test()->deleteJson(route('keyring.impersonation.destroy')) : test()->delete(route('keyring.impersonation.destroy'));
}

/**
 * The admin, signed in, impersonating the user. Returns the registry ID of
 * the admin's own session.
 */
function impersonating(): string
{
    adminSignsIn();
    $own = session(Sessions::KEY);

    impersonate(test()->user)->assertRedirect('/dashboard');

    return $own;
}

/**
 * A user provider whose database refuses any ID that isn't digits, with
 * this SQLSTATE, as PostgreSQL refuses "abc" for an integer key.
 */
function pickyProvider(string $state, string $message): void
{
    Auth::provider('picky', fn ($app, array $config) => new class($app['hash'], $config['model'], $state, $message) extends EloquentUserProvider
    {
        public function __construct($hasher, $model, protected string $state, protected string $message)
        {
            parent::__construct($hasher, $model);
        }

        public function retrieveById($identifier)
        {
            if (ctype_digit((string) $identifier)) {
                return parent::retrieveById($identifier);
            }

            $error = new PDOException($this->message);
            $error->errorInfo = [$this->state, 7, $this->message];

            throw new QueryException('pgsql', 'select * from "users" where "id" = ?', [$identifier], $error);
        }
    });
    config(['auth.providers.users.driver' => 'picky']);
}

function record(string $id): ?RegisteredSession
{
    return app(SessionRegistry::class)->find($id);
}

/**
 * Why starting was refused, or null when it wasn't.
 */
function refusal(Closure $callback): ?ImpersonationRefusal
{
    try {
        $callback();
    } catch (ImpersonationRefused $e) {
        return $e->reason;
    }

    return null;
}

/**
 * A session registry whose $method lets the first $works calls through and
 * throws on the $fails after them (every one, without $fails), as a
 * database that went away.
 */
function registryThatGoesAway(int $works, string $method = 'revoke', int $fails = PHP_INT_MAX): void
{
    $calls = new ArrayObject;

    app(SessionRegistryManager::class)->extend('failing', fn () => new class(app('db')->connection(), $calls, $works, $method, $fails) extends DatabaseSessionRegistry
    {
        public function __construct(ConnectionInterface $connection, protected ArrayObject $calls, protected int $works, protected string $method, protected int $fails)
        {
            parent::__construct($connection);
        }

        public function revoke(string $id): ?RegisteredSession
        {
            $this->call('revoke');

            return parent::revoke($id);
        }

        public function replace(string $id, RegisteredSession $successor, bool $revoke = false): bool
        {
            $this->call('replace');

            return parent::replace($id, $successor, $revoke);
        }

        protected function call(string $method): void
        {
            if ($method !== $this->method) {
                return;
            }

            $this->calls->append($method);

            if (count($this->calls) > $this->works && count($this->calls) - $this->works <= $this->fails) {
                throw new RuntimeException('The database went away.');
            }
        }
    });
    config(['keyring.sessions.driver' => 'failing']);
}

/**
 * A session registry that hands back these records as they were, as a
 * request that read them a moment before another request changed them,
 * until it moves one itself and so reads them as they are.
 *
 * @param  array<string, RegisteredSession>  $records
 */
function registryReadingEarlier(array $records): void
{
    $earlier = new ArrayObject($records);

    app(SessionRegistryManager::class)->extend('earlier', fn () => new class(app('db')->connection(), $earlier) extends DatabaseSessionRegistry
    {
        public function __construct(ConnectionInterface $connection, protected ArrayObject $earlier)
        {
            parent::__construct($connection);
        }

        public function find(string $id): ?RegisteredSession
        {
            return $this->earlier[$id] ?? parent::find($id);
        }

        public function replace(string $id, RegisteredSession $successor, bool $revoke = false): bool
        {
            $this->earlier->exchangeArray([]);

            return parent::replace($id, $successor, $revoke);
        }
    });
    config(['keyring.sessions.driver' => 'earlier']);
}

/**
 * The ImpersonationEnded events dispatched from now on, as they're
 * dispatched: faking them would keep the security log from writing them.
 */
function impersonationsEnded(): ArrayObject
{
    $ended = new ArrayObject;

    Event::listen(fn (ImpersonationEnded $event) => $ended->append($event));

    return $ended;
}

/**
 * Run Laravel's auth.session middleware on the web group, ahead of
 * Keyring's session middleware, as an app that uses it would.
 */
function withLaravelsAuthSession(): void
{
    app('router')->pushMiddlewareToGroup('web', LaravelAuthenticateSession::class);
    app('router')->removeMiddlewareFromGroup('web', AuthenticateSession::class);
    app('router')->pushMiddlewareToGroup('web', AuthenticateSession::class);
}

/**
 * Keep the session on Laravel's cookie driver, which lives in the browser.
 */
function onTheCookieDriver(): void
{
    config(['session.driver' => 'cookie']);
    app('session')->forgetDrivers();
    app()->forgetInstance('session.store');
}

/**
 * The cookies a cookie session is in, after a response: its ID, and the
 * session itself under that name.
 *
 * @return array<string, string>
 */
function cookiesOf(TestResponse $response): array
{
    $id = $response->getCookie(config('session.cookie'))->getValue();

    return [config('session.cookie') => $id, $id => $response->getCookie($id)->getValue()];
}

describe('who may impersonate', function () {
    it('signs in as the user once the callback says so', function () {
        adminSignsIn();

        impersonate($this->user)->assertRedirect('/dashboard')->assertSessionHas('status', 'impersonation-started');

        expect($this->get('/whoami')->getContent())->toBe((string) $this->user->getKey())
            ->and(Keyring::impersonating())->toBeTrue()
            ->and(Keyring::impersonator()->is($this->admin))->toBeTrue();
    });

    it('refuses everyone until the app says who may, as no_callback rather than not_allowed', function () {
        (fn () => $this->impersonationGate = null)->call(app(KeyringManager::class));
        adminSignsIn();

        impersonate($this->user, json: true)->assertForbidden()->assertExactJson(['status' => 'impersonation-refused', 'message' => Keyring::statusMessage('impersonation-refused')]);

        expect($this->get('/whoami')->getContent())->toBe((string) $this->admin->getKey())
            ->and(Keyring::allowsImpersonation($this->admin, $this->user))->toBeFalse()
            ->and(Keyring::impersonationRefusal($this->admin, $this->user))->toBe(ImpersonationRefusal::NoCallback)
            ->and(refusal(fn () => Keyring::impersonate(request(), $this->user)))->toBe(ImpersonationRefusal::NoCallback)
            ->and(SecurityEvent::query()->where('type', 'impersonation_refused')->pluck('meta')->pluck('reason')->all())->toBe(['no_callback', 'no_callback']);
    });

    // The answer can't say it, so the log does, for the developer.
    it('warns in the log, once a request, when a refusal is for impersonation not being set up', function () {
        (fn () => $this->impersonationGate = null)->call(app(KeyringManager::class));
        adminSignsIn();
        Log::spy();

        impersonate($this->user)->assertForbidden();

        Log::shouldHaveReceived('warning')->once()->withArgs(fn (string $message) => str_contains($message, 'Keyring::allowImpersonationWhen() was never called'));

        // The same request again.
        refusal(fn () => Keyring::impersonate(request(), $this->user));
        refusal(fn () => Keyring::impersonate(request(), $this->user));

        Log::shouldHaveReceived('warning')->once();

        // A route of the app's own, with the feature off.
        withFeatures(array_values(array_diff(Features::all(), [Features::impersonation()])));
        Route::middleware(['web', 'auth'])->post('/become/{id}', fn (Request $request, string $id) => refusal(fn () => Keyring::impersonate($request, User::findOrFail($id)))?->value);

        expect($this->post('/become/'.$this->user->getKey())->getContent())->toBe('disabled');

        Log::shouldHaveReceived('warning')->twice();
        Log::shouldHaveReceived('warning')->withArgs(fn (string $message) => str_contains($message, 'Features::impersonation() is not in the features'));
    });

    it('doesn\'t warn when the callback turns the impersonator down', function () {
        Keyring::allowImpersonationWhen(fn () => false);
        adminSignsIn();
        Log::spy();

        impersonate($this->user)->assertForbidden();
        impersonate($this->admin)->assertForbidden();

        Log::shouldNotHaveReceived('warning');
    });

    it('refuses whoever the callback turns down, and asks it with the impersonator and the user', function () {
        $asked = [];
        Keyring::allowImpersonationWhen(function (User $impersonator, User $user) use (&$asked) {
            $asked = [$impersonator->getKey(), $user->getKey()];

            return false;
        });
        adminSignsIn();

        impersonate($this->user, json: true)->assertForbidden()->assertExactJson(['status' => 'impersonation-refused', 'message' => Keyring::statusMessage('impersonation-refused')]);

        expect($asked)->toBe([$this->admin->getKey(), $this->user->getKey()])
            ->and(Keyring::impersonationRefusal($this->admin, $this->user))->toBe(ImpersonationRefusal::NotAllowed)
            ->and(refusal(fn () => Keyring::impersonate(request(), $this->user)))->toBe(ImpersonationRefusal::NotAllowed);
    });

    // Nothing is stuck yet, so it's an error like any other.
    it('throws on what the callback throws before starting, starting nothing', function () {
        Keyring::allowImpersonationWhen(fn () => throw new RuntimeException('The roles service is down.'));
        adminSignsIn();

        $this->withoutExceptionHandling();

        expect(fn () => impersonate($this->user))->toThrow(RuntimeException::class, 'The roles service is down.')
            ->and(fn () => Keyring::allowsImpersonation($this->admin, $this->user))->toThrow(RuntimeException::class)
            ->and(Keyring::impersonating())->toBeFalse()
            ->and(Auth::id())->toBe($this->admin->getKey())
            ->and(SecurityEvent::query()->where('type', 'impersonation_started')->count())->toBe(0);
    });

    it('only counts a callback that answers true', function () {
        Keyring::allowImpersonationWhen(fn () => 1);

        expect(Keyring::allowsImpersonation($this->admin, $this->user))->toBeFalse()
            ->and(Keyring::impersonationRefusal($this->admin, $this->user))->toBe(ImpersonationRefusal::NotAllowed);

        Keyring::allowImpersonationWhen(fn () => true);

        expect(Keyring::allowsImpersonation($this->admin, $this->user))->toBeTrue()
            ->and(Keyring::impersonationRefusal($this->admin, $this->user))->toBeNull();
    });

    it('has no routes, and refuses in code, with the feature off', function () {
        withFeatures(array_values(array_diff(Features::all(), [Features::impersonation()])));
        adminSignsIn();

        $this->post('/impersonate/'.$this->user->getKey())->assertNotFound();

        expect(Route::has('keyring.impersonation.store'))->toBeFalse()
            ->and(Route::has('keyring.impersonation.destroy'))->toBeFalse()
            ->and(Keyring::allowsImpersonation($this->admin, $this->user))->toBeFalse()
            ->and(Keyring::impersonationRefusal($this->admin, $this->user))->toBe(ImpersonationRefusal::Disabled)
            ->and(refusal(fn () => Keyring::impersonate(request(), $this->user)))->toBe(ImpersonationRefusal::Disabled);
    });

    it('refuses impersonating yourself', function () {
        Keyring::allowImpersonationWhen(fn () => true);
        adminSignsIn();

        impersonate($this->admin)->assertForbidden();

        expect(refusal(fn () => Keyring::impersonate(request(), $this->admin)))->toBe(ImpersonationRefusal::Self)
            ->and(Keyring::impersonationRefusal($this->admin, $this->admin))->toBe(ImpersonationRefusal::Self);
    });

    it('refuses a user the app does not let sign in', function () {
        Keyring::allowSignInWhen(fn (User $user) => ! $user->is($this->user));
        adminSignsIn();

        impersonate($this->user)->assertForbidden();

        expect(Keyring::impersonationRefusal($this->admin, $this->user))->toBe(ImpersonationRefusal::NotAllowed);
    });

    it('refuses an ID nobody has as it refuses one it may not impersonate', function () {
        adminSignsIn();

        impersonate(new User(['id' => 999]), json: true)->assertForbidden()->assertExactJson(['status' => 'impersonation-refused', 'message' => Keyring::statusMessage('impersonation-refused')]);
    });

    // As Keyring's other 403s: the status for JSON clients, and Laravel's
    // 403 for a page visit or an Inertia one, the same whatever the reason.
    it('answers a refusal with the impersonation-refused status for json clients, and a 403 for pages and inertia', function () {
        Keyring::allowImpersonationWhen(fn () => false);
        adminSignsIn();

        impersonate($this->user, json: true)->assertForbidden()->assertExactJson(['status' => 'impersonation-refused', 'message' => 'You can\'t sign in as that user.']);
        impersonate($this->user)->assertForbidden()->assertSee('You can\'t sign in as that user.');
        $this->post(route('keyring.impersonation.store', $this->user->getKey()), headers: ['X-Inertia' => 'true', 'X-Requested-With' => 'XMLHttpRequest', 'Accept' => 'text/html, application/xhtml+xml'])
            ->assertForbidden()
            ->assertHeaderMissing('X-Inertia-Location');

        expect($this->get('/whoami')->getContent())->toBe((string) $this->admin->getKey())
            ->and(new ImpersonationRefused(ImpersonationRefusal::NoCallback)->render(Request::create('/', server: ['HTTP_ACCEPT' => 'application/json']))->getData(true))
            ->toBe(new ImpersonationRefused(ImpersonationRefusal::Self)->render(Request::create('/', server: ['HTTP_ACCEPT' => 'application/json']))->getData(true));
    });

    // PostgreSQL won't compare "abc" with an integer key, and says so.
    it('refuses an ID the database won\'t look up as it refuses one nobody has, logging it as not_found', function () {
        pickyProvider('22P02', 'invalid input syntax for type bigint');
        Keyring::allowImpersonationWhen(fn () => false);
        adminSignsIn();

        $unknown = $this->postJson(route('keyring.impersonation.store', 'abc'))->assertForbidden();
        $refused = impersonate($this->user, json: true)->assertForbidden();

        expect($unknown->getContent())->toBe($refused->getContent())
            ->and(Auth::id())->toBe($this->admin->getKey())
            ->and(SecurityEvent::query()->where('type', 'impersonation_refused')->oldest('id')->get()->pluck('meta')->all())->toBe([
                ['reason' => 'not_found', 'user' => 'abc'],
                ['reason' => 'not_allowed', 'user' => (string) $this->user->getKey()],
            ]);
    });

    // Only data the column won't take is an ID nobody has. A database that
    // fails for any other reason fails the start.
    it('throws on any other error looking the user up', function (string $state) {
        pickyProvider($state, 'the database went away');
        adminSignsIn();
        $this->withoutExceptionHandling();

        expect(fn () => $this->postJson(route('keyring.impersonation.store', 'abc')))->toThrow(QueryException::class, 'the database went away')
            ->and(SecurityEvent::query()->where('type', 'impersonation_refused')->count())->toBe(0);
    })->with(['a deadlock' => ['40P01'], 'a dropped connection' => ['08006']]);

    it('refuses an account of another model, which the guard would not load', function () {
        Keyring::allowImpersonationWhen(fn () => true);

        $staff = staff();

        expect(Keyring::allowsImpersonation($this->admin, $staff))->toBeFalse()
            ->and(Keyring::impersonationRefusal($this->admin, $staff))->toBe(ImpersonationRefusal::NotAllowed)
            ->and(Keyring::impersonationRefusal($staff, $this->user))->toBe(ImpersonationRefusal::NotAllowed);
    });

    it('refuses a session keyring has no record of, which there would be no coming back to', function () {
        Route::middleware(['web', 'auth'])->post('/become/{id}', function (Request $request, string $id) {
            $request->session()->forget(Sessions::KEY);

            try {
                Keyring::impersonate($request, User::findOrFail($id));
            } catch (ImpersonationRefused $e) {
                return $e->reason->value;
            }
        });
        adminSignsIn();

        expect($this->post('/become/'.$this->user->getKey())->getContent())->toBe('unregistered');
    });
});

describe('starting', function () {
    it('needs two factors proved in the last 15 minutes', function () {
        adminSignsIn();
        $this->travel(16)->minutes();

        impersonate($this->user)->assertRedirect(route('keyring.confirm.challenge'));

        expect(Keyring::impersonating())->toBeFalse();
    });

    it('needs a second factor, whatever the password proved', function () {
        $this->totp->delete();
        $this->post('/login', ['email' => 'admin@example.com', 'password' => 'password']);

        impersonate($this->user, json: true)->assertForbidden()->assertJson(['status' => 'enroll-first']);

        expect(Keyring::impersonating())->toBeFalse();
    });

    it('is only a POST', function () {
        adminSignsIn();

        $this->get('/impersonate/'.$this->user->getKey())->assertMethodNotAllowed();

        expect(Keyring::impersonating())->toBeFalse();
    });

    it('is one at a time', function () {
        $other = User::create(['name' => 'Other', 'email' => 'other@example.com', 'password' => 'password', 'email_verified_at' => now()]);
        impersonating();

        impersonate($other, json: true)->assertForbidden()->assertJson(['status' => 'impersonating']);

        expect(refusal(fn () => Keyring::impersonate(request(), $other)))->toBe(ImpersonationRefusal::Impersonating)
            ->and($this->get('/whoami')->getContent())->toBe((string) $this->user->getKey());
    });

    it('gives the browser a new session id, and the user a session record of their own', function () {
        adminSignsIn();
        $before = session()->getId();
        $own = session(Sessions::KEY);

        impersonate($this->user);
        $record = record(session(Sessions::KEY));

        expect(session()->getId())->not->toBe($before)
            ->and($record->belongsTo($this->user))->toBeTrue()
            ->and($record->isImpersonated())->toBeTrue()
            ->and($record->impersonatorId)->toBe((string) $this->admin->getKey())
            ->and($record->impersonatorType)->toBe(RegisteredSession::typeOf($this->admin))
            ->and($record->impersonatorSession)->toBe($own)
            ->and($record->remembered)->toBeFalse()
            ->and($record->deviceId)->toBeNull()
            // The admin's, so the user's record doesn't keep them.
            ->and($record->ip)->toBeNull()
            ->and($record->userAgent)->toBeNull()
            ->and($record->expiresAt)->toBe(now()->addHour()->getTimestamp())
            // The admin's own session is parked, not ended.
            ->and(record($own)->isActive(now()->getTimestamp()))->toBeTrue();
    });

    it('is not the user signing in: no sign in events, no new device, no emails', function () {
        adminSignsIn();
        Event::fake([Login::class, Authenticated::class, NewDeviceSignedIn::class]);
        Notification::fake();

        impersonate($this->user);

        Event::assertNotDispatched(Login::class);
        Event::assertNotDispatched(Authenticated::class);
        Event::assertNotDispatched(NewDeviceSignedIn::class);
        Notification::assertNothingSent();
        expect(SecurityEvent::query()->whereMorphedTo('authenticatable', $this->user)->pluck('type')->all())->toBe(['impersonation_started']);
    });

    it('carries nothing the admin proved over to the user', function () {
        adminSignsIn();
        session()->put('auth.password_confirmed_at', now()->getTimestamp());

        impersonate($this->user);

        expect(session(SessionAssurance::KEY))->toBeNull()
            ->and(session('auth.password_confirmed_at'))->toBeNull()
            ->and(app(SessionAssurance::class)->level()->name)->toBe('None')
            ->and(record(session(Sessions::KEY))->assurance->name)->toBe('None');
    });

    // Laravel's auth.session middleware keeps the signed-in user's password
    // hash in the session, and signs out a session whose hash no longer
    // matches. The admin's isn't carried over to be compared with the user's.
    it('keeps the user signed in through laravel\'s auth.session middleware, and the admin after', function () {
        Route::middleware(['web', 'auth', LaravelAuthenticateSession::class])->get('/checked', fn () => (string) Auth::id());
        adminSignsIn();
        $this->get('/checked');

        impersonate($this->user);

        expect($this->get('/checked')->assertOk()->getContent())->toBe((string) $this->user->getKey());

        stopImpersonating();

        expect($this->get('/checked')->assertOk()->getContent())->toBe((string) $this->admin->getKey());
    });

    it('can\'t prove anything as the user', function () {
        impersonating();

        $this->get('/billing')->assertForbidden();
        $this->getJson('/billing')->assertForbidden()->assertJson(['status' => 'impersonating', 'message' => Keyring::statusMessage('impersonating')]);
        $this->get(route('keyring.confirm.challenge'))->assertForbidden();
        $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password'])->assertForbidden();
    });

    it('answers json clients with its status and where to go', function () {
        adminSignsIn();

        impersonate($this->user, json: true)->assertOk()->assertJson([
            'status' => 'impersonation-started',
            'message' => Keyring::statusMessage('impersonation-started'),
            'redirect' => url('/dashboard'),
        ])->assertHeader('Clear-Site-Data', '"cache", "storage"');
    });

    it('goes to impersonation.redirect_url', function () {
        config(['keyring.impersonation.redirect_url' => '/support/view']);
        adminSignsIn();

        impersonate($this->user)->assertRedirect('/support/view');
    });

    it('lasts no longer than the session could, and says so to the banner', function () {
        $this->freezeSecond();
        config(['keyring.impersonation.lifetime' => '90d']);
        adminSignsIn();

        impersonate($this->user);

        expect(record(session(Sessions::KEY))->expiresAt)->toBe(now()->addDays(30)->getTimestamp())
            ->and(session(Impersonation::KEY)['expires_at'])->toBe(now()->addDays(30)->getTimestamp())
            ->and(Keyring::impersonation()['expiresAt'])->toBe(now()->addDays(30)->toIso8601String());
    });
});

describe('laravel\'s intended url', function () {
    it('is forgotten when the browser changes hands, either way', function () {
        Route::middleware(['web', 'auth'])->get('/intend', function (Request $request) {
            redirect()->setIntendedUrl('/somewhere-'.Auth::id());

            return 'noted';
        });
        adminSignsIn();
        $this->get('/intend');

        impersonate($this->user)->assertRedirect('/dashboard');

        expect(session('url.intended'))->toBeNull();

        // A page of the user's chooses where the admin goes next.
        $this->get('/intend');
        stopImpersonating()->assertRedirect('/dashboard');

        expect(session('url.intended'))->toBeNull()
            ->and($this->get('/whoami')->getContent())->toBe((string) $this->admin->getKey());
    });
});

describe('while impersonating', function () {
    it('refuses keyring\'s security changes', function (string $method, Closure $url, array $data = []) {
        impersonating();
        $this->user->update(['remember_token' => 'the users own']);

        $this->json($method, $url(), $data)->assertForbidden()->assertJson(['status' => 'impersonating']);

        expect($this->get('/whoami')->getContent())->toBe((string) $this->user->getKey());
    })->with([
        'changing the password' => ['PUT', fn () => route('user-password.update'), ['current_password' => 'password', 'password' => 'a much longer passphrase', 'password_confirmation' => 'a much longer passphrase']],
        'changing the email address' => ['POST', fn () => route('keyring.email.store'), ['email' => 'new@example.com']],
        'cancelling an email change' => ['DELETE', fn () => route('keyring.email.destroy')],
        'adding an authenticator' => ['POST', fn () => route('keyring.authenticators.store', 'totp')],
        'confirming an authenticator' => ['POST', fn () => route('keyring.authenticators.confirm', 'totp'), ['code' => '123456']],
        'renaming an authenticator' => ['PATCH', fn () => route('keyring.authenticators.update', 'anything'), ['name' => 'Mine']],
        'removing an authenticator' => ['DELETE', fn () => route('keyring.authenticators.destroy', 'anything')],
        'signing out everywhere else' => ['DELETE', fn () => route('keyring.sessions.destroy-others')],
        'ending a session' => ['DELETE', fn () => route('keyring.sessions.destroy', str_repeat('a', 64))],
        'signing out other devices' => ['DELETE', fn () => route('keyring.devices.destroy-others')],
        'signing out a device' => ['DELETE', fn () => route('keyring.devices.destroy', 'anything')],
        'confirming it\'s them' => ['POST', fn () => route('keyring.confirm.verify', 'password'), ['password' => 'password']],
        'the confirm page' => ['GET', fn () => route('keyring.confirm.challenge')],
        'sending the verification email again' => ['POST', fn () => route('verification.send')],
    ]);

    // The link went to the user's inbox: an impersonator who has it still
    // isn't the one to say the address is theirs.
    it('refuses following the user\'s email verification link', function () {
        impersonating();
        $this->user->forceFill(['email_verified_at' => null])->save();
        $url = URL::temporarySignedRoute('verification.verify', now()->addHour(), ['id' => $this->user->id, 'hash' => sha1($this->user->email)], absolute: false);

        postSignedLink($url)->assertForbidden();
        parse_str((string) parse_url($url, PHP_URL_QUERY), $fields);
        $this->postJson((string) parse_url($url, PHP_URL_PATH), $fields)->assertForbidden()->assertJson(['status' => 'impersonating']);

        expect($this->user->fresh()->hasVerifiedEmail())->toBeFalse()
            ->and($this->get('/whoami')->getContent())->toBe((string) $this->user->getKey());
    });

    it('refuses the app\'s own routes behind keyring.not-impersonating, and lets them through otherwise', function () {
        adminSignsIn();
        $this->delete('/account')->assertOk();

        impersonate($this->user);

        $this->delete('/account')->assertForbidden();
        $this->deleteJson('/account')->assertForbidden()->assertExactJson(['status' => 'impersonating', 'message' => Keyring::statusMessage('impersonating')]);
    });

    it('lets the user\'s sessions be listed', function () {
        impersonating();

        $sessions = $this->getJson(route('keyring.sessions.index'))->assertOk()->json('sessions');

        expect($sessions)->toHaveCount(1)
            ->and($sessions[0])->toMatchArray(['current' => true, 'impersonated' => true, 'impersonator' => ['name' => 'Ada Admin']]);
    });

    it('is not held to what the user has still to do: enroll, or change a held password', function () {
        Route::middleware(['web', 'auth', 'keyring.enrolled', 'keyring.password'])->get('/orders', fn () => 'orders');
        config(['keyring.enrollment_url' => '/enroll', 'keyring.password_change_url' => '/change-password']);
        app(PasswordHolds::class)->place($this->user);

        impersonating();

        $this->get('/orders')->assertOk()->assertSee('orders');
    });

    it('shares what a banner needs', function () {
        $this->freezeSecond();
        impersonating();

        expect(Keyring::impersonation())->toBe([
            'impersonator' => ['id' => (string) $this->admin->getKey(), 'name' => 'Ada Admin'],
            'startedAt' => now()->toIso8601String(),
            'expiresAt' => now()->addHour()->toIso8601String(),
            'stopUrl' => route('keyring.impersonation.destroy'),
        ]);
    });

    it('shares nothing, and nobody, when nobody is impersonating', function () {
        adminSignsIn();

        expect(Keyring::impersonation())->toBeNull()
            ->and(Keyring::impersonating())->toBeFalse()
            ->and(Keyring::impersonator())->toBeNull();
    });

    it('keeps the admin\'s own session from idling out while they\'re busy', function () {
        config(['keyring.impersonation.lifetime' => '4h']);
        $own = impersonating();

        foreach (range(1, 3) as $hour) {
            $this->travel(50)->minutes();
            $this->get('/whoami')->assertOk();
        }

        expect(Keyring::impersonating())->toBeTrue()
            ->and(record($own)->lastActivityAt)->toBe(now()->getTimestamp())
            ->and(record(session(Sessions::KEY))->lastActivityAt)->toBe(now()->getTimestamp())
            ->and(record(session(Sessions::KEY))->impersonatorSession)->toBe($own);
    });

    it('doesn\'t take one of the user\'s places under sessions.max, nor end one to make room', function () {
        config(['keyring.sessions.max' => 2]);
        $this->post('/login', ['email' => 'abigail@example.com', 'password' => 'password']);
        $users = session(Sessions::KEY);
        $this->flushSession();
        Auth::forgetGuards();
        $this->travel(1)->minutes();

        impersonating();
        $impersonated = session(Sessions::KEY);
        $admin = session()->all();
        $this->flushSession();
        Auth::forgetGuards();

        // The user signs in somewhere else: with two places, both their own stay.
        $this->post('/login', ['email' => 'abigail@example.com', 'password' => 'password']);

        expect(record($users)->isActive(now()->getTimestamp()))->toBeTrue()
            ->and(record($impersonated)->isActive(now()->getTimestamp()))->toBeTrue();

        sendBackSession($admin);

        expect($this->get('/whoami')->getContent())->toBe((string) $this->user->getKey());
    });

    it('isn\'t the session that ends to make room under sessions.max, even having gone unused longest', function () {
        config(['keyring.sessions.max' => 2]);
        impersonating();
        $impersonated = session(Sessions::KEY);
        $admin = session()->all();

        $own = array_map(function () {
            $this->flushSession();
            Auth::forgetGuards();
            $this->travel(1)->minutes();
            $this->post('/login', ['email' => 'abigail@example.com', 'password' => 'password']);

            return session(Sessions::KEY);
        }, range(1, 3));

        // The third sign in takes them past two: their own oldest ends.
        expect(record($own[0])->revokedAt)->not->toBeNull()
            ->and(record($own[1])->isActive(now()->getTimestamp()))->toBeTrue()
            ->and(record($own[2])->isActive(now()->getTimestamp()))->toBeTrue()
            ->and(record($impersonated)->isActive(now()->getTimestamp()))->toBeTrue();

        sendBackSession($admin);

        expect($this->get('/whoami')->getContent())->toBe((string) $this->user->getKey());
    });
});

describe('stopping', function () {
    it('goes back to the admin\'s own session, on a new session id', function () {
        $own = impersonating();
        $impersonated = session(Sessions::KEY);
        $before = session()->getId();

        stopImpersonating()->assertRedirect('/dashboard')->assertSessionHas('status', 'impersonation-ended');

        expect(session()->getId())->not->toBe($before)
            ->and(session(Sessions::KEY))->toBe(record($own)->replacedBy)
            ->and($this->get('/whoami')->getContent())->toBe((string) $this->admin->getKey())
            ->and(Keyring::impersonating())->toBeFalse()
            ->and(record($impersonated)->revokedAt)->not->toBeNull()
            ->and(record(session(Sessions::KEY))->revokedAt)->toBeNull();

        // Back at AAL1: the second factor is asked for again.
        $this->get('/billing')->assertRedirect(route('keyring.confirm.challenge'));
    });

    it('answers json clients, and goes to impersonation.return_url', function () {
        config(['keyring.impersonation.return_url' => '/admin/users']);
        impersonating();

        stopImpersonating(json: true)->assertOk()->assertJson([
            'status' => 'impersonation-ended',
            'redirect' => url('/admin/users'),
        ])->assertHeader('Clear-Site-Data', '"cache", "storage"');
    });

    it('is a POST too, for a plain form', function () {
        impersonating();

        $this->post(route('keyring.impersonation.destroy'))->assertRedirect('/dashboard');

        expect($this->get('/whoami')->getContent())->toBe((string) $this->admin->getKey());
    });

    // A second stop, from a tab left open, finds the browser back already.
    it('answers a stop with nobody being impersonated as back already: 409 not-impersonating for json clients', function () {
        config(['keyring.impersonation.return_url' => '/admin/users']);
        $own = impersonating();
        stopImpersonating()->assertRedirect('/admin/users');
        $back = session(Sessions::KEY);

        stopImpersonating(json: true)->assertConflict()->assertExactJson([
            'status' => 'not-impersonating',
            'message' => Keyring::statusMessage('not-impersonating'),
            'redirect' => url('/admin/users'),
        ])->assertHeaderMissing('Clear-Site-Data');
        stopImpersonating()->assertRedirect('/admin/users')->assertSessionHas('status', 'not-impersonating');
        $this->inertia()->delete(route('keyring.impersonation.destroy'))->assertConflict()->assertHeader('X-Inertia-Location', url('/admin/users'));

        expect(Auth::id())->toBe($this->admin->getKey())
            ->and(session(Sessions::KEY))->toBe($back)
            ->and(record($own)->replacedBy)->toBe($back)
            ->and(record($back)->revokedAt)->toBeNull()
            ->and(fn () => Keyring::stopImpersonating(request()))->toThrow(LogicException::class);
    });

    it('signs out when there is no going back', function (Closure $meanwhile) {
        $own = impersonating();
        $meanwhile->call($this, $own);

        stopImpersonating(json: true)->assertUnauthorized()->assertJson(['status' => 'signed-out']);

        expect(Auth::guard('web')->check())->toBeFalse()
            ->and(record($own)?->isActive(now()->getTimestamp()) ?? false)->toBeFalse();
        $this->get('/whoami')->assertRedirect('/login');
    })->with([
        'the admin\'s session was revoked' => [fn (string $own) => app(SessionRegistry::class)->revoke($own)],
        'the admin\'s session is gone' => [function (string $own) {
            app(SessionRegistry::class)->revoke($own);
            app(SessionRegistry::class)->prune();
        }],
        'the admin was deleted' => [fn () => $this->admin->delete()],
        'the admin may no longer sign in' => [fn () => Keyring::allowSignInWhen(fn (User $user) => ! $user->is($this->admin))],
        'the admin\'s session expired' => [fn (string $own) => app(SessionRegistry::class)->update($own, ['expiresAt' => now()->getTimestamp()])],
        'the admin\'s session idled out' => [fn (string $own) => app(SessionRegistry::class)->update($own, ['lastActivityAt' => now()->subHours(3)->getTimestamp()])],
        'the admin is held for a new password' => [fn () => app(PasswordHolds::class)->place($this->admin)],
    ]);

    // The session middleware ends an impersonation it finds over before
    // the request gets this far. One that ends while the request is under
    // way still signs out.
    it('signs out when the admin\'s session ends while the request is under way', function () {
        $own = impersonating();
        app('router')->removeMiddlewareFromGroup('web', AuthenticateSession::class);
        app(SessionRegistry::class)->revoke($own);

        stopImpersonating(json: true)->assertUnauthorized()->assertJson(['status' => 'signed-out']);

        expect(Auth::guard('web')->check())->toBeFalse();
    });

    it('leaves the admin\'s "remember me" cookies as they are, and remembered, moving keyring\'s with their record', function () {
        adminSignsIn(remember: true);
        $own = session(Sessions::KEY);
        $recaller = Auth::guard('web')->getRecallerName();

        Cookie::flushQueuedCookies();
        $started = impersonate($this->user);
        Cookie::flushQueuedCookies();
        $stopped = stopImpersonating();

        expect($started->getCookie($recaller))->toBeNull()
            ->and($started->getCookie('remembered_session'))->toBeNull()
            ->and($stopped->getCookie($recaller))->toBeNull()
            ->and($stopped->getCookie('remembered_session')->getValue())->toBe(session(Sessions::KEY))
            ->and(session(Sessions::KEY))->toBe(record($own)->replacedBy)
            ->and(session(Sessions::REMEMBERED))->toBeTrue()
            ->and(record(session(Sessions::KEY))->remembered)->toBeTrue();
    });

    // A request sent while impersonating that saves its copy of the session
    // after the stop would put back what was parked, on any session driver.
    it('leaves a request that overlapped the stop nothing to go back to', function () {
        $own = impersonating();
        $during = session()->all();

        stopImpersonating()->assertRedirect('/dashboard');

        expect(record($own)->revokedAt)->not->toBeNull()
            ->and(record($own)->replacedBy)->toBe(session(Sessions::KEY));

        sendBackSession($during);
        $this->getJson('/whoami')->assertUnauthorized();

        expect(Auth::guard('web')->check())->toBeFalse()
            ->and(record(record($own)->replacedBy)->revokedAt)->toBeNull();
    });

    it('works on either registry', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        $own = impersonating();
        $impersonated = session(Sessions::KEY);

        stopImpersonating();

        expect(record($impersonated)->impersonatorSession)->toBe($own)
            ->and(record($impersonated)->revokedAt)->not->toBeNull()
            ->and(session(Sessions::KEY))->toBe(record($own)->replacedBy);
    })->with(['database', 'cache']);

    // A page of the user's could have sent the stop, a stored script say,
    // and would then carry on as the admin. It gets no further than AAL1.
    it('comes back at aal1, with nothing counting as fresh', function () {
        Route::middleware(['web', 'auth', 'keyring.fresh:15m'])->get('/danger', fn () => 'danger zone');
        impersonating();

        stopImpersonating();

        $this->get('/billing')->assertRedirect(route('keyring.confirm.challenge'));
        $this->getJson('/billing')->assertStatus(423);
        $this->get('/danger')->assertRedirect(route('keyring.confirm.challenge'));

        expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL1)
            ->and(array_column(app(SessionAssurance::class)->all(), 'factor'))->toBe(['password'])
            ->and(app(SessionAssurance::class)->provedSince(now()->subMinutes(15)->getTimestamp()))->toBe([])
            ->and(record(session(Sessions::KEY))->assurance)->toBe(Assurance::AAL1);
    });

    it('asks only for the second factor to step back up to aal2', function () {
        impersonating();
        stopImpersonating();

        $this->get('/billing')->assertRedirect(route('keyring.confirm.challenge'));
        $this->getJson(route('keyring.confirm.challenge'))->assertOk()->assertJsonPath('props.factor', 'totp')->assertJsonPath('props.alternatives', []);
        $this->post(route('keyring.confirm.verify', 'totp'), ['code' => totpCode($this->totp->secret, 1)])->assertRedirect('http://localhost/billing');

        $this->get('/billing')->assertOk()->assertSee('billing');

        expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL2)
            ->and(record(session(Sessions::KEY))->assurance)->toBe(Assurance::AAL2);
    });

    // A passkey that verified the user is both factors at once: nothing
    // short of AAL2 is left to keep, so the passkey is asked for again.
    it('keeps nothing of a sign in that was both factors at once', function () {
        $this->actingAs($this->admin)->withAssurance(Assurance::AAL3)->withSession([SessionAssurance::SIGNED_IN => Assurance::AAL3->value]);
        $this->get('/whoami')->assertOk();
        impersonate($this->user)->assertRedirect('/dashboard');

        stopImpersonating()->assertRedirect('/dashboard');

        expect(app(SessionAssurance::class)->level())->toBe(Assurance::None)
            ->and(app(SessionAssurance::class)->all())->toBe([])
            ->and(app(SessionAssurance::class)->signedInLevel())->toBe(Assurance::AAL3);
        expect($this->get('/whoami')->assertOk()->getContent())->toBe((string) $this->admin->getKey());
        $this->get('/billing')->assertRedirect(route('keyring.confirm.challenge'));
    });

    // The admin's own session would lapse a level after a gap past its idle
    // limit. Impersonating meanwhile doesn't wipe the gap out.
    it('lapses a level whose idle limit passed between two requests, as the admin\'s own session would', function () {
        config(['keyring.sessions.levels.aal2.idle' => '30m']);
        impersonating();

        $this->travel(20)->minutes();
        $this->get('/whoami')->assertOk();
        $this->travel(40)->minutes();

        stopImpersonating()->assertRedirect('/dashboard');

        expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL1);
        $this->get('/billing')->assertRedirect(route('keyring.confirm.challenge'));
    });

    // Coming back is at AAL1 at most, and a session there doesn't outlive
    // the level it signed in at, as one "remember me" brings back doesn't.
    it('signs the admin out rather than coming back below the level they signed in at, where sessions end with their level', function (Assurance $level) {
        config(['keyring.sessions.end_on_lapse' => true]);
        Event::fake([ImpersonationEnded::class]);
        $this->actingAs($this->admin)->withAssurance($level)->withSession([SessionAssurance::SIGNED_IN => $level->value]);
        $this->get('/whoami')->assertOk();
        $own = session(Sessions::KEY);
        impersonate($this->user)->assertRedirect('/dashboard');
        $impersonated = session(Sessions::KEY);

        stopImpersonating()->assertRedirect('/login');

        expect(Auth::guard('web')->check())->toBeFalse()
            ->and(record($own)->revokedAt)->not->toBeNull()
            ->and(record($own)->replacedBy)->toBeNull()
            ->and(record($impersonated)->revokedAt)->not->toBeNull();
        Event::assertDispatchedTimes(ImpersonationEnded::class, 1);
        Event::assertDispatched(ImpersonationEnded::class, fn (ImpersonationEnded $event) => $event->reason === ImpersonationEndReason::ImpersonatorSessionEnded && ! $event->returned);
    })->with([
        'signed in at aal2' => [Assurance::AAL2],
        'signed in at aal3' => [Assurance::AAL3],
    ]);

    // AAL1 holds once back, so it doesn't lapse there.
    it('comes back where sessions end with their level, for a session that signed in at aal1', function () {
        config(['keyring.sessions.end_on_lapse' => true]);
        $this->actingAs($this->admin)->withAssurance(Assurance::AAL2)->withSession([SessionAssurance::SIGNED_IN => Assurance::AAL1->value]);
        $this->get('/whoami')->assertOk();
        impersonate($this->user)->assertRedirect('/dashboard');

        stopImpersonating()->assertRedirect('/dashboard');

        expect(app(SessionAssurance::class)->signedInLevel())->toBe(Assurance::AAL1)
            ->and(app(SessionAssurance::class)->level())->toBe(Assurance::AAL1);

        $this->travel(5)->minutes();
        expect($this->get('/whoami')->assertOk()->getContent())->toBe((string) $this->admin->getKey());
        $this->get('/billing')->assertRedirect(route('keyring.confirm.challenge'));
    });

    // What held AAL1 was the authenticator app, as the password is past
    // AAL1's overall limit. Coming back takes the app away, which would
    // lapse the session on the next request, so it ends now.
    it('signs out a session that signed in at aal1 and held it only by what coming back takes away, where sessions end with their level', function () {
        config(['keyring.sessions.end_on_lapse' => true, 'keyring.sessions.levels.aal1.absolute' => '1h']);
        $this->actingAs($this->admin)->withSession([
            SessionAssurance::KEY => [
                'password' => new Verification('password', null, [Category::Knowledge], at: now()->subHours(2)->getTimestamp())->toArray(),
                $this->totp->getKey() => new Verification('totp', $this->totp->getKey(), [Category::Possession], at: now()->getTimestamp())->toArray(),
            ],
            SessionAssurance::SIGNED_IN => Assurance::AAL1->value,
        ]);
        // Started from a route of the app's that asks for no step-up.
        Route::middleware(['web', 'auth'])->post('/support/impersonate', fn (Request $request) => Keyring::impersonate($request, $this->user));
        $this->get('/whoami')->assertOk();
        $this->post('/support/impersonate')->assertOk();

        stopImpersonating()->assertRedirect('/login');

        expect(Auth::guard('web')->check())->toBeFalse()
            ->and(SecurityEvent::query()->where('type', 'impersonation_ended')->get()->pluck('meta.reason')->unique()->all())->toBe(['impersonator_session_ended']);
    });

    it('ends the admin\'s session where sessions end with their level, when a gap lapses it', function () {
        config(['keyring.sessions.end_on_lapse' => true, 'keyring.sessions.levels.aal2.idle' => '30m']);
        $own = impersonating();

        $this->travel(40)->minutes();

        $this->get('/whoami')->assertRedirect('/login')->assertSessionHas('status', 'signed-out');

        expect(Auth::guard('web')->check())->toBeFalse()
            ->and(record($own)->revokedAt)->not->toBeNull()
            ->and(SecurityEvent::query()->where('type', 'impersonation_ended')->get()->pluck('meta.reason')->unique()->all())->toBe(['impersonator_session_ended']);
    });

    // Without the session middleware getting there first, the stop itself
    // finds the level gone.
    it('ends it on a stop of the app\'s own too', function () {
        config(['keyring.sessions.end_on_lapse' => true, 'keyring.sessions.levels.aal2.idle' => '30m']);
        $own = impersonating();
        app('router')->removeMiddlewareFromGroup('web', AuthenticateSession::class);

        $this->travel(40)->minutes();

        stopImpersonating(json: true)->assertUnauthorized();

        expect(record($own)->revokedAt)->not->toBeNull();
    });

    // A form request is a copy of request(), which the Logout listener reads.
    it('announces a stop that signs out once, given a form request', function () {
        $own = impersonating();
        Route::middleware(['web', 'auth'])->delete('/admin/impersonation', function (PlainFormRequest $request) use ($own) {
            app(SessionRegistry::class)->revoke($own);

            return Keyring::stopImpersonating($request) === null ? 'signed out' : 'back';
        });
        Event::fake([ImpersonationEnded::class]);

        expect($this->delete('/admin/impersonation')->getContent())->toBe('signed out')
            ->and(Auth::guard('web')->check())->toBeFalse();
        Event::assertDispatchedTimes(ImpersonationEnded::class, 1);
        Event::assertDispatched(ImpersonationEnded::class, fn (ImpersonationEnded $event) => $event->reason === ImpersonationEndReason::ImpersonatorSessionEnded);
    });

    // Laravel's auth.session middleware would sign them out on its own, but
    // only where it runs, and its step after the response stores the
    // current hash over the one put back. Keyring compares them itself.
    it('signs the admin out rather than going back, when their password changed meanwhile', function () {
        Route::middleware(['web', 'auth', LaravelAuthenticateSession::class])->get('/checked', fn () => (string) Auth::id());
        adminSignsIn();
        $this->get('/checked');
        $own = session(Sessions::KEY);
        impersonate($this->user);
        app('router')->removeMiddlewareFromGroup('web', AuthenticateSession::class);

        // Saved behind Keyring's back, so nothing else signs the admin out.
        User::query()->whereKey($this->admin->getKey())->update(['password' => Hash::make('changed somewhere else')]);

        stopImpersonating()->assertRedirect('/login')->assertSessionHas('status', 'signed-out');

        expect(record($own)->revokedAt)->not->toBeNull()
            ->and(SecurityEvent::query()->where('type', 'impersonation_ended')->get()->pluck('meta.reason')->unique()->all())->toBe(['impersonator_session_ended']);
        $this->get('/checked')->assertRedirect('/login');
    });

    // Laravel's guard keeps the hash it signed in with in the session, and
    // nothing brings it up to date without auth.session: the change is
    // from before the impersonation, so it isn't one.
    it('goes back when the admin changed their password in this session before starting', function (bool $authSession) {
        if ($authSession) {
            withLaravelsAuthSession();
        }

        adminSignsIn();
        $this->put('/user/password', ['current_password' => 'password', 'password' => 'a-brand-new-long-password-1', 'password_confirmation' => 'a-brand-new-long-password-1'])->assertRedirect();
        $own = session(Sessions::KEY);
        $this->get('/whoami')->assertOk();

        impersonate($this->user)->assertRedirect('/dashboard');
        expect($this->get('/whoami')->assertOk()->getContent())->toBe((string) $this->user->getKey());
        Auth::forgetGuards();

        stopImpersonating()->assertRedirect('/dashboard')->assertSessionHas('status', 'impersonation-ended');

        expect(session(Sessions::KEY))->toBe(record($own)->replacedBy)
            ->and(SecurityEvent::query()->where('type', 'impersonation_ended')->get()->pluck('meta.reason')->unique()->all())->toBe(['stopped']);
        Auth::forgetGuards();
        expect($this->get('/whoami')->assertOk()->getContent())->toBe((string) $this->admin->getKey());
    })->with(['without laravel\'s auth.session' => [false], 'with laravel\'s auth.session' => [true]]);

    it('signs the admin out on a stop, when their password changed meanwhile', function (Closure $change, bool $authSession) {
        if ($authSession) {
            withLaravelsAuthSession();
        }

        $own = impersonating();
        $this->get('/whoami')->assertOk();

        $change($this->admin);
        Auth::forgetGuards();

        stopImpersonating()->assertRedirect('/login');

        expect(Auth::guard('web')->check())->toBeFalse()
            ->and(record($own)->revokedAt)->not->toBeNull();
        Auth::forgetGuards();
        $this->get('/whoami')->assertRedirect('/login');
        $this->get('/billing')->assertRedirect('/login');
    })->with([
        'with the query builder' => [fn (User $admin) => User::query()->whereKey($admin->getKey())->update(['password' => Hash::make('changed somewhere else')])],
        'without keyring\'s protection' => [fn (User $admin) => Keyring::withoutProtection(fn () => $admin->fresh()->forceFill(['password' => Hash::make('changed somewhere else')])->save())],
    ])->with(['without laravel\'s auth.session' => [false], 'with laravel\'s auth.session' => [true]]);

    it('goes back as before when laravel\'s auth.session middleware wraps the stop and the password is the same', function () {
        app('router')->pushMiddlewareToGroup('web', LaravelAuthenticateSession::class);
        app('router')->removeMiddlewareFromGroup('web', AuthenticateSession::class);
        app('router')->pushMiddlewareToGroup('web', AuthenticateSession::class);
        $own = impersonating();
        $this->get('/whoami')->assertOk();
        Auth::forgetGuards();

        stopImpersonating()->assertRedirect('/dashboard');

        expect(session(Sessions::KEY))->toBe(record($own)->replacedBy);
        Auth::forgetGuards();
        expect($this->get('/whoami')->assertOk()->getContent())->toBe((string) $this->admin->getKey());
    });

    it('signs the admin out on a stop, when their password was removed meanwhile', function () {
        $own = impersonating();
        User::query()->whereKey($this->admin->getKey())->update(['password' => null]);

        stopImpersonating()->assertRedirect('/login');

        expect(Auth::guard('web')->check())->toBeFalse()
            ->and(record($own)->revokedAt)->not->toBeNull()
            ->and(SecurityEvent::query()->where('type', 'impersonation_ended')->get()->pluck('meta.reason')->unique()->all())->toBe(['impersonator_session_ended']);
    });

    it('signs the admin out on a stop, when they had no password when it started and have one now', function () {
        adminSignsIn();
        $own = session(Sessions::KEY);
        User::query()->whereKey($this->admin->getKey())->update(['password' => null]);
        Auth::forgetGuards();
        impersonate($this->user)->assertRedirect('/dashboard');
        User::query()->whereKey($this->admin->getKey())->update(['password' => Hash::make('set somewhere else')]);
        Auth::forgetGuards();

        stopImpersonating()->assertRedirect('/login');

        expect(Auth::guard('web')->check())->toBeFalse()
            ->and(record($own)->revokedAt)->not->toBeNull()
            ->and(SecurityEvent::query()->where('type', 'impersonation_ended')->get()->pluck('meta.reason')->unique()->all())->toBe(['impersonator_session_ended']);
    });

    it('goes back when the admin had no password when it started, and still has none', function (bool $authSession) {
        if ($authSession) {
            withLaravelsAuthSession();
        }

        adminSignsIn();
        User::query()->whereKey($this->admin->getKey())->update(['password' => null]);
        Auth::forgetGuards();
        impersonate($this->user)->assertRedirect('/dashboard');
        Auth::forgetGuards();

        stopImpersonating()->assertRedirect('/dashboard');

        Auth::forgetGuards();
        expect($this->get('/whoami')->getContent())->toBe((string) $this->admin->getKey());
    })->with(['without laravel\'s auth.session' => [false], 'with laravel\'s auth.session' => [true]]);

    it('has an inertia visit load the next page in full, starting and stopping', function () {
        config(['keyring.impersonation.return_url' => '/admin/users']);
        adminSignsIn();

        $this->inertia()->post(route('keyring.impersonation.store', $this->user->getKey()))
            ->assertConflict()
            ->assertHeader('X-Inertia-Location', url('/dashboard'))
            ->assertHeader('Clear-Site-Data', '"cache", "storage"')
            ->assertSessionHas('status', 'impersonation-started');

        expect(Keyring::impersonating())->toBeTrue();

        $this->inertia()->delete(route('keyring.impersonation.destroy'))
            ->assertConflict()
            ->assertHeader('X-Inertia-Location', url('/admin/users'))
            ->assertHeader('Clear-Site-Data', '"cache", "storage"')
            ->assertSessionHas('status', 'impersonation-ended');

        expect(Keyring::impersonating())->toBeFalse()
            ->and(Auth::id())->toBe($this->admin->getKey());
    });

    // A cookie session lives in the browser, where nothing can destroy a
    // copy of the one it had while impersonating, with the admin's proofs
    // parked in it.
    it('leaves a copy of a cookie session from while impersonating nothing to go back to', function () {
        onTheCookieDriver();
        $own = impersonating();
        $during = cookiesOf($this->get('/whoami')->assertOk());

        $back = cookiesOf(stopImpersonating()->assertRedirect('/dashboard'));

        expect(session(Sessions::KEY))->not->toBe($own)
            ->and(record($own)->replacedBy)->toBe(session(Sessions::KEY));

        $this->flushSession();
        Auth::forgetGuards();
        $this->withCredentials()->withCookies($during)->getJson('/whoami')->assertUnauthorized();

        $this->flushSession();
        Auth::forgetGuards();
        expect($this->withCredentials()->withCookies($back)->get('/whoami')->assertOk()->getContent())->toBe((string) $this->admin->getKey());
    });
});

describe('ending by itself', function () {
    it('goes back to the admin after impersonation.lifetime', function () {
        $own = impersonating();
        $impersonated = session(Sessions::KEY);

        $this->travel(61)->minutes();

        $this->get('/whoami')->assertRedirect('/dashboard')->assertSessionHas('status', 'impersonation-ended')->assertHeader('Clear-Site-Data');

        expect(session(Sessions::KEY))->toBe(record($own)->replacedBy)
            ->and(record($impersonated)->revokedAt)->not->toBeNull()
            ->and($this->get('/whoami')->getContent())->toBe((string) $this->admin->getKey());
    });

    it('signs out on the next request once the admin\'s password changed', function (bool $authSession) {
        $own = impersonating();

        if ($authSession) {
            withLaravelsAuthSession();
        }

        User::query()->whereKey($this->admin->getKey())->update(['password' => Hash::make('changed somewhere else')]);
        Auth::forgetGuards();

        $this->get('/welcome')->assertRedirect('/login')->assertSessionHas('status', 'signed-out');

        expect(Auth::guard('web')->check())->toBeFalse()
            ->and(record($own)->revokedAt)->not->toBeNull();
    })->with(['without laravel\'s auth.session' => [false], 'with laravel\'s auth.session' => [true]]);

    it('signs out after impersonation.lifetime rather than going back, once the admin\'s password changed', function (bool $authSession) {
        if ($authSession) {
            withLaravelsAuthSession();
        }

        $own = impersonating();
        $this->get('/whoami')->assertOk();

        User::query()->whereKey($this->admin->getKey())->update(['password' => Hash::make('changed somewhere else')]);
        $this->travel(61)->minutes();
        Auth::forgetGuards();

        $this->get('/whoami')->assertRedirect('/login');

        expect(Auth::guard('web')->check())->toBeFalse()
            ->and(record($own)->revokedAt)->not->toBeNull();
        Auth::forgetGuards();
        $this->get('/whoami')->assertRedirect('/login');
    })->with(['without laravel\'s auth.session' => [false], 'with laravel\'s auth.session' => [true]]);

    it('tells a json client with a 409', function () {
        impersonating();
        $this->travel(61)->minutes();

        $this->getJson('/whoami')->assertConflict()->assertJson(['status' => 'impersonation-ended', 'redirect' => url('/dashboard')]);
    });

    it('has an inertia visit load the page in full', function () {
        impersonating();
        $this->travel(61)->minutes();

        $this->inertia()->get('/whoami')->assertConflict()->assertHeader('X-Inertia-Location', url('/dashboard'));
    });

    // Both sessions are kept up together, so only an admin's remembered
    // session outlasts the one they're impersonating in.
    it('ends when the impersonated session idles out', function () {
        config(['keyring.sessions.idle' => '30m']);
        adminSignsIn(remember: true);
        impersonate($this->user);

        $this->travel(31)->minutes();

        $this->get('/whoami')->assertRedirect('/dashboard');

        expect($this->get('/whoami')->getContent())->toBe((string) $this->admin->getKey());
    });

    it('ends, back to the admin, when the user ends the session from their own list', function () {
        $own = impersonating();
        $admin = session()->all();
        $this->flushSession();
        Auth::forgetGuards();

        $this->post('/login', ['email' => 'abigail@example.com', 'password' => 'password']);
        $listed = collect($this->getJson(route('keyring.sessions.index'))->json('sessions'))->firstWhere('impersonated', true);

        expect($listed['impersonator'])->toBe(['name' => 'Ada Admin']);

        $this->deleteJson(route('keyring.sessions.destroy', $listed['id']))->assertOk();

        sendBackSession($admin);
        $this->get('/whoami')->assertRedirect('/dashboard');

        expect(session(Sessions::KEY))->toBe(record($own)->replacedBy)
            ->and(SecurityEvent::query()->where('type', 'impersonation_ended')->get()->pluck('meta.reason')->unique()->all())->toBe(['ended']);
    });

    it('ends when the user may no longer sign in', function () {
        impersonating();
        Keyring::allowSignInWhen(fn (User $user) => ! $user->is($this->user));

        $this->get('/whoami')->assertRedirect('/dashboard');

        expect($this->get('/whoami')->getContent())->toBe((string) $this->admin->getKey());
    });

    it('signs out when the admin\'s own session ends meanwhile, as with signing out everywhere', function () {
        $own = impersonating();

        app(Sessions::class)->signOutEverywhere($this->admin);

        // A page guests may see too: Laravel's auth middleware would turn
        // the browser away first, to the login page, which is one.
        $this->get('/welcome')->assertRedirect('/login')->assertSessionHas('status', 'signed-out');

        expect(Auth::guard('web')->check())->toBeFalse()
            ->and(record($own)->revokedAt)->not->toBeNull();
    });

    // The impersonated record still says who, and which of their sessions
    // was parked: nobody can go back to it now, so it ends.
    it('signs out when the session no longer says who is impersonating, ending the admin\'s parked session', function () {
        Event::fake([ImpersonationEnded::class]);
        $own = impersonating();
        $handle = app(Sessions::class)->handle(record(session(Sessions::KEY)));
        session()->forget(Impersonation::KEY);

        $this->get('/whoami')->assertRedirect('/login');

        expect(record($own)->revokedAt)->not->toBeNull();
        Event::assertDispatched(ImpersonationEnded::class, fn (ImpersonationEnded $event) => $event->impersonator?->is($this->admin) && $event->user->is($this->user)
            && $event->reason === ImpersonationEndReason::Lost && ! $event->returned && $event->handle === $handle);
    });

    it('goes back when the impersonated session has no record, naming it by the handle it started with', function () {
        Event::fake([ImpersonationEnded::class]);
        $own = impersonating();
        $handle = app(Sessions::class)->handle(record(session(Sessions::KEY)));
        session()->forget(Sessions::KEY);

        $this->get('/whoami')->assertRedirect('/dashboard');

        expect(session(Sessions::KEY))->toBe(record($own)->replacedBy);
        Event::assertDispatched(ImpersonationEnded::class, fn (ImpersonationEnded $event) => $event->returned && $event->handle === $handle);
    });

    it('ends, back to the admin, once they may no longer impersonate the user', function () {
        $own = impersonating();
        Keyring::allowImpersonationWhen(fn () => false);

        $this->get('/whoami')->assertRedirect('/dashboard')->assertSessionHas('status', 'impersonation-ended');

        expect(session(Sessions::KEY))->toBe(record($own)->replacedBy)
            ->and($this->get('/whoami')->getContent())->toBe((string) $this->admin->getKey())
            ->and(SecurityEvent::query()->where('type', 'impersonation_ended')->get()->pluck('meta.reason')->unique()->all())->toBe(['ended']);
    });

    // Thrown, it would fail every request the browser makes, stopping and
    // signing out included, until its cookies were cleared.
    it('ends, back to the admin, when the callback throws while it runs, reporting what it threw', function () {
        Exceptions::fake();
        $own = impersonating();
        Keyring::allowImpersonationWhen(fn () => throw new RuntimeException('The roles service is down.'));

        $this->get('/whoami')->assertRedirect('/dashboard')->assertSessionHas('status', 'impersonation-ended');

        expect(session(Sessions::KEY))->toBe(record($own)->replacedBy)
            ->and($this->get('/whoami')->getContent())->toBe((string) $this->admin->getKey())
            ->and(SecurityEvent::query()->where('type', 'impersonation_ended')->get()->pluck('meta.reason')->unique()->all())->toBe(['ended']);
        Exceptions::assertReported(fn (RuntimeException $e) => $e->getMessage() === 'The roles service is down.');
    });

    it('brings the admin back signed in where sessions end with their level, having kept it from lapsing', function () {
        config(['keyring.sessions.end_on_lapse' => true]);
        $this->actingAs($this->admin)->withAssurance(Assurance::AAL2)->withSession([SessionAssurance::SIGNED_IN => Assurance::AAL1->value]);
        $this->get('/whoami')->assertOk();
        impersonate($this->user)->assertRedirect('/dashboard');

        $this->travel(40)->minutes();
        $this->get('/whoami')->assertOk();
        $this->travel(21)->minutes();

        $this->get('/whoami')->assertRedirect('/dashboard');

        expect($this->get('/whoami')->assertOk()->getContent())->toBe((string) $this->admin->getKey());
        $this->get('/billing')->assertRedirect(route('keyring.confirm.challenge'));
    });

    it('comes back at aal1 after impersonation.lifetime, and steps back up to aal2', function () {
        impersonating();

        // A request meanwhile keeps the admin's levels from idling out.
        $this->travel(40)->minutes();
        $this->get('/whoami')->assertOk();
        $this->travel(21)->minutes();
        $this->get('/whoami')->assertRedirect('/dashboard')->assertSessionHas('status', 'impersonation-ended');

        expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL1)
            ->and(record(session(Sessions::KEY))->assurance)->toBe(Assurance::AAL1);

        $this->get('/billing')->assertRedirect(route('keyring.confirm.challenge'));
        $this->post(route('keyring.confirm.verify', 'totp'), ['code' => totpCode($this->totp->secret)])->assertRedirect('http://localhost/billing');
        $this->get('/billing')->assertOk()->assertSee('billing');

        expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL2);
    });

    // A session that signed in at AAL2 would come back at AAL1, which is
    // the level it signed in at lapsing: it ends instead, saying why.
    it('signs the admin out where sessions end with their level, rather than coming back at aal1', function (bool $timeLimit) {
        config(['keyring.sessions.end_on_lapse' => true]);
        $own = impersonating();
        $impersonated = session(Sessions::KEY);

        if ($timeLimit) {
            $this->travel(40)->minutes();
            $this->get('/whoami')->assertOk();
            $this->travel(21)->minutes();
            $this->get('/whoami')->assertRedirect('/login')->assertSessionHas('status', 'signed-out');
        } else {
            stopImpersonating()->assertRedirect('/login');
        }

        expect(Auth::guard('web')->check())->toBeFalse()
            ->and(record($own)->revokedAt)->not->toBeNull()
            ->and(record($impersonated)->revokedAt)->not->toBeNull()
            ->and(SecurityEvent::query()->where('type', 'impersonation_ended')->oldest('id')->get()->map(fn (SecurityEvent $event) => [$event->meta['role'], $event->meta['reason'], $event->meta['returned']])->all())->toBe([
                ['impersonator', 'impersonator_session_ended', false],
                ['impersonated', 'impersonator_session_ended', false],
            ]);
    })->with(['on a stop' => [false], 'after impersonation.lifetime' => [true]]);

    // Nothing is left for the next sign in on the browser to go back with.
    it('signs out when the user can no longer be loaded', function () {
        $own = impersonating();
        $impersonated = session(Sessions::KEY);

        $this->user->delete();
        Auth::forgetGuards();

        // A page guests may see too: Laravel's auth middleware would turn
        // the browser away first, to the login page, which is one.
        $this->get('/welcome')->assertRedirect('/login')->assertSessionHas('status', 'signed-out');

        expect(session()->has(Impersonation::KEY))->toBeFalse()
            ->and(record($own)->revokedAt)->not->toBeNull()
            ->and(record($impersonated)->revokedAt)->not->toBeNull()
            ->and(logEntry('impersonation_ended'))
            ->authenticatable_id->toBe($this->admin->getKey())
            ->meta->toEqual(['impersonator' => (string) $this->admin->getKey(), 'user' => null, 'reason' => 'lost', 'returned' => false, 'role' => 'impersonator']);
        expect($this->get('/welcome')->getContent())->toBe('guest');
    });

    it('signs out, rather than going back, when someone else is signed in on the session', function () {
        $own = impersonating();
        $parked = session(Impersonation::KEY);
        $this->flushSession();
        Auth::forgetGuards();

        $this->post('/login', ['email' => 'abigail@example.com', 'password' => 'password']);
        session()->put(Impersonation::KEY, $parked);

        $this->get('/whoami')->assertRedirect('/login');

        expect(Auth::guard('web')->check())->toBeFalse()
            ->and(record($own)->revokedAt)->not->toBeNull()
            ->and(SecurityEvent::query()->where('type', 'impersonation_ended')->get()->pluck('meta.reason')->unique()->all())->toBe(['lost']);
    });

    // The app's own Auth::login() on the session, once the impersonated
    // record is gone (pruned, or dropped by the cache), leaves no record to
    // say whose session it is: the guard's user does.
    it('signs out, rather than going back, when someone else is signed in on a session with no record', function () {
        $own = impersonating();
        $other = User::create(['name' => 'Other', 'email' => 'other@example.com', 'password' => 'password', 'email_verified_at' => now()]);
        session()->forget(Sessions::KEY);
        session()->put(Auth::guard('web')->getName(), $other->getKey());
        Auth::forgetGuards();

        $this->get('/whoami')->assertRedirect('/login');

        expect(Auth::guard('web')->check())->toBeFalse()
            ->and(record($own)->revokedAt)->not->toBeNull()
            ->and(SecurityEvent::query()->where('type', 'impersonation_ended')->get()->pluck('meta.reason')->unique()->all())->toBe(['lost']);
    });

    // As any session that ends there is.
    it('asks for a page that also serves guests again, as a guest, when it signs out', function () {
        config(['keyring.sessions.continue_as_guest' => ['welcome']]);
        Route::middleware('web')->get('/welcome', fn () => Auth::check() ? (string) Auth::id() : 'guest')->name('welcome');
        app('router')->getRoutes()->refreshNameLookups();
        $own = impersonating();

        app(Sessions::class)->signOutEverywhere($this->admin);

        $this->get('/welcome?tab=news')->assertRedirect('/welcome?tab=news')->assertSessionHas('status', 'signed-out')->assertHeader('Clear-Site-Data');

        expect(Auth::guard('web')->check())->toBeFalse()
            ->and(session()->has(Impersonation::KEY))->toBeFalse()
            ->and(record($own)->revokedAt)->not->toBeNull()
            ->and($this->get('/welcome?tab=news')->getContent())->toBe('guest');
        $this->getJson('/welcome')->assertOk();
    });

    it('signs out for the reason it ended for in the end', function (Closure $meanwhile, string $reason) {
        Keyring::respondWith(SignedOutResponse::class, fn ($app, array $with) => new class($with['reason']) implements SignedOutResponse
        {
            public function __construct(public string $reason) {}

            public function toResponse($request)
            {
                return response("signed out: {$this->reason}", 401);
            }
        });
        $own = impersonating();
        $meanwhile->call($this, $own);

        expect($this->get('/welcome')->assertUnauthorized()->getContent())->toBe("signed out: {$reason}");
    })->with([
        // Ended, but with nobody to go back to.
        'the user and the admin signed out everywhere' => [function (string $own) {
            app(SessionRegistry::class)->revoke(session(Sessions::KEY));
            app(SessionRegistry::class)->revoke($own);
        }, 'impersonator_session_ended'],
        'the user deleted' => [function () {
            $this->user->delete();
            Auth::forgetGuards();
        }, 'lost'],
    ]);

    it('answers a stop with the reason it ended for, too', function () {
        Keyring::respondWith(SignedOutResponse::class, fn ($app, array $with) => new class($with['reason']) implements SignedOutResponse
        {
            public function __construct(public string $reason) {}

            public function toResponse($request)
            {
                return response("signed out: {$this->reason}", 401);
            }
        });
        $own = impersonating();

        // With the middleware out of the way, the stop is the first to see
        // the session is on a record that isn't the impersonation's.
        app('router')->removeMiddlewareFromGroup('web', AuthenticateSession::class);
        session()->put(Sessions::KEY, $own);

        expect(stopImpersonating()->assertUnauthorized()->getContent())->toBe('signed out: lost')
            ->and(record($own)->revokedAt)->not->toBeNull();
    });
});

describe('two requests ending it', function () {
    // A request that read the session before another ended the
    // impersonation, an XHR sent alongside say, saves its copy after it.
    it('ends it once when a copy of the session from before ends it again, leaving the admin signed in', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        $ended = impersonationsEnded();
        adminSignsIn(remember: true);
        $own = session(Sessions::KEY);
        impersonate($this->user);
        $during = session()->all();

        $this->travel(61)->minutes();
        $this->get('/whoami')->assertRedirect('/dashboard')->assertSessionHas('status', 'impersonation-ended');
        $back = session()->all();

        sendBackSession($during);
        Cookie::flushQueuedCookies();
        $stale = $this->getJson('/whoami')->assertUnauthorized();

        expect($ended)->toHaveCount(1)
            ->and($ended[0]->returned)->toBeTrue()
            ->and(SecurityEvent::query()->where('type', 'impersonation_ended')->count())->toBe(2)
            ->and(record(record($own)->replacedBy)->isActive(now()->getTimestamp()))->toBeTrue()
            ->and(Auth::guard('web')->check())->toBeFalse()
            // Its "remember me" cookies are the admin's, which it leaves as they are.
            ->and($stale->getCookie('remembered_session'))->toBeNull()
            ->and($stale->getCookie(Auth::guard('web')->getRecallerName()))->toBeNull();

        sendBackSession($back);
        expect($this->get('/whoami')->assertOk()->getContent())->toBe((string) $this->admin->getKey());
    })->with(['database', 'cache']);

    it('announces a sign-out once when a copy of the session from before it ends it again', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        $ended = impersonationsEnded();
        adminSignsIn();
        impersonate($this->user);
        $during = session()->all();

        $this->post('/logout');

        sendBackSession($during);
        Cookie::flushQueuedCookies();
        $this->getJson('/whoami')->assertUnauthorized();

        expect($ended)->toHaveCount(1)
            ->and($ended[0]->reason)->toBe(ImpersonationEndReason::SignedOut)
            ->and(SecurityEvent::query()->where('type', 'impersonation_ended')->count())->toBe(2);
    })->with(['database', 'cache']);

    it('doesn\'t announce a sign-out again when a copy of the session signs out after another request ended it', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        $ended = impersonationsEnded();
        adminSignsIn();
        impersonate($this->user);
        $during = session()->all();

        $this->travel(61)->minutes();
        $this->get('/whoami')->assertRedirect('/dashboard');

        sendBackSession($during);
        $this->post('/logout');

        expect($ended)->toHaveCount(1)
            ->and(SecurityEvent::query()->where('type', 'impersonation_ended')->count())->toBe(2);
    })->with(['database', 'cache']);

    it('ends it once when two requests find it over together, and only one revokes it', function () {
        $ended = impersonationsEnded();
        $own = impersonating();
        $impersonated = session(Sessions::KEY);
        $during = session()->all();
        $earlier = [$impersonated => record($impersonated), $own => record($own)];

        $this->travel(61)->minutes();
        $this->get('/whoami')->assertRedirect('/dashboard');
        $back = session()->all();

        // The other request read both records before this one ended it.
        registryReadingEarlier($earlier);
        sendBackSession($during);
        $this->getJson('/whoami')->assertUnauthorized();
        config(['keyring.sessions.driver' => 'database']);

        expect($ended)->toHaveCount(1)
            ->and($ended[0]->reason)->toBe(ImpersonationEndReason::Expired)
            ->and(SecurityEvent::query()->where('type', 'impersonation_ended')->count())->toBe(2)
            ->and(record($impersonated)->revokedAt)->not->toBeNull()
            ->and(record(record($own)->replacedBy)->isActive(now()->getTimestamp()))->toBeTrue()
            ->and(Auth::guard('web')->check())->toBeFalse();

        sendBackSession($back);
        expect($this->get('/whoami')->assertOk()->getContent())->toBe((string) $this->admin->getKey());
    });

    // Ended by the user from their sessions list, it's found ended by both,
    // so neither revokes it: claiming its end decides.
    it('goes back once when two requests go back together from one the user ended', function () {
        $ended = impersonationsEnded();
        $own = impersonating();
        app(SessionRegistry::class)->revoke(session(Sessions::KEY));
        $during = session()->all();
        $earlier = [$own => record($own)];

        $this->get('/whoami')->assertRedirect('/dashboard')->assertSessionHas('status', 'impersonation-ended');
        $back = session()->all();

        // The other request found the admin's record yet to move.
        registryReadingEarlier($earlier);
        sendBackSession($during);
        $this->getJson('/whoami')->assertUnauthorized();
        config(['keyring.sessions.driver' => 'database']);

        expect($ended)->toHaveCount(1)
            ->and($ended[0]->reason)->toBe(ImpersonationEndReason::Ended)
            ->and($ended[0]->returned)->toBeTrue()
            ->and(SecurityEvent::query()->where('type', 'impersonation_ended')->count())->toBe(2)
            ->and(record(record($own)->replacedBy)->isActive(now()->getTimestamp()))->toBeTrue()
            ->and(Auth::guard('web')->check())->toBeFalse();

        sendBackSession($back);
        expect($this->get('/whoami')->assertOk()->getContent())->toBe((string) $this->admin->getKey());
    });

    // The user ends it from their sessions list, or anything else ends it,
    // while the stop is under way: after the stop read the record, before
    // it revokes it. Nobody else ended the impersonation, so the stop does.
    it('ends it, once, when its record is revoked from outside during the stop', function (bool $returnable) {
        $ended = impersonationsEnded();
        $own = impersonating();
        $impersonated = session(Sessions::KEY);
        $calls = 0;

        // Asked of the admin by the session middleware, then by the stop.
        Keyring::allowSignInWhen(function (User $user) use (&$calls, $impersonated, $returnable) {
            if ($user->is($this->admin) && ++$calls === 2) {
                app(SessionRegistry::class)->revoke($impersonated);

                return $returnable;
            }

            return true;
        });

        stopImpersonating()->assertRedirect($returnable ? '/dashboard' : '/login');

        expect($calls)->toBe(2)
            ->and($ended)->toHaveCount(1)
            ->and($ended[0]->reason)->toBe($returnable ? ImpersonationEndReason::Stopped : ImpersonationEndReason::ImpersonatorSessionEnded)
            ->and($ended[0]->returned)->toBe($returnable)
            ->and(SecurityEvent::query()->where('type', 'impersonation_ended')->count())->toBe(2)
            ->and(record($impersonated)->revokedAt)->not->toBeNull()
            ->and(record($own)->revokedAt)->not->toBeNull()
            ->and(record($own)->replacedBy)->toBe($returnable ? session(Sessions::KEY) : null)
            ->and(Auth::id())->toBe($returnable ? $this->admin->getKey() : null);
    })->with(['back to the admin' => [true], 'with nothing to go back to' => [false]]);

    // The admin's own session was ended elsewhere, so both sign out.
    it('ends it once when two requests sign out together', function () {
        $ended = impersonationsEnded();
        $own = impersonating();
        $during = session()->all();
        app(SessionRegistry::class)->revoke($own);

        stopImpersonating()->assertRedirect('/login');

        sendBackSession($during);
        $this->getJson('/whoami')->assertUnauthorized();

        expect($ended)->toHaveCount(1)
            ->and($ended[0]->reason)->toBe(ImpersonationEndReason::ImpersonatorSessionEnded)
            ->and(SecurityEvent::query()->where('type', 'impersonation_ended')->oldest('id')->pluck('meta')->map(fn (array $meta) => $meta['role'])->all())->toBe(['impersonator', 'impersonated'])
            ->and(Auth::guard('web')->check())->toBeFalse();
    });

    // The admin's record moved without going back to it, a step-up on a
    // copy of their session from before it started say, and the user ended
    // the impersonation. Nobody went back, so the end is still announced.
    it('ends it when the admin\'s record moved for some other reason', function () {
        $ended = impersonationsEnded();
        $own = impersonating();
        $impersonated = session(Sessions::KEY);
        app(SessionRegistry::class)->replace($own, record($own)->with(['id' => 'stepped-up', 'origin' => record($own)->origin()]), revoke: true);
        app(SessionRegistry::class)->revoke($impersonated);

        $this->get('/whoami')->assertRedirect('/login');

        expect($ended)->toHaveCount(1)
            ->and($ended[0]->reason)->toBe(ImpersonationEndReason::ImpersonatorSessionEnded)
            ->and($ended[0]->returned)->toBeFalse()
            ->and(SecurityEvent::query()->where('type', 'impersonation_ended')->count())->toBe(2)
            ->and(record('stepped-up')->isActive(now()->getTimestamp()))->toBeTrue()
            ->and(Auth::guard('web')->check())->toBeFalse();
    });

    // Without the claim's store, nothing says another request ended it, so
    // it's announced rather than risk never announcing it.
    it('ends it when the store the claim is kept in fails, reporting why', function () {
        Exceptions::fake();
        $ended = impersonationsEnded();
        impersonating();
        config(['cache.limiter' => 'missing']);

        stopImpersonating()->assertRedirect('/dashboard');

        expect($ended)->toHaveCount(1)
            ->and(Auth::id())->toBe($this->admin->getKey());
        Exceptions::assertReported(InvalidArgumentException::class);
    });

    // The claim is given up, so the next request, finding it over, ends it.
    it('leaves the end to the next request when ending the admin\'s session fails', function () {
        Exceptions::fake();
        $ended = impersonationsEnded();
        $own = impersonating();
        Keyring::withoutProtection(fn () => $this->admin->forceFill(['password' => 'changed meanwhile'])->save());

        // The impersonated record ends, and the admin's doesn't, once.
        registryThatGoesAway(works: 1, fails: 1);
        stopImpersonating()->assertServerError();

        expect($ended)->toHaveCount(0)
            ->and(record($own)->revokedAt)->toBeNull();

        $this->get('/whoami')->assertRedirect('/login');

        expect($ended)->toHaveCount(1)
            ->and($ended[0]->reason)->toBe(ImpersonationEndReason::ImpersonatorSessionEnded)
            ->and(record($own)->revokedAt)->not->toBeNull()
            ->and(Auth::guard('web')->check())->toBeFalse();
    });

    // On the cookie driver, a second stop from a copy kept in the browser
    // gets past the stop route's block().
    it('answers a stop another request beat to it as signed out', function () {
        $ended = impersonationsEnded();
        $own = impersonating();
        $during = session()->all();

        stopImpersonating()->assertRedirect('/dashboard');

        sendBackSession($during);
        stopImpersonating(json: true)->assertUnauthorized()->assertJson(['status' => 'signed-out']);

        expect($ended)->toHaveCount(1)
            ->and($ended[0]->reason)->toBe(ImpersonationEndReason::Stopped)
            ->and(record(record($own)->replacedBy)->isActive(now()->getTimestamp()))->toBeTrue();
    });
});

describe('signing out while impersonating', function () {
    it('signs the browser out, ends the admin\'s parked session and leaves the user\'s "remember me" alone', function () {
        $own = impersonating();
        $this->user->forceFill(['remember_token' => 'the users own'])->save();

        $this->post('/logout')->assertRedirect('/');

        expect(Auth::guard('web')->check())->toBeFalse()
            ->and(record($own)->revokedAt)->not->toBeNull()
            ->and($this->user->fresh()->remember_token)->toBe('the users own')
            ->and(SecurityEvent::query()->where('type', 'impersonation_ended')->get()->pluck('meta.reason')->unique()->all())->toBe(['signed_out']);
    });

    it('does the same for the app\'s own Auth::logout()', function () {
        Route::middleware(['web', 'auth'])->post('/my-logout', function () {
            Auth::logout();

            return 'bye';
        });
        Event::fake([ImpersonationEnded::class]);
        $own = impersonating();
        $handle = app(Sessions::class)->handle(record(session(Sessions::KEY)));

        $this->post('/my-logout')->assertOk();

        expect(record($own)->revokedAt)->not->toBeNull();
        Event::assertDispatched(ImpersonationEnded::class, fn (ImpersonationEnded $event) => $event->reason === ImpersonationEndReason::SignedOut && ! $event->returned
            && $event->handle === $handle);
    });

    it('does the same when the app empties the session before its Auth::logout()', function () {
        Route::middleware(['web', 'auth'])->post('/my-logout', function (Request $request) {
            $request->session()->invalidate();
            Auth::logout();

            return 'bye';
        });
        Event::fake([ImpersonationEnded::class]);
        $own = impersonating();
        $impersonated = session(Sessions::KEY);

        $this->post('/my-logout')->assertOk();

        expect(record($own)->revokedAt)->not->toBeNull()
            ->and(record($impersonated)->revokedAt)->not->toBeNull();
        Event::assertDispatchedTimes(ImpersonationEnded::class, 1);
        Event::assertDispatched(ImpersonationEnded::class, fn (ImpersonationEnded $event) => $event->impersonator->is($this->admin) && $event->user->is($this->user)
            && $event->reason === ImpersonationEndReason::SignedOut);
    });

    it('signs out when the registry fails, ending the admin\'s parked session on the guard\'s second go', function () {
        Exceptions::fake();
        Event::fake([ImpersonationEnded::class]);
        $own = impersonating();
        $impersonated = session(Sessions::KEY);
        $this->user->forceFill(['remember_token' => 'the users own'])->save();

        // Only the first revocation, of the parked session, fails.
        registryThatGoesAway(works: 0, fails: 1);

        $this->post('/logout')->assertServerError();

        expect(Auth::guard('web')->check())->toBeFalse()
            ->and(session()->has(Auth::guard('web')->getName()))->toBeFalse()
            ->and(session()->has(Impersonation::KEY))->toBeFalse()
            ->and(record($own)->revokedAt)->not->toBeNull()
            ->and(record($impersonated)->revokedAt)->not->toBeNull()
            ->and($this->user->fresh()->remember_token)->toBe('the users own');
        Event::assertDispatchedTimes(ImpersonationEnded::class, 1);
    });

    it('logs the end once when the registry can\'t end the admin\'s parked session at all', function () {
        Exceptions::fake();
        $events = new ArrayObject;
        Event::listen(ImpersonationEnded::class, fn (ImpersonationEnded $event) => $events->append($event));
        impersonating();
        registryThatGoesAway(works: 0);

        $this->post('/logout')->assertServerError();

        expect(Auth::guard('web')->check())->toBeFalse()
            ->and(array_map(fn (ImpersonationEnded $event) => [$event->reason, $event->returned], $events->getArrayCopy()))->toBe([[ImpersonationEndReason::SignedOut, false]])
            ->and(SecurityEvent::query()->where('type', 'impersonation_ended')->get()->pluck('meta.reason')->all())->toBe(['signed_out', 'signed_out']);
    });

    // A sign in on a session that still holds an impersonation, with the
    // session middleware out of the way, ends it first. When that fails, the
    // browser is signed out, and the guard's sign-out ends the parked
    // session, having announced it already.
    it('doesn\'t log the end again when the guard\'s sign-out ends the parked session after a sign in failed to', function () {
        Exceptions::fake();
        $own = impersonating();
        User::create(['name' => 'Third', 'email' => 'third@example.com', 'password' => 'password', 'email_verified_at' => now()]);
        $this->user->delete();
        Auth::forgetGuards();
        app('router')->removeMiddlewareFromGroup('web', AuthenticateSession::class);
        registryThatGoesAway(works: 0, fails: 1);

        $this->post('/login', ['email' => 'third@example.com', 'password' => 'password'])->assertServerError();

        expect(record($own)->revokedAt)->not->toBeNull()
            ->and(session()->has(Impersonation::KEY))->toBeFalse()
            ->and(SecurityEvent::query()->where('type', 'impersonation_ended')->get()->pluck('meta.reason')->all())->toBe(['signed_out']);

        Auth::forgetGuards();
        $this->post('/login', ['email' => 'third@example.com', 'password' => 'password'])->assertRedirect('/dashboard');

        expect(SecurityEvent::query()->where('type', 'impersonation_ended')->count())->toBe(1);
    });

    // Signing in as someone else from the app's own route, while
    // impersonating, ends the impersonation first. When the registry can't,
    // the browser is signed out rather than carrying on as the user on an
    // impersonation that was announced as ended. The guard's sign-out ends
    // the parked session on its second go.
    it('signs the browser out when a sign in from the app can\'t end the impersonation first', function () {
        $third = User::create(['name' => 'Third', 'email' => 'third@example.com', 'password' => 'password', 'email_verified_at' => now()]);
        Route::middleware(['web', 'auth'])->post('/sign-in-as', function (Request $request) use ($third) {
            app(SignIn::class)->as($request, $third, []);

            return 'signed in';
        });
        Exceptions::fake();
        Event::fake([ImpersonationEnded::class]);
        $own = impersonating();
        $impersonated = session(Sessions::KEY);
        registryThatGoesAway(works: 0, fails: 1);

        $this->post('/sign-in-as')->assertServerError();

        expect(Auth::guard('web')->check())->toBeFalse()
            ->and(session()->has(Impersonation::KEY))->toBeFalse()
            ->and(record($own)->revokedAt)->not->toBeNull()
            ->and(record($impersonated)->revokedAt)->not->toBeNull();
        Auth::forgetGuards();
        $this->get('/whoami')->assertRedirect('/login');
        Event::assertDispatchedTimes(ImpersonationEnded::class, 1);
        Event::assertDispatched(ImpersonationEnded::class, fn (ImpersonationEnded $event) => $event->reason === ImpersonationEndReason::SignedOut && ! $event->returned);
    });

    it('signs out with the registry down, changing the admin\'s "remember me" token rather than the user\'s', function (string $url) {
        Route::middleware(['web', 'auth'])->post('/my-logout-device', function () {
            Auth::logoutCurrentDevice();

            return 'bye';
        });
        Exceptions::fake();
        adminSignsIn(remember: true);
        impersonate($this->user);
        $this->user->forceFill(['remember_token' => 'the users own'])->save();
        $token = $this->admin->fresh()->remember_token;
        registryThatGoesAway(works: 0);

        $this->post($url);

        expect(Auth::guard('web')->check())->toBeFalse()
            ->and(session()->has(Auth::guard('web')->getName()))->toBeFalse()
            ->and($this->user->fresh()->remember_token)->toBe('the users own')
            ->and($this->admin->fresh()->remember_token)->not->toBe($token)->not->toBeNull();
        Exceptions::assertReported(fn (RuntimeException $e) => $e->getMessage() === 'The database went away.');
    })->with(['keyring\'s sign-out' => '/logout', 'the app\'s Auth::logoutCurrentDevice()' => '/my-logout-device']);

    // Signing in ends what the session still held, wherever it came from:
    // here it's left behind with the session middleware out of the way.
    it('leaves nothing parked for whoever signs in next on the session', function () {
        $own = impersonating();
        $third = User::create(['name' => 'Third', 'email' => 'third@example.com', 'password' => 'password', 'email_verified_at' => now()]);
        $this->user->delete();
        Auth::forgetGuards();
        app('router')->removeMiddlewareFromGroup('web', AuthenticateSession::class);

        $this->post('/login', ['email' => 'third@example.com', 'password' => 'password'])->assertRedirect('/dashboard');

        app('router')->pushMiddlewareToGroup('web', AuthenticateSession::class);

        expect(session()->has(Impersonation::KEY))->toBeFalse()
            ->and(record($own)->revokedAt)->not->toBeNull()
            ->and($this->get('/whoami')->assertOk()->getContent())->toBe((string) $third->getKey())
            ->and($this->get('/whoami')->getContent())->toBe((string) $third->getKey())
            ->and(logEntry('impersonation_ended')->meta)->toMatchArray(['reason' => 'signed_out', 'user' => null]);
    });
});

describe('the user\'s sessions list', function () {
    it('shows the session with who is in it', function () {
        impersonating();

        $listed = app(Sessions::class)->list(request(), $this->user)->sole();

        expect($listed)->toMatchArray(['impersonated' => true, 'impersonator' => ['name' => 'Ada Admin'], 'remembered' => false, 'device' => null]);
    });

    // They'd be the support staff's own: where they are, and what they use.
    it('shows no ip address, browser or device for it, whatever its record holds, keeping the times', function () {
        impersonating();
        $impersonated = session(Sessions::KEY);
        app(SessionRegistry::class)->update($impersonated, ['ip' => '198.51.100.9', 'userAgent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0', 'deviceId' => 'the admins']);

        $listed = $this->getJson(route('keyring.sessions.index'))->assertOk()->json('sessions.0');

        expect($listed)->toMatchArray(['name' => null, 'ip' => null, 'device' => null, 'impersonated' => true, 'impersonator' => ['name' => 'Ada Admin'], 'current' => true])
            ->and($listed['signedInAt'])->toBe(now()->toIso8601String())
            ->and($listed['lastActiveAt'])->toBe(now()->toIso8601String())
            ->and($listed['expiresAt'])->toBe(now()->addHour()->toIso8601String());
    });

    it('still shows the user\'s own sessions\' ip address and browser beside it', function () {
        impersonating();

        $this->flushSession();
        Auth::forgetGuards();
        $this->withHeader('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0')->post('/login', ['email' => 'abigail@example.com', 'password' => 'password']);

        $own = collect($this->getJson(route('keyring.sessions.index'))->json('sessions'))->firstWhere('impersonated', false);

        expect($own)->toMatchArray(['name' => 'Firefox on Windows', 'ip' => '127.0.0.1']);
    });

    it('names nobody once the impersonator is gone', function () {
        impersonating();
        $record = record(session(Sessions::KEY));

        $this->admin->delete();

        expect(app(Impersonation::class)->describe($record))->toBeNull()
            ->and(app(Impersonation::class)->describe($record->with(['impersonatorId' => null])))->toBeNull();
    });

    it('leaves it out with impersonation.show_in_sessions off, but can still sign it out everywhere', function () {
        impersonating();
        $impersonated = session(Sessions::KEY);
        config(['keyring.impersonation.show_in_sessions' => false]);
        $this->flushSession();
        Auth::forgetGuards();

        $this->post('/login', ['email' => 'abigail@example.com', 'password' => 'password']);

        expect($this->getJson(route('keyring.sessions.index'))->json('sessions'))->toHaveCount(1)
            ->and($this->getJson(route('keyring.sessions.index'))->json('sessions.0.impersonated'))->toBeFalse();

        app(Sessions::class)->signOutEverywhere($this->user);

        expect(record($impersonated)->revokedAt)->not->toBeNull();
    });
});

describe('the security log and events', function () {
    // The requests are the admin's, so their IP address and browser would
    // show the user where support staff are and what they use.
    it('leaves the admin\'s IP address and browser off the user\'s entries, keeping them on the admin\'s', function () {
        $this->withHeader('User-Agent', FIREFOX);
        Route::middleware(['web', 'auth'])->post('/note', fn (Request $request) => app(SecurityLog::class)->record('noted', $request->user())?->getKey());
        impersonating();
        $during = $this->post('/note')->getContent();
        stopImpersonating()->assertRedirect('/dashboard');
        $after = $this->post('/note')->getContent();

        $entries = SecurityEvent::query()->whereIn('type', ['impersonation_started', 'impersonation_ended'])->oldest('id')->get();

        expect($entries->map(fn (SecurityEvent $entry) => [$entry->type, $entry->meta['role'], $entry->ip, $entry->user_agent])->all())->toBe([
            ['impersonation_started', 'impersonator', '127.0.0.1', FIREFOX],
            ['impersonation_started', 'impersonated', null, null],
            ['impersonation_ended', 'impersonator', '127.0.0.1', FIREFOX],
            ['impersonation_ended', 'impersonated', null, null],
        ])
            ->and(SecurityEvent::query()->findOrFail($during)->only(['authenticatable_id', 'ip', 'user_agent']))->toEqual(['authenticatable_id' => $this->user->getKey(), 'ip' => null, 'user_agent' => null])
            ->and(SecurityEvent::query()->findOrFail($after)->only(['authenticatable_id', 'ip', 'user_agent']))->toEqual(['authenticatable_id' => $this->admin->getKey(), 'ip' => '127.0.0.1', 'user_agent' => FIREFOX]);
    });

    it('shows the start and end in both accounts\' activity', function () {
        impersonating();
        stopImpersonating();

        expect(Keyring::activity($this->user)->pluck('type')->all())->toEqualCanonicalizing(['impersonation_started', 'impersonation_ended'])
            ->and(Keyring::activity($this->admin)->pluck('type')->all())->toContain('impersonation_started', 'impersonation_ended')
            ->and(Keyring::unlistedActivityTypes())->toBe([]);
    });

    it('leaves them out of activity with impersonation.show_in_activity off, still logging them', function () {
        config(['keyring.impersonation.show_in_activity' => false, 'keyring.security_log.unlisted' => ['acme.token_issued']]);
        impersonating();
        stopImpersonating();

        expect(Keyring::activity($this->user)->all())->toBe([])
            ->and(Keyring::activity($this->admin)->pluck('type')->all())->not->toContain('impersonation_started', 'impersonation_ended')
            ->and(Keyring::unlistedActivityTypes())->toBe(['acme.token_issued', 'impersonation_started', 'impersonation_ended'])
            ->and(SecurityEvent::query()->whereIn('type', ['impersonation_started', 'impersonation_ended'])->count())->toBe(4);
    });

    // A package could list them without the app knowing, and hide an
    // impersonation from the user it was of.
    it('still shows them when only security_log.unlisted lists them', function () {
        config(['keyring.security_log.unlisted' => ['impersonation_started', 'impersonation_ended']]);
        impersonating();
        stopImpersonating();

        expect(Keyring::activity($this->user)->pluck('type')->all())->toEqualCanonicalizing(['impersonation_started', 'impersonation_ended'])
            ->and(Keyring::unlistedActivityTypes())->toBe([]);
    });

    it('logs the start and end on both accounts', function () {
        impersonating();
        stopImpersonating();

        $entries = SecurityEvent::query()->whereIn('type', ['impersonation_started', 'impersonation_ended'])->oldest('id')->get();
        $both = ['impersonator' => (string) $this->admin->getKey(), 'user' => (string) $this->user->getKey()];

        expect($entries->map(fn (SecurityEvent $entry) => [$entry->type, $entry->authenticatable_id, $entry->meta])->all())->toEqual([
            ['impersonation_started', $this->admin->getKey(), [...$both, 'role' => 'impersonator']],
            ['impersonation_started', $this->user->getKey(), [...$both, 'role' => 'impersonated']],
            ['impersonation_ended', $this->admin->getKey(), [...$both, 'reason' => 'stopped', 'returned' => true, 'role' => 'impersonator']],
            ['impersonation_ended', $this->user->getKey(), [...$both, 'reason' => 'stopped', 'returned' => true, 'role' => 'impersonated']],
        ])->and($entries->first()->severity->value)->toBe('notice');
    });

    it('logs the end on the user\'s account alone once the admin is gone', function () {
        impersonating();
        $this->admin->delete();

        stopImpersonating();

        expect(logEntry('impersonation_ended'))
            ->authenticatable_id->toBe($this->user->getKey())
            ->meta->toEqual(['impersonator' => null, 'user' => (string) $this->user->getKey(), 'reason' => 'impersonator_session_ended', 'returned' => false, 'role' => 'impersonated']);
    });

    it('logs why it ended', function () {
        impersonating();
        $this->travel(61)->minutes();

        $this->get('/whoami');

        expect(SecurityEvent::query()->where('type', 'impersonation_ended')->get()->pluck('meta.reason')->unique()->all())->toBe(['expired']);
    });

    it('still fires ImpersonationEnded, and logs the end, when nothing says which session it was', function () {
        $ended = new ArrayObject;
        Event::listen(fn (ImpersonationEnded $event) => $ended->append($event));
        impersonating();
        session()->put(Impersonation::KEY, Arr::except(session(Impersonation::KEY), 'handle'));
        session()->forget(Sessions::KEY);

        $this->get('/whoami')->assertRedirect('/dashboard');

        expect($ended)->toHaveCount(1)
            ->and($ended[0]->returned)->toBeTrue()
            ->and($ended[0]->handle)->toBeNull()
            ->and(SecurityEvent::query()->where('type', 'impersonation_ended')->count())->toBe(2);
    });

    it('fires events with who, why, and the impersonated session\'s handle', function () {
        Event::fake([ImpersonationStarted::class, ImpersonationEnded::class, RegisteredSessionEnded::class]);
        impersonating();
        $handle = app(Sessions::class)->handle(record(session(Sessions::KEY)));
        stopImpersonating();

        Event::assertDispatched(ImpersonationStarted::class, fn (ImpersonationStarted $event) => $event->impersonator->is($this->admin) && $event->user->is($this->user)
            && $event->handle === $handle);
        Event::assertDispatched(ImpersonationEnded::class, fn (ImpersonationEnded $event) => $event->impersonator->is($this->admin) && $event->user->is($this->user)
            && $event->reason === ImpersonationEndReason::Stopped && $event->returned && $event->handle === $handle);
        Event::assertDispatched(RegisteredSessionEnded::class, fn (RegisteredSessionEnded $event) => $event->reason === SessionEndReason::ImpersonationEnded && $event->userId === (string) $this->user->getKey()
            && $event->handle === $handle);
    });

    // A browser that never comes back is announced by its record's
    // RegisteredSessionEnded alone, with the handle ImpersonationStarted gave.
    it('names the impersonated session in RegisteredSessionEnded by the handle ImpersonationStarted gave, when the sweep ends it', function () {
        Event::fake([ImpersonationStarted::class, RegisteredSessionEnded::class]);
        impersonating();
        $this->travel(2)->hours();

        $this->artisan('keyring:sweep')->assertSuccessful();

        $started = Event::dispatched(ImpersonationStarted::class)->sole()[0];
        Event::assertDispatched(RegisteredSessionEnded::class, fn (RegisteredSessionEnded $event) => in_array($started->handle, $event->handles, true) && $event->reason === SessionEndReason::Expired);
    });

    it('logs a refused start on the impersonator\'s account, with why and the ID asked for', function (Closure $refuse, ImpersonationRefusal $reason) {
        adminSignsIn();

        $id = $refuse($this);

        expect(logEntry('impersonation_refused'))
            ->authenticatable_id->toBe($this->admin->getKey())
            ->severity->value->toBe('warning')
            ->meta->toEqual(['reason' => $reason->value, 'user' => $id]);
    })->with([
        'not allowed' => [function ($test) {
            Keyring::allowImpersonationWhen(fn () => false);
            impersonate($test->user)->assertForbidden();

            return (string) $test->user->getKey();
        }, ImpersonationRefusal::NotAllowed],
        'themselves' => [function ($test) {
            Keyring::allowImpersonationWhen(fn () => true);
            impersonate($test->admin)->assertForbidden();

            return (string) $test->admin->getKey();
        }, ImpersonationRefusal::Self],
        'an ID nobody has' => [function ($test) {
            impersonate(new User(['id' => 999]))->assertForbidden();

            return '999';
        }, ImpersonationRefusal::NotFound],
        'a session with no record' => [function ($test) {
            Route::middleware(['web', 'auth'])->post('/become/{id}', function (Request $request, string $id) {
                $request->session()->forget(Sessions::KEY);
                Keyring::impersonate($request, User::findOrFail($id));
            });
            $test->post('/become/'.$test->user->getKey())->assertForbidden();

            return (string) $test->user->getKey();
        }, ImpersonationRefusal::Unregistered],
        // Logged on the admin, not the user the browser is signed in as.
        'an ID nobody has, while impersonating' => [function ($test) {
            Route::middleware(['web', 'auth'])->post('/become-unknown', fn (Request $request) => app(Impersonation::class)->refuseUnknown($request, '999'));
            impersonate($test->user);
            $test->post('/become-unknown')->assertForbidden();

            return '999';
        }, ImpersonationRefusal::NotFound],
        'one already going' => [function ($test) {
            Route::middleware(['web', 'auth'])->post('/become/{id}', fn (Request $request, string $id) => Keyring::impersonate($request, User::findOrFail($id)));
            $other = User::create(['name' => 'Other', 'email' => 'other@example.com', 'password' => 'password', 'email_verified_at' => now()]);
            impersonate($test->user);
            $test->post('/become/'.$other->getKey())->assertForbidden();

            return (string) $other->getKey();
        }, ImpersonationRefusal::Impersonating],
    ]);

    it('answers an ID nobody has as it answers one that may not be impersonated, logging which it was', function () {
        Keyring::allowImpersonationWhen(fn (User $impersonator, User $user) => false);
        adminSignsIn();

        $missing = impersonate(new User(['id' => 999]), json: true)->assertForbidden()->assertJsonPath('status', 'impersonation-refused');
        $refused = impersonate($this->user, json: true)->assertForbidden();

        expect($missing->getContent())->toBe($refused->getContent())
            ->and(SecurityEvent::query()->where('type', 'impersonation_refused')->oldest('id')->get()->pluck('meta.reason')->all())->toBe(['not_found', 'not_allowed']);
    });

    // The user's record it saved first ends unannounced: nobody used it.
    it('refuses the start, leaving the admin where they were, when it can\'t be logged', function () {
        Exceptions::fake();
        Event::fake([ImpersonationStarted::class, RegisteredSessionEnded::class]);
        adminSignsIn();
        $own = session(Sessions::KEY);
        Schema::drop('keyring_events');

        impersonate($this->user)->assertServerError();

        expect($this->get('/whoami')->getContent())->toBe((string) $this->admin->getKey())
            ->and(Keyring::impersonating())->toBeFalse()
            ->and(session(Sessions::KEY))->toBe($own)
            ->and(app(SessionRegistry::class)->forUser($this->user))->toBeEmpty();
        Event::assertNotDispatched(ImpersonationStarted::class);
        Event::assertNotDispatched(RegisteredSessionEnded::class);
    });

    it('leaves the user\'s record it took back for the sweep not to announce either, when the start can\'t be logged', function () {
        Exceptions::fake();
        $announced = new ArrayObject;
        Event::listen(fn (RegisteredSessionEnded $event) => $announced->append($event));
        adminSignsIn();
        Schema::drop('keyring_events');

        impersonate($this->user)->assertServerError();

        $this->travel(Sweep::GRACE + 1)->seconds();
        $this->artisan('keyring:sweep')->assertSuccessful();

        expect($announced)->toBeEmpty();
    });

    // Laravel's guard fires its Authenticated event as the browser changes
    // hands, and an app's listener for it can throw.
    it('leaves the admin where they were, takes the user\'s record back and logs the end, when handing the browser over fails', function () {
        Exceptions::fake();
        Event::fake([ImpersonationStarted::class, ImpersonationEnded::class, RegisteredSessionEnded::class]);
        adminSignsIn();
        $own = session(Sessions::KEY);
        $proved = session(SessionAssurance::KEY);
        Event::listen(fn (LaravelAuthenticated $event) => $event->user->is($this->user) ? throw new RuntimeException('The audit service went away.') : null);

        impersonate($this->user)->assertServerError();

        expect(Keyring::impersonating())->toBeFalse()
            ->and(session(Sessions::KEY))->toBe($own)
            ->and(session(SessionAssurance::KEY))->toBe($proved)
            ->and(session()->has(Impersonation::KEY))->toBeFalse()
            ->and(Auth::id())->toBe($this->admin->getKey())
            ->and(app(SessionRegistry::class)->forUser($this->user))->toBeEmpty()
            ->and(record($own)->isActive(now()->getTimestamp()))->toBeTrue()
            ->and(SecurityEvent::query()->where('type', 'impersonation_started')->count())->toBe(2)
            ->and(SecurityEvent::query()->where('type', 'impersonation_ended')->oldest('id')->get()->map(fn (SecurityEvent $entry) => [$entry->authenticatable_id, $entry->meta])->all())->toEqual([
                [$this->admin->getKey(), ['impersonator' => (string) $this->admin->getKey(), 'user' => (string) $this->user->getKey(), 'reason' => 'failed', 'returned' => true, 'role' => 'impersonator']],
                [$this->user->getKey(), ['impersonator' => (string) $this->admin->getKey(), 'user' => (string) $this->user->getKey(), 'reason' => 'failed', 'returned' => true, 'role' => 'impersonated']],
            ])
            ->and(SecurityEvent::query()->where('type', 'impersonation_ended')->oldest('id')->pluck('ip')->all())->toBe(['127.0.0.1', null]);
        Exceptions::assertReported(fn (RuntimeException $e) => $e->getMessage() === 'The audit service went away.');
        Event::assertNotDispatched(ImpersonationStarted::class);
        Event::assertNotDispatched(ImpersonationEnded::class);
        Event::assertNotDispatched(RegisteredSessionEnded::class);

        // Still the admin on the next request, at the level they had.
        expect($this->get('/whoami')->getContent())->toBe((string) $this->admin->getKey());
        $this->get('/billing')->assertOk();
    });

    it('writes neither start entry when the second can\'t be written', function () {
        Exceptions::fake();
        adminSignsIn();
        SecurityEvent::saving(fn (SecurityEvent $event) => ($event->meta['role'] ?? null) === 'impersonated' ? throw new RuntimeException('The database went away.') : null);

        impersonate($this->user)->assertServerError();

        expect(SecurityEvent::query()->where('type', 'impersonation_started')->count())->toBe(0)
            ->and(Keyring::impersonating())->toBeFalse()
            ->and(app(SessionRegistry::class)->forUser($this->user))->toBeEmpty()
            ->and($this->get('/whoami')->getContent())->toBe((string) $this->admin->getKey());
    });

    it('refuses the start when the log channel can\'t take it, with the security log table off', function () {
        Exceptions::fake();
        Event::fake([ImpersonationStarted::class]);
        config(['keyring.features' => array_values(array_diff(config('keyring.features'), [Features::securityLog()]))]);
        adminSignsIn();
        $own = session(Sessions::KEY);
        Log::extend('broken', fn () => new Logger('broken', [new class extends AbstractProcessingHandler
        {
            protected function write(LogRecord $record): void
            {
                throw new RuntimeException('The log is down.');
            }
        }]));
        config(['logging.channels.broken' => ['driver' => 'broken'], 'keyring.security_log.channel' => 'broken']);

        impersonate($this->user)->assertServerError();

        expect($this->get('/whoami')->getContent())->toBe((string) $this->admin->getKey())
            ->and(Keyring::impersonating())->toBeFalse()
            ->and(session(Sessions::KEY))->toBe($own)
            ->and(app(SessionRegistry::class)->forUser($this->user))->toBeEmpty();
        Event::assertNotDispatched(ImpersonationStarted::class);
        Exceptions::assertReported(fn (RuntimeException $e) => $e->getMessage() === 'The log is down.');
    });

    it('writes the start to the log channel with the security log table off', function () {
        config(['keyring.features' => array_values(array_diff(config('keyring.features'), [Features::securityLog()]))]);
        adminSignsIn();
        $log = logTo('security');
        config(['keyring.security_log.channel' => 'security']);

        impersonate($this->user)->assertRedirect('/dashboard');

        expect(array_map(fn (array $entry) => [$entry[1], $entry[2]['meta']['role']], written($log)))->toBe([['impersonation_started', 'impersonator'], ['impersonation_started', 'impersonated']]);
    });

    it('logs the start before a listener of the app\'s that throws can stop it', function () {
        // Ahead of Keyring's own listeners, as an app's can be.
        $events = app('events');
        $listeners = (fn () => $this->listeners)->call($events);
        $listeners[ImpersonationStarted::class] ??= [];
        array_unshift($listeners[ImpersonationStarted::class], $events->makeListener(fn () => throw new RuntimeException('The mail server went away.')));
        (fn () => $this->listeners = $listeners)->call($events);
        adminSignsIn();

        impersonate($this->user)->assertServerError();

        expect(SecurityEvent::query()->where('type', 'impersonation_started')->oldest('id')->get()->pluck('meta.role')->all())->toBe(['impersonator', 'impersonated']);
    });

    it('logs the end when signing out fails after the sessions have ended', function () {
        Exceptions::fake();
        Event::fake([ImpersonationEnded::class]);
        $own = impersonating();
        $this->user->forceFill(['remember_token' => 'the users own'])->save();
        app(SessionRegistry::class)->revoke($own);

        // Ending the two records works, and signing the browser out of the
        // impersonated one again doesn't.
        registryThatGoesAway(works: 2);

        stopImpersonating()->assertServerError();

        Event::assertDispatched(ImpersonationEnded::class, fn (ImpersonationEnded $event) => $event->reason === ImpersonationEndReason::ImpersonatorSessionEnded && ! $event->returned);
        expect(Auth::guard('web')->check())->toBeFalse()
            ->and($this->user->fresh()->remember_token)->toBe('the users own');
    });

    // The admin's record didn't move, so a copy of the session from while
    // impersonating could still go back to it. It ends instead, and the
    // browser is signed out, as when handing it back fails.
    it('logs the end, ends the admin\'s session and signs out, when moving the admin\'s record fails on the way back', function () {
        Exceptions::fake();
        Event::fake([ImpersonationEnded::class]);
        $own = impersonating();
        registryThatGoesAway(works: 0, method: 'replace');

        stopImpersonating()->assertServerError();

        Event::assertDispatchedTimes(ImpersonationEnded::class, 1);
        Event::assertDispatched(ImpersonationEnded::class, fn (ImpersonationEnded $event) => $event->reason === ImpersonationEndReason::Stopped && ! $event->returned);
        expect(Auth::guard('web')->check())->toBeFalse()
            ->and(record($own)->revokedAt)->not->toBeNull()
            ->and(record($own)->replacedBy)->toBeNull();
    });

    // The session can't be handed back, and nothing is parked to go back
    // with any more, so it ends as if it couldn't go back: the admin's
    // session too, and the browser is signed out, once.
    it('says it didn\'t go back, and signs the browser out, when handing it back throws', function () {
        $fail = new ArrayObject;
        app('session')->extend('failing', fn () => new class($fail) extends ArraySessionHandler
        {
            public function __construct(protected ArrayObject $fail)
            {
                parent::__construct(120);
            }

            public function destroy($sessionId): bool
            {
                throw_if(count($this->fail) > 0, RuntimeException::class, 'The session store went away.');

                return parent::destroy($sessionId);
            }
        });
        config(['session.driver' => 'failing']);
        app('session')->forgetDrivers();
        app()->forgetInstance('session.store');
        Exceptions::fake();
        Event::fake([ImpersonationEnded::class]);
        $own = impersonating();
        $fail->append(true);

        stopImpersonating()->assertServerError();

        expect(Auth::guard('web')->check())->toBeFalse()
            ->and(record($own)->revokedAt)->not->toBeNull();

        $fail->exchangeArray([]);
        Auth::forgetGuards();
        $this->get('/whoami')->assertRedirect('/login');

        Event::assertDispatchedTimes(ImpersonationEnded::class, 1);
        Event::assertDispatched(ImpersonationEnded::class, fn (ImpersonationEnded $event) => $event->reason === ImpersonationEndReason::Stopped && ! $event->returned);
    });

    it('names the user who was impersonated, whoever the app has signed in since', function () {
        $other = User::create(['name' => 'Other', 'email' => 'other@example.com', 'password' => 'password', 'email_verified_at' => now()]);
        Route::middleware(['web', 'auth'])->post('/switch', function (Request $request) use ($other) {
            Auth::login($other);

            return Keyring::stopImpersonating($request) === null ? 'signed out' : 'back';
        });
        Event::fake([ImpersonationEnded::class]);
        impersonating();

        expect($this->post('/switch')->getContent())->toBe('signed out')
            ->and(Auth::guard('web')->check())->toBeFalse();
        Event::assertDispatched(ImpersonationEnded::class, fn (ImpersonationEnded $event) => $event->user->is($this->user) && $event->impersonator->is($this->admin)
            && $event->reason === ImpersonationEndReason::Lost && ! $event->returned);
    });
});

describe('the session record', function () {
    it('keeps the impersonator\'s session ID off the server with the rest of its IDs', function () {
        impersonating();

        expect(record(session(Sessions::KEY))->withoutIds()->impersonatorSession)->toBeNull();
    });

    it('needs the migration only for an impersonated session, so signing in works before it', function () {
        Schema::table('keyring_sessions', fn (Blueprint $table) => $table->dropColumn(['impersonator_id', 'impersonator_type', 'impersonator_session']));

        adminSignsIn();

        expect(record(session(Sessions::KEY))->isImpersonated())->toBeFalse();
    });

    it('says the migration is missing on the first start without it, starting nothing', function () {
        Schema::table('keyring_sessions', fn (Blueprint $table) => $table->dropColumn(['impersonator_id', 'impersonator_type', 'impersonator_session']));
        adminSignsIn();
        $this->withoutExceptionHandling();

        expect(fn () => impersonate($this->user))->toThrow(LogicException::class, 'The [keyring_sessions] table is missing the columns Keyring keeps an impersonation in (impersonator_id, impersonator_type, impersonator_session). Publish and run Keyring\'s migrations: php artisan keyring:install, then php artisan migrate.')
            ->and(Auth::id())->toBe($this->admin->getKey())
            ->and(Keyring::impersonating())->toBeFalse()
            ->and(SecurityEvent::query()->where('type', 'impersonation_started')->count())->toBe(0);
    });

    it('asks the database whether the migration ran once, then takes the cache\'s word for a few minutes', function () {
        Route::middleware(['web', 'auth'])->post('/become/{id}', fn (Request $request, string $id) => Keyring::impersonate($request, User::findOrFail($id)));
        $become = fn () => $this->post('/become/'.$this->user->getKey());
        adminSignsIn();
        $schema = 0;
        DB::listen(function ($query) use (&$schema) {
            $schema += (int) str_contains($query->sql, 'pragma_table_xinfo');
        });

        $become()->assertOk();

        expect($schema)->toBe(1);

        // The same process again, which has it in hand.
        stopImpersonating();
        $schema = 0;
        $become()->assertOk();
        stopImpersonating();

        expect($schema)->toBe(0);

        // Another process: it takes the cache's word, and asks nothing.
        app()->forgetInstance(SessionRegistryManager::class);
        Schema::table('keyring_sessions', fn (Blueprint $table) => $table->dropColumn(['impersonator_id', 'impersonator_type', 'impersonator_session']));
        $schema = 0;
        $this->withoutExceptionHandling();

        expect(fn () => $become())->toThrow(QueryException::class)
            ->and($schema)->toBe(0);

        // Once that's gone, it asks again, and a no isn't kept.
        $this->travel(Sweep::SCHEMA_CACHED_FOR + 1)->seconds();
        app()->forgetInstance(SessionRegistryManager::class);

        expect(fn () => $become())->toThrow(LogicException::class)
            ->and(fn () => $become())->toThrow(LogicException::class)
            ->and($schema)->toBe(2);
    });
});
