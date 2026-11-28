<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Attributes\Table;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\QueryException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Timebox;
use Illuminate\Testing\TestResponse;
use Keyring\Activity\SecurityLog;
use Keyring\Contracts\LocatesIps;
use Keyring\Contracts\SessionRegistry;
use Keyring\Contracts\Signal;
use Keyring\Devices\UserAgent;
use Keyring\Events\AuthenticatorAdded;
use Keyring\Events\RiskAssessed;
use Keyring\Facades\Keyring;
use Keyring\Features;
use Keyring\Login\Requirement;
use Keyring\Models\Authenticator;
use Keyring\Models\PendingChange;
use Keyring\Models\SecurityEvent;
use Keyring\Notifications\AuthenticatorAdded as AuthenticatorAddedNotice;
use Keyring\Notifications\NewDevice as NewDeviceNotice;
use Keyring\Notifications\PasswordChanged;
use Keyring\Notifications\SecondFactorFailed;
use Keyring\Notifications\SuspiciousActivity;
use Keyring\Risk\Action;
use Keyring\Risk\Assessment;
use Keyring\Risk\Checkpoint;
use Keyring\Risk\Finding;
use Keyring\Risk\Risk;
use Keyring\Risk\RiskEngine;
use Keyring\Risk\RiskLocks;
use Keyring\Risk\Signals\CredentialStuffing;
use Keyring\Risk\Signals\ImpossibleTravel;
use Keyring\Risk\Signals\InactiveAccount;
use Keyring\Risk\Signals\NewCountry;
use Keyring\Risk\Signals\NewDevice;
use Keyring\Risk\Signals\RecentlyChangedRecovery;
use Keyring\Risk\Signals\RepeatedFactorFailures;
use Keyring\Risk\Signals\SessionFingerprintChanged;
use Keyring\Risk\Signals\SuccessAfterFailures;
use Keyring\Sessions\Sessions;
use Keyring\Tests\Fixtures\User;

class FakeLocator implements LocatesIps
{
    public ?array $location = null;

    public ?Throwable $failure = null;

    public function locate(Request $request): ?array
    {
        return $this->failure === null ? $this->location : throw $this->failure;
    }
}

class AlwaysRisky implements Signal
{
    public function __construct(public int $score = 95) {}

    public function assess(Assessment $assessment): ?Finding
    {
        return new Finding('always', $this->score, 'Testing.');
    }

    public function checkpoints(): array
    {
        return [Checkpoint::Login];
    }
}

beforeEach(function () {
    Notification::fake();
    $this->locator = new FakeLocator;
    $this->app->instance(LocatesIps::class, $this->locator);

    Route::middleware(['web', 'auth'])->get('/home', fn () => 'home');
    Route::middleware(['web', 'auth', 'keyring.fresh:15m'])->get('/sensitive', fn () => 'sensitive');

    $this->user = taylor();
});

function signInAs(string $agent = FIREFOX, string $password = 'password', array $cookies = []): TestResponse
{
    return test()->withHeader('User-Agent', $agent)->withCookies($cookies)
        ->post('/login', ['email' => 'taylor@example.com', 'password' => $password]);
}

it('logs an action that only locks as a lock', function () {
    expect(Action::allow()->lockFor('1h')->name())->toBe('locked')
        ->and(Action::deny()->lockFor('1h')->name())->toBe('denied')
        ->and(Action::allow()->name())->toBe('allowed');
});

it('takes as long to refuse a locked account with the right password as with a wrong one', function () {
    app(RiskLocks::class)->lock($this->user, 600);

    $timebox = new class extends Timebox
    {
        /** @var list<bool> */
        public static array $returnedEarly = [];

        public function call(callable $callback, int $microseconds)
        {
            $result = parent::call($callback, 0);
            self::$returnedEarly[] = $this->earlyReturn;

            return $result;
        }
    };
    $this->app->bind(Timebox::class, $timebox::class);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'wrong'])->assertSessionHasErrors('email');
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertSessionHasErrors('email');
    $this->assertGuest();

    expect($timebox::$returnedEarly)->toBe([false, false]);
});

it('asks for another factor when risk is medium', function () {
    Keyring::risk()->signals([NewDevice::class, NewCountry::class]);
    Keyring::require(Requirement::aal1());
    Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    $this->locator->location = ['country' => 'GB'];

    $cookie = signInAs()->assertRedirect('/dashboard')->getCookie('known_device')->getValue();
    $this->post('/logout');

    $this->locator->location = ['country' => 'BR'];

    signInAs()->assertRedirect(route('keyring.login.challenge'));
    $this->assertGuest();

    expect(SecurityEvent::where('type', 'risk_step_up')->exists())->toBeTrue();
});

it('does not turn away a password-only user when risk steps up under a policy out of reach', function () {
    Keyring::require(Requirement::aal2()->phishingResistant()->ifEnrolled());
    Keyring::risk()->signals([new AlwaysRisky(50)]);

    signInAs()->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($this->user);
});

it('does not ask for more on a familiar device and country', function () {
    Keyring::require(Requirement::aal1());
    Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    $this->locator->location = ['country' => 'GB'];

    $cookie = signInAs()->getCookie('known_device')->getValue();
    $this->post('/logout');

    // Each enough on its own to ask for the second factor, had it fired.
    Keyring::risk()->signals([new NewDevice(score: 30), NewCountry::class]);

    signInAs(cookies: ['known_device' => $cookie])->assertRedirect('/dashboard');
});

/**
 * Sign in and leave that session alive, with a remember token and a trusted
 * device, as if the owner were still using it from another browser.
 */
function liveOwnerSession(): string
{
    Keyring::risk()->signals([]);
    signInAs();
    $session = session(Sessions::KEY);

    test()->user->forceFill(['remember_token' => 'owners-token'])->save();
    test()->user->devices()->firstOrFail()->forceFill(['trusted_until' => now()->addDay()])->save();

    test()->flushSession();
    app('auth')->forgetGuards();

    return $session;
}

function expectOwnerStillSignedIn(string $session): void
{
    expect(app(SessionRegistry::class)->find($session)->revokedAt)->toBeNull()
        ->and(test()->user->fresh()->remember_token)->toBe('owners-token')
        ->and(test()->user->devices()->whereNotNull('trusted_until')->exists())->toBeTrue();
}

it('refuses critical risk with the usual error, tells the owner and leaves them signed in', function () {
    sendNotifications();
    $existing = liveOwnerSession();
    Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    Event::listen(RiskAssessed::class, function (RiskAssessed $event) use (&$assessed) {
        $assessed = $event;
    });

    Keyring::risk()->signals([new AlwaysRisky]);
    signInAs()->assertSessionHasErrors(['email' => __('auth.failed')]);

    $this->assertGuest();
    expectOwnerStillSignedIn($existing);
    expect($assessed->checkpoint)->toBe(Checkpoint::Login)
        ->and($assessed->action->deny)->toBeTrue()
        ->and($assessed->action->revokeSessions)->toBeFalse()
        ->and(SecurityEvent::where('type', 'risk_denied')->exists())->toBeTrue();
    Notification::assertSentTo($this->user, SuspiciousActivity::class);
});

it('does not let a custom responder sign the owner out from a login attempt', function () {
    $existing = liveOwnerSession();

    Keyring::risk()->signals([new AlwaysRisky])->respond(fn () => Action::deny()->revokeAllSessions()->notify());
    signInAs()->assertSessionHasErrors('email');

    expectOwnerStillSignedIn($existing);
    expect(SecurityEvent::where('type', 'risk_denied')->exists())->toBeTrue();
});

it('still revokes everything when a signed-in session is critical', function () {
    $existing = liveOwnerSession();

    Keyring::risk()->signals([new SessionFingerprintChanged(score: 95)]);
    signInAs()->assertRedirect('/dashboard');
    $current = session(Sessions::KEY);

    $this->withHeader('User-Agent', CHROME)->get('/home')->assertRedirect('/login');

    $this->assertGuest();
    expect(app(SessionRegistry::class)->find($existing)->revokedAt)->not->toBeNull()
        ->and(app(SessionRegistry::class)->find($current)->revokedAt)->not->toBeNull()
        ->and($this->user->fresh()->remember_token)->not->toBe('owners-token')
        ->and($this->user->devices()->whereNotNull('trusted_until')->exists())->toBeFalse();
});

it('can lock sign in for a while', function () {
    Keyring::risk()->signals([new AlwaysRisky(40)])->respond(fn ($risk) => $risk->isElevated() ? Action::deny()->lockFor('1h') : Action::allow());

    signInAs()->assertSessionHasErrors('email');

    Keyring::risk()->signals([]);
    signInAs()->assertSessionHasErrors('email');

    $this->travel(61)->minutes();
    signInAs()->assertRedirect('/dashboard');
});

it('lifts a risk lock when the password is reset', function () {
    Keyring::risk()->signals([new AlwaysRisky(40)])->respond(fn ($risk) => $risk->isElevated() ? Action::deny()->lockFor('1h') : Action::allow());
    signInAs()->assertSessionHasErrors('email');
    Keyring::risk()->signals([]);

    $this->post(route('password.update'), [
        'token' => Password::broker()->createToken(User::sole()),
        'email' => User::sole()->email,
        'password' => 'a much longer passphrase',
        'password_confirmation' => 'a much longer passphrase',
    ])->assertRedirect(route('login'));

    $this->post('/login', ['email' => User::sole()->email, 'password' => 'a much longer passphrase'])->assertRedirect('/dashboard');
});

it('spots impossible travel', function () {
    Keyring::risk()->signals([NewDevice::class, NewCountry::class, ImpossibleTravel::class]);
    $this->locator->location = ['country' => 'GB', 'latitude' => 51.5, 'longitude' => -0.12];
    signInAs()->assertRedirect('/dashboard');
    $this->post('/logout');

    $this->travel(10)->minutes();
    $this->locator->location = ['country' => 'AU', 'latitude' => -33.87, 'longitude' => 151.21];

    signInAs()->assertSessionHasErrors('email');
    expect(SecurityEvent::where('type', 'risk_denied')->latest('created_at')->first()->meta['reasons'])->toHaveCount(3);
});

it('finds nothing about where a sign in is from when the locator can\'t place it', function () {
    // Scored to refuse the sign in if either fired.
    Keyring::risk()->signals([new NewCountry(score: 95), new ImpossibleTravel(score: 95)]);
    $this->locator->location = ['country' => 'GB', 'latitude' => 51.5, 'longitude' => -0.12];
    signInAs()->assertRedirect('/dashboard');
    $this->post('/logout');

    $this->travel(10)->minutes();
    $this->locator->location = null;

    signInAs()->assertRedirect('/dashboard');
    $this->assertAuthenticatedAs($this->user);
});

it('asks again before sensitive pages when the session moves browser', function () {
    Keyring::risk()->signals([SessionFingerprintChanged::class]);
    signInAs();

    $this->withHeader('User-Agent', FIREFOX)->get('/sensitive')->assertOk();

    $this->withHeader('User-Agent', CHROME)->get('/home')->assertOk();
    $this->withHeader('User-Agent', CHROME)->get('/sensitive')->assertRedirect(route('keyring.confirm.challenge'));
});

// sessions.end_on_lapse ends a session when what it signed in with has gone,
// and a step-up is what makes it go.
it('ends the session instead where a session ends with the level it signed in at', function (bool $endOnLapse) {
    config(['keyring.sessions.end_on_lapse' => $endOnLapse]);
    Keyring::risk()->signals([SessionFingerprintChanged::class]);
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    $this->withHeader('User-Agent', FIREFOX)->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->withHeader('User-Agent', FIREFOX)->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)])->assertRedirect('/dashboard');
    $this->withHeader('User-Agent', FIREFOX)->get('/home')->assertOk();

    $moved = $this->withHeader('User-Agent', CHROME)->get('/home');

    if (! $endOnLapse) {
        $moved->assertOk();
        $this->assertAuthenticated();

        return;
    }

    $moved->assertRedirect('/login');
    $this->assertGuest();
    expect(SecurityEvent::where('type', 'session_ended')->sole()->meta['reason'])->toBe('risk');

    // Not left for the timeouts to find, a day later.
    $this->travel(2)->hours();
    $this->withHeader('User-Agent', CHROME)->get('/home')->assertRedirect('/login');
})->with(['on' => true, 'off' => false]);

it('does not let a confirmation started before the session moved browser keep its proofs', function () {
    Keyring::risk()->signals([SessionFingerprintChanged::class]);
    Route::middleware(['web', 'auth', 'keyring:aal2'])->get('/billing', fn () => 'billing');
    signInAs();
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    $this->withHeader('User-Agent', FIREFOX)->get('/billing')->assertRedirect(route('keyring.confirm.challenge'));

    $this->withHeader('User-Agent', CHROME)->get('/home')->assertOk();
    $this->withHeader('User-Agent', CHROME)->get('/billing')->assertRedirect(route('keyring.confirm.challenge'));
    $this->withHeader('User-Agent', CHROME)->post(route('keyring.confirm.verify', 'totp'), ['code' => totpCode($totp->secret)])
        ->assertRedirect(route('keyring.confirm.challenge'));

    $this->withHeader('User-Agent', CHROME)->get('/billing')->assertRedirect(route('keyring.confirm.challenge'));
});

it('has nothing to compare when the session signed in without a user agent', function () {
    Keyring::risk()->signals([SessionFingerprintChanged::class])->respond(fn ($risk, $at) => $risk->isElevated() ? Action::reauthenticate() : Action::allow());
    signInAs(agent: '')->assertRedirect('/dashboard');

    $this->withHeader('User-Agent', CHROME)->get('/home')->assertOk();
    $this->assertAuthenticatedAs($this->user);
});

it('can sign a hijacked session out', function () {
    Keyring::risk()->signals([SessionFingerprintChanged::class])->respond(fn ($risk, $at) => $risk->isElevated() ? Action::reauthenticate() : Action::allow());
    signInAs();

    $this->withHeader('User-Agent', CHROME)->get('/home')->assertRedirect('/login');
    $this->assertGuest();
});

it('locks out for longer each time', function () {
    config(['keyring.limits.per_account' => 2]);

    signInAs(password: 'nope');
    signInAs(password: 'nope');
    signInAs()->assertSessionHasErrors('email');

    $this->travel(61)->seconds();
    signInAs(password: 'nope');
    signInAs(password: 'nope');

    $this->travel(61)->seconds();
    signInAs()->assertSessionHasErrors('email');

    $this->travel(60)->seconds();
    signInAs()->assertRedirect('/dashboard');
});

it('logs security events and shows recent activity', function () {
    signInAs();
    $this->post('/logout');

    $types = Keyring::activity($this->user)->pluck('type');

    expect($types->first())->toBe('signed_out')
        ->and($types->all())->toContain('signed_in', 'new_device');
});

it('keeps "was this you?" for a browser the account has used before', function () {
    $device = signInAs()->getCookie('known_device')->getValue();
    $this->post('/logout');
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    $this->travel(1)->minutes();
    signInAs(CHROME);
    $this->post(route('keyring.login.verify', 'totp'), ['code' => '000000']);
    $newcomer = $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)])
        ->assertSessionHas('keyring.alerts', [])
        ->getCookie('known_device')->getValue();
    $this->post('/logout');

    // Nor on that browser's second visit: it was first seen after the
    // failure, so it could be whoever made it.
    $this->travel(1)->minutes();
    signInAs(CHROME, cookies: ['known_device' => $newcomer]);
    $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)])
        ->assertSessionHas('keyring.alerts', []);
    $this->post('/logout');

    $this->travel(1)->minutes();
    signInAs(cookies: ['known_device' => $device]);
    $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)])
        ->assertSessionHas('keyring.alerts', fn ($alerts) => $alerts[0]['type'] === 'second_factor_failed');

    expect(app(SecurityLog::class)->pullAlerts($this->user))->toBeEmpty();
});

it('sends no security email the app turned off', function () {
    Keyring::notifications(['new_device' => null]);
    signInAs();
    Notification::assertNothingSent();
    $this->post('/logout');

    sendNotifications(['new_device']);
    $this->user->devices()->delete();
    signInAs();

    Notification::assertSentTo($this->user, NewDeviceNotice::class, fn (NewDeviceNotice $notice) => $notice->url !== null);
});

it('sends whatever notification the app registers, with what the notice has to say', function () {
    Keyring::notifications(['new_device' => OwnNewDevice::class]);
    $this->user->devices()->delete();

    signInAs();

    Notification::assertSentTo($this->user, OwnNewDevice::class, fn (OwnNewDevice $notice, array $channels) => $channels === ['database']
        && str_contains($notice->url, '/report')
        && $notice->device === 'Firefox on Windows'
        && $notice->ip === '127.0.0.1');
});

it('stops sending a notice the app takes out again', function () {
    sendNotifications(['new_device']);
    Keyring::notifications(['new_device' => null]);
    $this->user->devices()->delete();

    signInAs();

    Notification::assertNothingSent();
});

it('refuses a notification type it doesn\'t send', function () {
    Keyring::notifications(['new_devise' => OwnNewDevice::class]);
})->throws(InvalidArgumentException::class, 'Unknown notification types: new_devise');

it('shows a device and IP address as plain text in the email', function () {
    $notice = new PasswordChanged(when: 'now', device: '[Firefox](https://evil.example/d)', ip: '<https://evil.example/i>');

    $mail = renderedMail($notice->toMail($this->user));

    expect($mail['html'])->not->toMatch('/<[^>]*(href|src)="[^"]*evil\.example/')
        ->toContain('Device: [Firefox](https://evil.example/d)')
        ->toContain('IP address: &lt;https://evil.example/i&gt;')
        ->and($mail['text'])->toContain('Device: [Firefox](https://evil.example/d)')
        ->toContain('IP address: <https://evil.example/i>');
});

it('shows a location from the locator as plain text in the email', function () {
    sendNotifications();
    Keyring::risk()->signals([new NewCountry(95)]);
    $this->locator->location = ['country' => 'GB'];
    signInAs()->assertRedirect('/dashboard');
    $this->post('/logout');

    $this->locator->location = ['country' => '[Amsterdam](https://evil.example/l)'];
    signInAs()->assertSessionHasErrors('email');

    $notice = Notification::sent($this->user, SuspiciousActivity::class)->sole();
    $mail = renderedMail($notice->toMail($this->user));

    expect($mail['html'])->not->toMatch('/<[^>]*(href|src)="[^"]*evil\.example/')
        ->toContain('Signing in from a new country ([Amsterdam](https://evil.example/l)).')
        ->and($mail['text'])->toContain('Signing in from a new country ([Amsterdam](https://evil.example/l)).');
});

it('hands the app\'s notification one clean, capped line, whatever was sent', function (string $name, string $expected) {
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->make(['name' => $name]);

    AuthenticatorAdded::dispatch($this->user, $totp);

    $notice = Notification::sent($this->user, AuthenticatorAddedNotice::class)->sole();

    expect($notice->name)->toBe($expected)
        ->and(renderedMail($notice->toMail($this->user))['text'])->toContain('was added as a way to sign in');
})->with([
    'invalid utf-8' => ["Key\xFF", 'Key?'],
    'mostly whitespace' => ['Fire'.str_repeat(' ', 10000).'fox', 'Fire...'],
    'very long' => [str_repeat('a', 1000), str_repeat('a', 500).'...'],
    'several lines' => ["[Not you?](https://evil.example/x)\n\nRobert's key", "[Not you?](https://evil.example/x) Robert's key"],
]);

it('shows a name someone typed as plain text in the email', function () {
    $notice = new AuthenticatorAddedNotice(when: 'now', name: "[Not you?](https://evil.example/x) Robert's key");
    $mail = renderedMail($notice->toMail($this->user));

    expect($mail['html'])->not->toMatch('/<[^>]*(href|src)="[^"]*evil\.example/')
        ->toContain("[Not you?](https://evil.example/x) Robert's key")
        ->and($mail['text'])->toContain("[Not you?](https://evil.example/x) Robert's key");
});

it('tells the user when someone gets their password but not the second factor', function () {
    sendNotifications();
    Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    signInAs();
    $this->post(route('keyring.login.verify', 'totp'), ['code' => '000000']);

    Notification::assertSentTo($this->user, SecondFactorFailed::class);
});

it('signs in without a location when the locator throws, and reports it once', function () {
    Exceptions::fake();
    $this->locator->failure = new RuntimeException('GeoIP database missing');

    signInAs()->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($this->user);
    expect($this->user->devices()->sole()->location)->toBeNull();
    Exceptions::assertReportedCount(1);
    Exceptions::assertReported(fn (RuntimeException $e) => $e->getMessage() === 'GeoIP database missing');
});

it('signs in without a location when the locator returns one that can\'t be stored', function (array $location) {
    $this->locator->location = $location;

    signInAs()->assertRedirect('/dashboard');

    expect($this->user->devices()->sole()->location)->toBeNull();
})->with([
    'infinite coordinate' => [['latitude' => INF]],
    'broken text' => [['city' => "Amst\xFFerdam"]],
]);

it('stores a user agent with broken bytes as valid text', function () {
    $userAgent = UserAgent::from(Request::create('/', server: ['HTTP_USER_AGENT' => "Firefox\xFF"]));

    expect(mb_check_encoding($userAgent, 'UTF-8'))->toBeTrue();
});

it('signs in and still sends the new device email when the security log is down', function () {
    Exceptions::fake();
    sendNotifications();
    Keyring::useSecurityEventModel(UnavailableSecurityEvent::class);

    signInAs()->assertRedirect('/dashboard');

    $this->get('/home')->assertOk();
    Notification::assertSentTo($this->user, NewDeviceNotice::class);
    Exceptions::assertReported(QueryException::class);
});

it('still refuses a wrong password when the security log is down', function () {
    Exceptions::fake();
    Keyring::useSecurityEventModel(UnavailableSecurityEvent::class);

    signInAs(password: 'wrong')->assertSessionHasErrors('email');

    $this->assertGuest();
    Exceptions::assertReported(QueryException::class);
});

it('still refuses a sign in the risk engine denies when the security log is down', function () {
    Exceptions::fake();
    Keyring::useSecurityEventModel(UnavailableSecurityEvent::class);
    Keyring::risk()->signals([new AlwaysRisky]);

    signInAs()->assertSessionHasErrors('email');

    $this->assertGuest();
    Exceptions::assertReported(QueryException::class);
});

it('finds nothing in a security log it cannot read', function () {
    Exceptions::fake();
    Keyring::useSecurityEventModel(UnavailableSecurityEvent::class);

    $finding = app(RepeatedFactorFailures::class)->assess(new Assessment(Checkpoint::Login, request(), $this->user));

    expect($finding)->toBeNull();
    Exceptions::assertReported(QueryException::class);
});

it('keeps the caller\'s transaction usable when a security log write fails', function () {
    Exceptions::fake();
    Keyring::useSecurityEventModel(UnavailableSecurityEvent::class);

    DB::transaction(function () {
        expect(app(SecurityLog::class)->record('signed_in', $this->user))->toBeNull();

        $this->user->update(['name' => 'Still Taylor']);
    });

    expect($this->user->fresh()->name)->toBe('Still Taylor');
});

it('does not bypass protection when the bypass cannot be logged', function () {
    Keyring::useSecurityEventModel(UnavailableSecurityEvent::class);

    expect(fn () => Keyring::withoutProtection(fn () => $this->user->update(['email' => 'admin-set@example.com']), reason: 'support ticket 42'))
        ->toThrow(QueryException::class);

    expect($this->user->fresh()->email)->toBe('taylor@example.com');
});

it('does not swallow a failure in something that decides the sign in', function () {
    Exceptions::fake();
    Keyring::risk()->signals([new class implements Signal
    {
        public function assess(Assessment $assessment): ?Finding
        {
            throw new RuntimeException('Signal broke');
        }

        public function checkpoints(): array
        {
            return [Checkpoint::Login];
        }
    }]);

    signInAs()->assertServerError();

    $this->assertGuest();
});

// Every query fails, as if the table were gone, without DDL that MySQL would commit.
#[Table('keyring_events_unavailable')]
class UnavailableSecurityEvent extends SecurityEvent {}

/**
 * An app's own notification, taking only what it wants of what Keyring passes.
 */
class OwnNewDevice extends Illuminate\Notifications\Notification
{
    public function __construct(public string $url, public ?string $device = null, public ?string $ip = null) {}

    public function via(object $notifiable): array
    {
        return ['database'];
    }
}

it('runs no signals until the app picks some', function () {
    expect(new RiskEngine()->signalsFor(Checkpoint::Login))->toBe([])
        ->and(new RiskEngine()->signalsFor(Checkpoint::Request))->toBe([]);
});

it('adds signals to the ones the app already picked', function () {
    Keyring::risk()->signals([NewDevice::class])->push(new AlwaysRisky);

    expect(Keyring::risk()->signalsFor(Checkpoint::Login))
        ->sequence(
            fn ($signal) => $signal->toBeInstanceOf(NewDevice::class),
            fn ($signal) => $signal->toBeInstanceOf(AlwaysRisky::class),
        );

    signInAs()->assertSessionHasErrors('email');
    $this->assertGuest();
});

it('doesn\'t call every browser new when devices are off', function () {
    // Scored to refuse the sign in if it fired.
    Keyring::risk()->signals([new NewDevice(score: 90)]);
    config(['keyring.features' => []]);

    signInAs()->assertRedirect('/dashboard');
    $this->assertAuthenticatedAs($this->user);
});

describe('a sign in after a long quiet period', function () {
    /**
     * Sign in, then leave the account alone for that long.
     */
    function lastSignedIn(int $daysAgo): string
    {
        $cookie = signInAs()->assertRedirect('/dashboard')->getCookie('known_device')->getValue();
        test()->post('/logout');
        test()->travel($daysAgo)->days();

        return $cookie;
    }

    it('is found after ninety days, and asks for the second factor', function () {
        Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
        Keyring::require(Requirement::aal1());
        Keyring::risk()->signals([InactiveAccount::class]);
        $cookie = lastSignedIn(daysAgo: 91);

        Event::listen(RiskAssessed::class, function (RiskAssessed $event) use (&$assessed) {
            $assessed = $event;
        });

        signInAs(cookies: ['known_device' => $cookie])->assertRedirect(route('keyring.login.challenge'));

        expect($assessed->risk->has('inactive_account'))->toBeTrue()
            ->and($assessed->risk->score)->toBe(30)
            ->and($assessed->risk->reasons())->toBe(['The first sign in for 91 days.']);
    });

    // OWASP ASVS 5.0.0, 6.3.5: the owner hears of it without the app
    // writing a response of its own.
    it('is told to the owner, who may have nothing more to prove', function () {
        Keyring::risk()->signals([InactiveAccount::class]);
        $cookie = lastSignedIn(daysAgo: 91);

        signInAs(cookies: ['known_device' => $cookie])->assertRedirect('/dashboard');

        $notice = Notification::sent($this->user, SuspiciousActivity::class)->sole();

        expect($notice->reasons)->toBe('The first sign in for 91 days.');
    });

    it('is not found before then', function () {
        Keyring::risk()->signals([InactiveAccount::class])->respond(fn (Risk $risk) => $risk->has('inactive_account') ? Action::deny() : Action::allow());
        $cookie = lastSignedIn(daysAgo: 89);

        signInAs(cookies: ['known_device' => $cookie])->assertRedirect('/dashboard');
    });

    it('takes the period the app gives it', function () {
        Keyring::risk()->signals([app()->make(InactiveAccount::class, ['after' => '30d', 'score' => 95])]);
        lastSignedIn(daysAgo: 31);

        signInAs()->assertSessionHasErrors('email');
        $this->assertGuest();
    });

    it('goes by the account, whichever browser it comes back in', function () {
        Keyring::risk()->signals([app()->make(InactiveAccount::class, ['score' => 95])]);
        lastSignedIn(daysAgo: 91);

        signInAs(CHROME)->assertSessionHasErrors('email');
    });

    it('is only quiet until the next sign in', function () {
        Keyring::risk()->signals([InactiveAccount::class])->respond(fn (Risk $risk) => $risk->has('inactive_account') ? Action::allow()->notify() : Action::allow());
        sendNotifications(['suspicious_activity']);
        $cookie = lastSignedIn(daysAgo: 91);

        signInAs(cookies: ['known_device' => $cookie])->assertRedirect('/dashboard');
        $this->post('/logout');
        signInAs(cookies: ['known_device' => $cookie])->assertRedirect('/dashboard');

        Notification::assertSentToTimes($this->user, SuspiciousActivity::class, 1);
    });

    it('says nothing about an account it has never seen sign in', function () {
        Keyring::risk()->signals([app()->make(InactiveAccount::class, ['score' => 95])]);
        $this->user->forceFill(['created_at' => now()->subYears(2)])->save();

        signInAs()->assertRedirect('/dashboard');
    });

    it('does not call an account quiet while one of its sessions is in use', function () {
        config(['keyring.sessions.absolute' => '365d']);
        Keyring::risk()->signals([app()->make(InactiveAccount::class, ['score' => 95])]);

        signInAs()->assertRedirect('/dashboard');
        $session = session(Sessions::KEY);
        $this->flushSession();
        app('auth')->forgetGuards();

        $this->travel(91)->days();
        app(SessionRegistry::class)->update($session, ['lastActivityAt' => now()->subDay()->getTimestamp()]);

        signInAs(CHROME)->assertRedirect('/dashboard');
    });

    // Someone else signed in as the user isn't the user using the account.
    it('still calls an account quiet while someone impersonates it', function () {
        Keyring::risk()->signals([InactiveAccount::class])->respond(fn (Risk $risk) => $risk->has('inactive_account') ? Action::deny() : Action::allow());
        $cookie = lastSignedIn(daysAgo: 91);
        $admin = User::create(['name' => 'Ada Admin', 'email' => 'admin@example.com', 'password' => 'password', 'email_verified_at' => now()]);
        $totp = Authenticator::factory()->totp()->for($admin, 'authenticatable')->create();
        Keyring::allowImpersonationWhen(fn (User $impersonator) => $impersonator->is($admin));

        $this->post('/login', ['email' => 'admin@example.com', 'password' => 'password']);
        $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)])->assertRedirect('/dashboard');
        $this->post(route('keyring.impersonation.store', $this->user->getKey()))->assertRedirect('/dashboard');
        $this->flushSession();
        app('auth')->forgetGuards();

        expect(app(SessionRegistry::class)->forUser($this->user)->sole()->isImpersonated())->toBeTrue();

        signInAs(cookies: ['known_device' => $cookie])->assertSessionHasErrors('email');
        $this->assertGuest();
    });

    it('does nothing without devices, which is where it reads the last sign in', function () {
        Keyring::risk()->signals([app()->make(InactiveAccount::class, ['score' => 95])]);
        lastSignedIn(daysAgo: 91);
        withFeatures([]);

        signInAs()->assertRedirect('/dashboard');
    });
});

describe('a sign in that follows several failed attempts', function () {
    it('is found after five failures since the account last signed in', function () {
        Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
        Keyring::require(Requirement::aal1());
        config(['keyring.limits.per_account' => 100]);
        Keyring::risk()->signals([SuccessAfterFailures::class]);

        Event::listen(RiskAssessed::class, function (RiskAssessed $event) use (&$assessed) {
            $assessed = $event;
        });

        foreach (range(1, 5) as $guess) {
            signInAs(password: 'nope');
        }

        signInAs()->assertRedirect(route('keyring.login.challenge'));

        expect($assessed->risk->has('success_after_failures'))->toBeTrue()
            ->and($assessed->risk->score)->toBe(30)
            ->and($assessed->risk->reasons())->toBe(['Signed in after 5 failed attempts in the last 1h.']);
    });

    // OWASP ASVS 5.0.0, 6.3.5: the owner hears of it without the app
    // writing a response of its own.
    it('is told to the owner, who may have nothing more to prove', function () {
        config(['keyring.limits.per_account' => 100]);
        Keyring::risk()->signals([SuccessAfterFailures::class]);

        foreach (range(1, 5) as $guess) {
            signInAs(password: 'nope');
        }

        Notification::assertNothingSent();

        signInAs()->assertRedirect('/dashboard');

        $notice = Notification::sent($this->user, SuspiciousActivity::class)->sole();

        expect($notice->reasons)->toBe('Signed in after 5 failed attempts in the last 1h.');
    });

    it('is not told when the app answers for itself and says nothing', function () {
        config(['keyring.limits.per_account' => 100]);
        Keyring::risk()->signals([SuccessAfterFailures::class])->respond(fn (Risk $risk) => Action::allow());

        foreach (range(1, 5) as $guess) {
            signInAs(password: 'nope');
        }

        signInAs()->assertRedirect('/dashboard');

        Notification::assertNotSentTo($this->user, SuspiciousActivity::class);
    });

    it('is not found after fewer', function () {
        config(['keyring.limits.per_account' => 100]);
        Keyring::risk()->signals([app()->make(SuccessAfterFailures::class, ['score' => 95])]);

        foreach (range(1, 4) as $guess) {
            signInAs(password: 'nope');
        }

        signInAs()->assertRedirect('/dashboard');
    });

    it('counts from the last sign in, so one run of failures is only followed once', function () {
        config(['keyring.limits.per_account' => 100]);
        Keyring::risk()->signals([app()->make(SuccessAfterFailures::class, ['threshold' => 3])])
            ->respond(fn (Risk $risk) => $risk->has('success_after_failures') ? Action::allow()->notify() : Action::allow());
        sendNotifications(['suspicious_activity']);

        foreach (range(1, 3) as $guess) {
            signInAs(password: 'nope');
        }

        signInAs()->assertRedirect('/dashboard');
        $this->post('/logout');
        signInAs(password: 'nope');
        signInAs()->assertRedirect('/dashboard');

        Notification::assertSentToTimes($this->user, SuspiciousActivity::class, 1);
    });

    it('forgets failures older than the time it looks back', function () {
        config(['keyring.limits.per_account' => 100]);
        Keyring::risk()->signals([app()->make(SuccessAfterFailures::class, ['score' => 95, 'within' => '10m'])]);

        foreach (range(1, 5) as $guess) {
            signInAs(password: 'nope');
        }

        $this->travel(11)->minutes();

        signInAs()->assertRedirect('/dashboard');
    });

    it('leaves another account\'s failures out of it', function () {
        config(['keyring.limits.per_account' => 100]);
        Keyring::risk()->signals([app()->make(SuccessAfterFailures::class, ['score' => 95])]);
        taylor(['email' => 'abigail@example.com']);

        foreach (range(1, 5) as $guess) {
            $this->post('/login', ['email' => 'abigail@example.com', 'password' => 'nope']);
        }

        signInAs()->assertRedirect('/dashboard');
    });

    it('does nothing without the security log, which is where it reads the failures', function () {
        withFeatures([Features::devices()]);
        config(['keyring.limits.per_account' => 100]);
        Keyring::risk()->signals([app()->make(SuccessAfterFailures::class, ['score' => 95])]);

        foreach (range(1, 5) as $guess) {
            signInAs(password: 'nope');
        }

        signInAs()->assertRedirect('/dashboard');
    });
});

describe('a sign in from an address that has been failing on other accounts', function () {
    /**
     * Failed sign ins from an address, one for each of these accounts. Null
     * is a name nobody has.
     *
     * @param  list<Model|null>  $accounts
     */
    function failedFrom(array $accounts, string $ip = '127.0.0.1', int $minutesAgo = 0): void
    {
        foreach ($accounts as $account) {
            $event = new SecurityEvent(['type' => 'factor_failed', 'factor' => 'password', 'ip' => $ip, 'created_at' => now()->subMinutes($minutesAgo)]);

            if ($account !== null) {
                $event->authenticatable()->associate($account);
            }

            $event->save();
        }
    }

    /**
     * Accounts besides Taylor's.
     *
     * @return list<User>
     */
    function otherAccounts(int $count): array
    {
        return array_map(fn (int $n) => taylor(['email' => "other-{$n}@example.com"]), range(1, $count));
    }

    /**
     * What CredentialStuffing finds for Taylor's sign in, with these options.
     *
     * @param  array<string, mixed>  $options
     */
    function stuffing(array $options = []): ?Finding
    {
        return app()->make(CredentialStuffing::class, $options)->assess(new Assessment(Checkpoint::Login, request(), test()->user));
    }

    it('is found when five other accounts failed from the same address', function () {
        Keyring::risk()->signals([CredentialStuffing::class]);
        otherAccounts(5);

        Event::listen(RiskAssessed::class, function (RiskAssessed $event) use (&$assessed) {
            $assessed = $event;
        });

        foreach (range(1, 5) as $n) {
            $this->post('/login', ['email' => "other-{$n}@example.com", 'password' => 'nope'])->assertSessionHasErrors('email');
        }

        signInAs()->assertRedirect('/dashboard');

        expect($assessed->risk->has(CredentialStuffing::FINDING))->toBeTrue()
            ->and($assessed->risk->score)->toBe(40)
            ->and($assessed->risk->reasons())->toBe(['Failed attempts on 5 other accounts from this IP address in the last 1h.']);
    });

    it('is not found after fewer', function () {
        failedFrom(otherAccounts(4));

        expect(stuffing())->toBeNull();
    });

    it('counts an account that failed many times once', function () {
        [$other] = otherAccounts(1);
        failedFrom(array_fill(0, 10, $other));

        expect(stuffing())->toBeNull()
            ->and(stuffing(['threshold' => 1]))->not->toBeNull();
    });

    it('counts an account of another model as another account, even with the user\'s ID', function () {
        $staff = staff();
        failedFrom([...otherAccounts(4), $staff]);

        expect($staff->getKey())->toBe($this->user->getKey())
            ->and(stuffing()?->signal)->toBe(CredentialStuffing::FINDING);
    });

    it('counts every account, the user\'s own too, when asked to leave none out', function () {
        failedFrom([...otherAccounts(2), $this->user, null, null]);

        expect(app(SecurityLog::class)->accountsFrom(request(), 'factor_failed', 3600))->toBe(4)
            ->and(app(SecurityLog::class)->accountsFrom(request(), 'factor_failed', 3600, except: $this->user))->toBe(3);
    });

    // OWASP ASVS 5.0.0, 6.3.5: a user with nothing more to prove gets in at
    // that level, so they're told.
    it('is told to the owner, who may have nothing more to prove', function () {
        Keyring::risk()->signals([CredentialStuffing::class]);
        failedFrom(otherAccounts(5));

        signInAs()->assertRedirect('/dashboard');

        $notice = Notification::sent($this->user, SuspiciousActivity::class)->sole();

        expect($notice->reasons)->toBe('Failed attempts on 5 other accounts from this IP address in the last 1h.');
    });

    it('leaves out the user\'s own failures', function () {
        failedFrom([...otherAccounts(4), $this->user, $this->user]);

        expect(stuffing())->toBeNull();
    });

    it('counts names nobody has as one account between them, since it cannot tell them apart', function () {
        failedFrom([...otherAccounts(3), null, null, null]);

        expect(stuffing())->toBeNull();

        failedFrom([taylor(['email' => 'one-more@example.com'])]);

        expect(stuffing()?->reason)->toBe('Failed attempts on 5 other accounts from this IP address in the last 1h.');
    });

    it('counts names nobody has that were refused at the form', function () {
        foreach (range(1, 4) as $n) {
            taylor(['email' => "other-{$n}@example.com"]);
            $this->post('/login', ['email' => "other-{$n}@example.com", 'password' => 'nope']);
        }

        $this->post('/login', ['email' => 'nobody@example.com', 'password' => 'nope']);
        $this->post('/login', ['email' => 'nobody-else@example.com', 'password' => 'nope']);

        expect(stuffing()?->reason)->toBe('Failed attempts on 5 other accounts from this IP address in the last 1h.');
    });

    it('leaves out failures from other addresses', function () {
        failedFrom(otherAccounts(5), ip: '203.0.113.9');

        expect(stuffing())->toBeNull();
    });

    it('compares the address Keyring records, not the one the request came from', function () {
        Keyring::recordIpsUsing(fn (Request $request) => '127.0.0.0');
        failedFrom(otherAccounts(5), ip: '127.0.0.0');

        expect(stuffing())->not->toBeNull();

        Keyring::recordIpsUsing(fn (Request $request) => null);

        expect(stuffing())->toBeNull();
    });

    it('forgets failures older than the time it looks back', function () {
        failedFrom(otherAccounts(5), minutesAgo: 61);

        expect(stuffing())->toBeNull()
            ->and(stuffing(['within' => '2h']))->not->toBeNull();
    });

    it('takes a threshold and a score', function () {
        failedFrom(otherAccounts(3));

        expect(stuffing())->toBeNull()
            ->and(stuffing(['threshold' => 3, 'score' => 20])?->score)->toBe(20);
    });

    it('does nothing without the security log, which is where it reads the failures', function () {
        withFeatures([Features::devices()]);
        Keyring::risk()->signals([app()->make(CredentialStuffing::class, ['score' => 95])]);
        otherAccounts(5);

        foreach (range(1, 5) as $n) {
            $this->post('/login', ['email' => "other-{$n}@example.com", 'password' => 'nope']);
        }

        signInAs()->assertRedirect('/dashboard');
    });

    it('finds nothing in a security log it cannot read', function () {
        Exceptions::fake();
        Keyring::useSecurityEventModel(UnavailableSecurityEvent::class);

        expect(stuffing(['threshold' => 1]))->toBeNull();
        Exceptions::assertReported(QueryException::class);
    });
});

it('tells the user about either, and refuses neither, when both are found at once', function () {
    config(['keyring.limits.per_account' => 100]);
    sendNotifications(['suspicious_activity']);
    Keyring::risk()->signals([InactiveAccount::class, SuccessAfterFailures::class]);

    $cookie = signInAs()->getCookie('known_device')->getValue();
    $this->post('/logout');
    $this->travel(91)->days();

    foreach (range(1, 5) as $guess) {
        signInAs(password: 'nope');
    }

    signInAs(cookies: ['known_device' => $cookie])->assertRedirect('/dashboard');

    $notice = Notification::sent($this->user, SuspiciousActivity::class)->sole();

    expect($notice->reasons)->toBe('The first sign in for 91 days. Signed in after 5 failed attempts in the last 1h.');
});

/**
 * An email change to the user's address that was applied then, and
 * undone later when given.
 */
function emailChangedAt(User $user, DateTimeInterface $applied, ?DateTimeInterface $reverted = null): void
{
    $change = new PendingChange([
        'attribute' => 'email',
        'value' => 'taylor@example.com',
        'previous_value' => 'old@example.com',
        'confirm_token' => PendingChange::hashToken('confirm'),
        'revert_token' => PendingChange::hashToken('revert'),
        'confirmed_at' => $applied,
        'applied_at' => $applied,
        'reverted_at' => $reverted,
        'revertable_until' => CarbonImmutable::parse($applied)->addDays(7),
        'expires_at' => CarbonImmutable::parse($applied)->addDay(),
    ]);

    $change->authenticatable()->associate($user)->save();
}

describe('a sign in soon after the email address changed', function () {
    it('is found within a week of the change', function () {
        Keyring::risk()->signals([RecentlyChangedRecovery::class])->respond(function (Risk $risk) use (&$found) {
            $found = $risk;

            return Action::allow();
        });
        emailChangedAt($this->user, now()->subDays(6));

        signInAs()->assertRedirect('/dashboard');

        expect($found->has('recent_recovery_change'))->toBeTrue()
            ->and($found->score)->toBe(25)
            ->and($found->reasons())->toBe(['The email address changed recently.']);
    });

    it('counts an undo as a change', function () {
        Keyring::risk()->signals([app()->make(RecentlyChangedRecovery::class, ['score' => 95])]);
        emailChangedAt($this->user, now()->subDays(20), reverted: now()->subDay());

        signInAs()->assertSessionHasErrors('email');
        $this->assertGuest();
    });

    it('is not found once the change is older than the app looks back', function () {
        config(['keyring.risk.recent_change' => '1d']);
        Keyring::risk()->signals([app()->make(RecentlyChangedRecovery::class, ['score' => 95])]);
        emailChangedAt($this->user, now()->subDays(2));

        signInAs()->assertRedirect('/dashboard');
    });

    it('is not found for an address that never changed', function () {
        Keyring::risk()->signals([app()->make(RecentlyChangedRecovery::class, ['score' => 95])]);

        signInAs()->assertRedirect('/dashboard');
    });
});
