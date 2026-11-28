<?php

declare(strict_types=1);

use Illuminate\Foundation\AliasLoader;
use Illuminate\Http\Request;
use Illuminate\Routing\RouteCollection;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Route;
use Keyring\Enums\Assurance;
use Keyring\Facades\Keyring;
use Keyring\Models\Authenticator;
use Keyring\Sessions\Sessions;
use Keyring\Tests\Fixtures\User;

// The examples docs/impersonation.md and docs/testing.md give, run as they
// write them.
beforeEach(function () {
    $this->admin = taylor(['name' => 'Ada Admin', 'email' => 'admin@example.com']);
    $this->totp = Authenticator::factory()->totp()->for($this->admin, 'authenticatable')->create();
    $this->user = User::create(['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => 'password', 'email_verified_at' => now()]);
});

/**
 * The admin signs in with their password and authenticator app, as the
 * default impersonation.middleware asks.
 */
function adminSignsInForTheDocs(): void
{
    test()->post('/login', ['email' => 'admin@example.com', 'password' => 'password']);
    test()->post(route('keyring.login.verify', 'totp'), ['code' => totpCode(test()->totp->secret)])->assertRedirect('/dashboard');
}

/**
 * The routes "From Your Own Code" gives, as it writes them.
 */
function impersonationRoutesOfTheAppsOwn(): void
{
    Route::middleware('web')->group(function () {
        Route::post('/admin/users/{user}/impersonate', function (Request $request, User $user) {
            Keyring::impersonate($request, $user);   // throws ImpersonationRefused

            return redirect('/dashboard');
        })->middleware(['auth', 'keyring.not-impersonating', 'keyring:aal2', 'keyring.fresh:15m'])->block();

        Route::delete('/admin/impersonation', function (Request $request) {
            if (! Keyring::impersonating($request)) {
                return redirect('/admin/users');   // back already: a second stop, from a stale tab say
            }

            $impersonator = Keyring::stopImpersonating($request);   // null when it signed out instead

            return $impersonator === null ? redirect('/login') : redirect('/admin/users');
        })->middleware('auth')->block();
    });
}

it('starts and stops from routes of the app\'s own, answering a second stop as back already', function () {
    Keyring::allowImpersonationWhen(fn (User $impersonator, User $user) => $impersonator->is($this->admin));
    impersonationRoutesOfTheAppsOwn();
    adminSignsInForTheDocs();

    $this->post("/admin/users/{$this->user->getKey()}/impersonate")->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($this->user);

    $this->delete('/admin/impersonation')->assertRedirect('/admin/users');

    $this->assertAuthenticatedAs($this->admin);

    $this->delete('/admin/impersonation')->assertRedirect('/admin/users');

    $this->assertAuthenticatedAs($this->admin);
});

it('refuses starting from the app\'s own route as Keyring\'s does', function () {
    Keyring::allowImpersonationWhen(fn (User $impersonator, User $user) => false);
    impersonationRoutesOfTheAppsOwn();
    adminSignsInForTheDocs();

    $this->post("/admin/users/{$this->user->getKey()}/impersonate")->assertForbidden();

    $this->assertAuthenticatedAs($this->admin);
});

it('lets only admins impersonate, and only those who aren\'t', function () {
    // "Who May Impersonate Whom". The fixture's isAdmin() is whoever's
    // address starts with "admin@".
    Keyring::allowImpersonationWhen(fn (User $impersonator, User $user) => $impersonator->isAdmin() && ! $user->isAdmin());
    $other = User::create(['name' => 'Other Admin', 'email' => 'admin@example.org', 'password' => 'password']);

    expect(Keyring::allowsImpersonation($this->admin, $this->user))->toBeTrue()
        ->and(Keyring::allowsImpersonation($this->admin, $other))->toBeFalse()
        ->and(Keyring::allowsImpersonation($this->user, $this->admin))->toBeFalse();
});

it('asks a gate about the impersonator, so the impersonation carries on', function () {
    Gate::define('impersonate', fn (User $impersonator, User $user) => $impersonator->isAdmin());
    Route::middleware(['web', 'auth'])->get('/whoami', fn () => (string) Auth::id());

    Keyring::allowImpersonationWhen(fn (User $impersonator, User $user) => Gate::forUser($impersonator)->allows('impersonate', $user));

    adminSignsInForTheDocs();
    $this->post(route('keyring.impersonation.store', $this->user))->assertRedirect('/dashboard');

    $this->get('/whoami')->assertOk()->assertSee((string) $this->user->getKey());
    expect(Keyring::impersonating())->toBeTrue();
});

it('shows the allowsImpersonation button only when it would work', function () {
    AliasLoader::getInstance()->alias('Keyring', Keyring::class);
    Keyring::allowImpersonationWhen(fn (User $impersonator, User $user) => $impersonator->is($this->admin));

    $button = <<<'BLADE'
        @if (Keyring::allowsImpersonation(auth()->user(), $user))
            <form method="POST" action="{{ route('keyring.impersonation.store', $user) }}">
                @csrf
                <button>Sign in as {{ $user->name }}</button>
            </form>
        @endif
        BLADE;

    Route::middleware(['web', 'auth'])->get('/button/{user}', fn (User $user) => Blade::render($button, ['user' => $user]));

    adminSignsInForTheDocs();

    $this->get("/button/{$this->user->getKey()}")->assertSee('Sign in as Abigail')
        ->assertSee(route('keyring.impersonation.store', $this->user), escape: false);
    $this->get("/button/{$this->admin->getKey()}")->assertDontSee('Sign in as');
});

it('shares what the banner needs, and shows the Blade banner, only while impersonating', function () {
    AliasLoader::getInstance()->alias('Keyring', Keyring::class);
    Keyring::allowImpersonationWhen(fn (User $impersonator, User $user) => $impersonator->is($this->admin));

    // "Showing a Banner", shared as Inertia middleware's share() would.
    Route::middleware(['web', 'auth'])->get('/shared', fn (Request $request) => ['impersonation' => (fn () => Keyring::impersonation($request))()]);

    $banner = <<<'BLADE'
        @if (Keyring::impersonating())
            <div role="status">
                Signed in as {{ auth()->user()->name }}.
                <form method="POST" action="{{ route('keyring.impersonation.destroy') }}">
                    @csrf
                    <button>Back to my account</button>
                </form>
            </div>
        @endif
        BLADE;

    Route::middleware(['web', 'auth'])->get('/banner', fn () => Blade::render($banner));

    adminSignsInForTheDocs();

    $this->getJson('/shared')->assertExactJson(['impersonation' => null]);
    $this->get('/banner')->assertDontSee('Back to my account');

    $this->post(route('keyring.impersonation.store', $this->user));

    $this->getJson('/shared')->assertJsonPath('impersonation.impersonator', ['id' => (string) $this->admin->getKey(), 'name' => 'Ada Admin'])
        ->assertJsonPath('impersonation.stopUrl', route('keyring.impersonation.destroy'));
    $this->get('/banner')->assertSee('Signed in as Abigail.')->assertSee('Back to my account')
        ->assertSee(route('keyring.impersonation.destroy'), escape: false);
});

it('has no stopUrl when Keyring\'s routes aren\'t registered', function () {
    Keyring::allowImpersonationWhen(fn (User $impersonator, User $user) => $impersonator->is($this->admin));
    adminSignsInForTheDocs();
    $this->post(route('keyring.impersonation.store', $this->user));

    app('router')->setRoutes(new RouteCollection);

    expect(Keyring::impersonation())->toMatchArray(['stopUrl' => null])
        ->and(Keyring::impersonation()['impersonator'])->toBe(['id' => (string) $this->admin->getKey(), 'name' => 'Ada Admin']);
});

it('asks for nothing more with an empty impersonation.middleware', function () {
    config(['keyring.impersonation.middleware' => []]);
    reloadRoutes();
    Keyring::allowImpersonationWhen(fn (User $impersonator, User $user) => $impersonator->is($this->user));

    // A password alone, and long ago: neither AAL2 nor fresh.
    $this->post('/login', ['email' => 'abigail@example.com', 'password' => 'password'])->assertRedirect('/dashboard');
    $this->travel(30)->minutes();

    $this->post(route('keyring.impersonation.store', $this->admin))->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($this->admin);
    expect(Keyring::impersonator()?->is($this->user))->toBeTrue();
});

it('asks for a recent password alone with the password-only middleware', function () {
    config(['keyring.impersonation.middleware' => ['keyring.fresh:15m']]);
    reloadRoutes();
    Keyring::allowImpersonationWhen(fn (User $impersonator, User $user) => $impersonator->is($this->user));

    $this->post('/login', ['email' => 'abigail@example.com', 'password' => 'password'])->assertRedirect('/dashboard');

    $this->post(route('keyring.impersonation.store', $this->admin))->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($this->admin);
});

it('sends an impersonator without a second factor to enrollment_url, or answers 403 without one', function () {
    Keyring::allowImpersonationWhen(fn (User $impersonator, User $user) => $impersonator->is($this->user));
    $this->post('/login', ['email' => 'abigail@example.com', 'password' => 'password'])->assertRedirect('/dashboard');

    $this->post(route('keyring.impersonation.store', $this->admin))->assertForbidden();

    config(['keyring.enrollment_url' => '/settings/security']);

    $this->post(route('keyring.impersonation.store', $this->admin))->assertRedirect('/settings/security');
    $this->assertAuthenticatedAs($this->user);
});

it('starts one in a test with withAssurance, as docs/testing.md writes it', function () {
    Keyring::allowImpersonationWhen(fn (User $impersonator, User $user) => $impersonator->is($this->admin));
    $admin = $this->admin;
    $user = $this->user;

    // "Impersonating"
    $this->actingAs($admin)->withAssurance(Assurance::AAL2)
        ->post(route('keyring.impersonation.store', $user))
        ->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($user);
    expect(Keyring::impersonating())->toBeTrue()
        ->and(Keyring::impersonator()->is($admin))->toBeTrue();

    $this->delete(route('keyring.impersonation.destroy'))->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($admin);
    expect(Keyring::impersonating())->toBeFalse();
});

it('lists the impersonated session to itself with impersonation.show_in_sessions off', function () {
    config(['keyring.impersonation.show_in_sessions' => false]);
    Keyring::allowImpersonationWhen(fn (User $impersonator, User $user) => $impersonator->is($this->admin));
    adminSignsInForTheDocs();
    $this->post(route('keyring.impersonation.store', $this->user));
    $handle = app(Sessions::class)->handle(app(Sessions::class)->registry()->find(session(Sessions::KEY)));

    $sessions = $this->getJson(route('keyring.sessions.index'))->assertOk()->json('sessions');

    expect($sessions)->toHaveCount(1)
        ->and($sessions[0])->toMatchArray(['id' => $handle, 'current' => true, 'impersonated' => true, 'impersonator' => ['name' => 'Ada Admin']]);
});
