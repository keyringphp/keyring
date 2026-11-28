<?php

declare(strict_types=1);

use Illuminate\Auth\AuthenticationException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use Keyring\Changes\AuthenticatorChanges;
use Keyring\Changes\EmailChanges;
use Keyring\Contracts\SessionRegistry;
use Keyring\Enums\Assurance;
use Keyring\Enums\EmailConfirmation;
use Keyring\Events\AuthenticatorRemoved;
use Keyring\Events\FactorVerified;
use Keyring\Exceptions\ProtectedAttributeException;
use Keyring\Exceptions\ReservedAddressException;
use Keyring\Facades\Keyring;
use Keyring\Factors\EmailCode;
use Keyring\Factors\Password as PasswordFactor;
use Keyring\Factors\SingleSignOn;
use Keyring\Features;
use Keyring\Models\Authenticator;
use Keyring\Models\PendingChange;
use Keyring\Notifications\ConfirmEmailChange;
use Keyring\Notifications\EmailAddressInUse;
use Keyring\Notifications\EmailChanged;
use Keyring\Notifications\EmailChangeNotice;
use Keyring\Notifications\EmailChangeReverted;
use Keyring\Notifications\VerificationCode;
use Keyring\Rules\UnreservedAddress;
use Keyring\Sessions\RegisteredSession;
use Keyring\Sessions\Sessions;
use Keyring\Support\MailText;
use Keyring\Testing\VirtualAuthenticator;
use Keyring\Tests\Fixtures\SoftDeletingUser;
use Keyring\Tests\Fixtures\User;

beforeEach(function () {
    Notification::fake();
    $this->user = taylor();
});

/**
 * @return array{confirm: string, revert: string, current: ?string}
 */
function tokensFor(string $newAddress, string $currentAddress): array
{
    $confirm = $notice = null;

    Notification::assertSentTo(new AnonymousNotifiable, ConfirmEmailChange::class, function ($n, $c, $to) use ($newAddress, &$confirm) {
        return $to->routes['mail'] === $newAddress && ($confirm = Str::afterLast($n->url, '/'));
    });
    Notification::assertSentTo(new AnonymousNotifiable, EmailChangeNotice::class, function ($n, $c, $to) use ($currentAddress, &$notice) {
        return $to->routes['mail'] === $currentAddress && ($notice = $n);
    });

    return [
        'confirm' => $confirm,
        'revert' => Str::afterLast($notice->revertUrl, '/'),
        'current' => $notice->confirmUrl === null ? null : Str::afterLast($notice->confirmUrl, '/'),
    ];
}

function requestChange(User $user, string $to, Assurance $as = Assurance::AAL1): PendingChange
{
    test()->actingAs($user)->withAssurance($as)
        ->postJson(route('keyring.email.store'), ['email' => $to])->assertOk();

    return PendingChange::query()->latest('id')->first();
}

/**
 * Confirm from both addresses (no second factor was proved, so both must).
 */
function confirmBoth(PendingChange $change, array $tokens): EmailConfirmation
{
    app(EmailChanges::class)->confirm($change, $tokens['current']);

    return app(EmailChanges::class)->confirm($change->fresh(), $tokens['confirm']);
}

it('shows the address in the change notice as plain text', function (string $value, string $shown) {
    $mail = renderedMail(new EmailChangeNotice(MailText::maskAddress($value), 'https://example.com/revert')->toMail(new AnonymousNotifiable));

    expect($mail['html'])->not->toMatch('/<[^>]*(href|src)="[^"]*evil\.example/')
        ->toContain($shown)
        ->and($mail['text'])->toContain($shown);
})->with([
    'a link in the domain' => ['a@[x](https://evil.example/e)', 'a•••@[x](https://evil.example/e)'],
    'a normal address' => ['new@example.com', 'n•••@example.com'],
]);

it('does not change anything when an emailed link is only opened', function () {
    $change = requestChange($this->user, 'new@example.com');
    $tokens = tokensFor('new@example.com', 'taylor@example.com');

    $this->inertia()->get(route('keyring.email.confirm', [$change->id, $tokens['confirm']]))
        ->assertOk()
        ->assertJsonPath('component', 'auth/email-change')
        ->assertHeader('Referrer-Policy', 'no-referrer');
    $this->inertia()->get(route('keyring.email.revert', [$change->id, $tokens['revert']]))->assertOk()->assertJsonPath('props.action', 'revert')
        ->assertHeader('Referrer-Policy', 'no-referrer');

    expect($this->user->fresh()->email)->toBe('taylor@example.com')
        ->and($change->fresh()->isPending())->toBeTrue();
});

it('closes later changes when an earlier one is reverted', function () {
    $first = requestChange($this->user, 'b@example.com');
    $firstTokens = tokensFor('b@example.com', 'taylor@example.com');
    confirmBoth($first, $firstTokens);

    $this->user->refresh();
    Notification::fake();
    $second = requestChange($this->user, 'c@example.com');
    $secondTokens = tokensFor('c@example.com', 'b@example.com');
    confirmBoth($second, $secondTokens);
    expect($this->user->fresh()->email)->toBe('c@example.com');

    expect(app(EmailChanges::class)->revert($first->fresh(), $firstTokens['revert']))->toBeTrue();
    expect($this->user->fresh()->email)->toBe('taylor@example.com');

    expect(app(EmailChanges::class)->revert($second->fresh(), $secondTokens['revert']))->toBeFalse();
    expect($this->user->fresh()->email)->toBe('taylor@example.com');
});

it('cancels changes still pending when an earlier one is reverted', function () {
    $first = requestChange($this->user, 'b@example.com');
    $firstTokens = tokensFor('b@example.com', 'taylor@example.com');
    confirmBoth($first, $firstTokens);

    $this->user->refresh();
    Notification::fake();
    $second = requestChange($this->user, 'c@example.com');
    $secondTokens = tokensFor('c@example.com', 'b@example.com');

    app(EmailChanges::class)->revert($first->fresh(), $firstTokens['revert']);

    expect(confirmBoth($second->fresh(), $secondTokens))->toBe(EmailConfirmation::Invalid)
        ->and($this->user->fresh()->email)->toBe('taylor@example.com');
});

it('does not apply a change once the address has moved on', function () {
    $change = requestChange($this->user, 'new@example.com');
    $tokens = tokensFor('new@example.com', 'taylor@example.com');

    Keyring::withoutProtection(fn () => $this->user->fresh()->update(['email' => 'support-set@example.com']));

    expect(confirmBoth($change, $tokens))->toBe(EmailConfirmation::Invalid)
        ->and($this->user->fresh()->email)->toBe('support-set@example.com');
});

it('cannot be confirmed twice from stale copies', function () {
    $change = requestChange($this->user, 'new@example.com');
    $tokens = tokensFor('new@example.com', 'taylor@example.com');
    app(EmailChanges::class)->confirm($change, $tokens['current']);
    $stale = PendingChange::find($change->id);

    expect(app(EmailChanges::class)->confirm($change->fresh(), $tokens['confirm']))->toBe(EmailConfirmation::Applied)
        ->and(app(EmailChanges::class)->confirm($stale, $tokens['confirm']))->toBe(EmailConfirmation::Invalid)
        ->and(PendingChange::find($change->id)->previous_value)->toBe('taylor@example.com');

    app(EmailChanges::class)->revert(PendingChange::find($change->id), $tokens['revert']);
    expect($this->user->fresh()->email)->toBe('taylor@example.com');
});

it('removes sign-in methods added since the change when it is reverted', function () {
    Event::fake([AuthenticatorRemoved::class]);
    $before = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create(['created_at' => now()->subMonth()]);
    $change = requestChange($this->user, 'attacker@example.com', Assurance::AAL2);
    $tokens = tokensFor('attacker@example.com', 'taylor@example.com');

    $this->travel(1)->minutes();
    $planted = Authenticator::factory()->passkey()->for($this->user, 'authenticatable')->create();

    confirmBoth($change, $tokens);
    app(EmailChanges::class)->revert($change->fresh(), $tokens['revert']);

    expect(Authenticator::find($planted->id))->toBeNull()
        ->and(Authenticator::find($before->id))->not->toBeNull();
    Event::assertDispatched(AuthenticatorRemoved::class, fn (AuthenticatorRemoved $event) => $event->authenticator->is($planted));
});

it('unlinks identity providers linked since the change when it is reverted', function () {
    Keyring::factors([PasswordFactor::class, SingleSignOn::class]);
    $kept = Authenticator::factory()->sso(subject: 'owner')->for($this->user, 'authenticatable')->create(['created_at' => now()->subMonth()]);
    $change = requestChange($this->user, 'attacker@example.com', Assurance::AAL2);
    $tokens = tokensFor('attacker@example.com', 'taylor@example.com');

    $this->travel(1)->minutes();
    $planted = Authenticator::factory()->sso(subject: 'attacker')->for($this->user, 'authenticatable')->create();

    confirmBoth($change, $tokens);
    app(EmailChanges::class)->revert($change->fresh(), $tokens['revert']);

    expect(Authenticator::find($planted->id))->toBeNull()
        ->and(Authenticator::find($kept->id))->not->toBeNull();
});

// back, whatever sends the notice: an event carrying the copy loaded before
// that would have a notice that isn't queued go to the address taken off.
it('announces what an undo removed to the address it put back', function () {
    Event::fake([AuthenticatorRemoved::class]);
    $change = requestChange($this->user, 'attacker@example.com', Assurance::AAL2);
    $tokens = tokensFor('attacker@example.com', 'taylor@example.com');

    $this->travel(1)->minutes();
    Authenticator::factory()->passkey()->for($this->user, 'authenticatable')->create();

    confirmBoth($change, $tokens);
    expect($this->user->fresh()->email)->toBe('attacker@example.com');

    app(EmailChanges::class)->revert($change->fresh(), $tokens['revert']);

    Event::assertDispatched(AuthenticatorRemoved::class, fn (AuthenticatorRemoved $event) => $event->user->email === 'taylor@example.com');
    Event::assertNotDispatched(AuthenticatorRemoved::class, fn (AuthenticatorRemoved $event) => $event->user->email === 'attacker@example.com');
});

// A request already past its middleware when the undo starts. It either
// saves before the undo ends the sessions, where the undo's last look finds
// what it saved, or after, where it's refused.
describe('a request under way while a change is being undone', function () {
    it('has what it saved in the meantime closed and removed by the undo', function () {
        $change = requestChange($this->user, 'attacker@example.com', Assurance::AAL2);
        $tokens = tokensFor('attacker@example.com', 'taylor@example.com');
        confirmBoth($change, $tokens);

        // Saved once the undo has looked for later changes and for sign-in
        // methods to remove, and before it has ended the sessions.
        $late = [];
        PendingChange::updated(function (PendingChange $saved) use ($change, &$late) {
            if ($saved->is($change) && $saved->wasChanged('reverted_at') && $late === []) {
                $late['change'] = tap(new PendingChange([
                    'attribute' => 'email',
                    'value' => 'again@example.com',
                    'previous_value' => 'attacker@example.com',
                    'confirm_token' => PendingChange::hashToken('confirm'),
                    'revert_token' => PendingChange::hashToken('late'),
                    'expires_at' => now()->addDay(),
                ]), fn (PendingChange $late) => $late->authenticatable()->associate($this->user)->save());
            }
        });
        Authenticator::deleted(function () use (&$late) {
            $late['passkey'] ??= Authenticator::factory()->passkey()->for($this->user, 'authenticatable')->create();
        });

        $this->travel(1)->minutes();
        Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

        expect(app(EmailChanges::class)->revert($change->fresh(), $tokens['revert']))->toBeTrue()
            ->and($late)->toHaveKeys(['change', 'passkey'])
            ->and($late['change']->fresh()->canRevert())->toBeFalse()
            ->and(app(EmailChanges::class)->revert($late['change']->fresh(), 'late'))->toBeFalse()
            ->and(app(EmailChanges::class)->confirm($late['change']->fresh(), 'confirm'))->toBe(EmailConfirmation::Invalid)
            ->and(Authenticator::find($late['passkey']->id))->toBeNull()
            ->and($this->user->fresh()->email)->toBe('taylor@example.com');
    });

    it('is refused once the undo has ended its session', function (Closure $save) {
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect();
        $request = request();
        $request->setLaravelSession(session()->driver());

        // What an undo, a reset or "this wasn't me" does while this request runs.
        app(Sessions::class)->signOutEverywhere($this->user);

        expect(fn () => $save($this->user, $request))->toThrow(AuthenticationException::class)
            ->and(PendingChange::query()->count())->toBe(0)
            ->and(Authenticator::query()->count())->toBe(0);
    })->with([
        'an email change' => [fn (User $user, Request $request) => app(EmailChanges::class)->request($user, 'attacker@example.com', $request)],
        'a sign-in method' => [fn (User $user, Request $request) => app(AuthenticatorChanges::class)->add(
            $user,
            Keyring::factor('totp'),
            Authenticator::factory()->totp()->for($user, 'authenticatable')->make(),
            $request,
        )],
    ]);

    it('saves as usual while its session stands', function () {
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect();
        $request = request();
        $request->setLaravelSession(session()->driver());

        expect(app(EmailChanges::class)->request($this->user, 'new@example.com', $request))->toBeInstanceOf(PendingChange::class);
    });
});

it('removes sign-in methods added earlier in the session that asked for the change', function () {
    $before = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create(['created_at' => now()->subMonth()]);
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($before->secret)]);

    $this->travel(1)->minutes();
    $planted = Authenticator::factory()->passkey()->for($this->user, 'authenticatable')->create();

    $this->travel(1)->minutes();
    $this->postJson(route('keyring.email.store'), ['email' => 'attacker@example.com'])->assertOk();
    $change = PendingChange::sole();

    app(EmailChanges::class)->revert($change, tokensFor('attacker@example.com', 'taylor@example.com')['revert']);

    expect(Authenticator::find($planted->id))->toBeNull()
        ->and(Authenticator::find($before->id))->not->toBeNull();
});

it('removes recovery codes with the last factor an undo removes', function () {
    Event::fake([AuthenticatorRemoved::class]);
    $codes = Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create(['created_at' => now()->subMonths(2)]);
    $this->travel(1)->month();
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create(['created_at' => now()->subDays(3)]);
    $change = requestChange($this->user, 'new@example.com', Assurance::AAL2);
    $tokens = tokensFor('new@example.com', 'taylor@example.com');

    confirmBoth($change, $tokens);
    app(EmailChanges::class)->revert($change->fresh(), $tokens['revert']);

    expect(Authenticator::find($totp->id))->toBeNull()
        ->and(Authenticator::find($codes->id))->toBeNull();
    Event::assertDispatched(AuthenticatorRemoved::class, fn (AuthenticatorRemoved $event) => $event->authenticator->is($codes));
});

it('leaves nothing but the password to confirm with once an undo removes a replaced authenticator app', function () {
    // Replacing the app the day the new one is added would be refused otherwise.
    config(['keyring.authenticator_changes.established_after' => 0]);
    Route::middleware(['web', 'auth', 'keyring.fresh:15m'])->get('/account', fn () => 'danger zone');
    $signIn = function (?string $code = null) {
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

        if ($code !== null) {
            $this->post(route('keyring.login.verify', 'totp'), ['code' => $code]);
        }
    };
    $enroll = function () {
        $secret = $this->postJson(route('keyring.authenticators.store', 'totp'), ['password' => 'password'])->json('enrollment.secret');

        return [$secret, $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => totpCode($secret)])->assertOk()->json('recoveryCodes')];
    };
    $signOut = function () {
        $this->post(route('logout'));
        $this->flushSession();
        Auth::forgetGuards();
    };

    // The codes come with a first app, which is replaced a month later.
    $signIn();
    [$first, $codes] = $enroll();
    $firstId = Authenticator::query()->where('factor', 'totp')->sole()->id;
    $signOut();

    $this->travel(30)->days();
    $signIn(totpCode($first));
    [$second] = $enroll();
    $this->deleteJson(route('keyring.authenticators.destroy', $firstId))->assertOk();
    $signOut();

    // An email change days later, confirmed from both addresses and undone.
    $this->travel(3)->days();
    $signIn(totpCode($second));
    $this->postJson(route('keyring.email.store'), ['email' => 'new@example.com'])->assertOk();
    $change = PendingChange::sole();
    $tokens = tokensFor('new@example.com', 'taylor@example.com');
    confirmBoth($change, $tokens);
    $signOut();

    $this->travel(1)->day();
    app(EmailChanges::class)->revert($change->fresh(), $tokens['revert']);

    expect(Authenticator::query()->ownedBy($this->user)->pluck('factor')->all())->toBe([]);

    $this->travel(1)->day();
    $signIn();
    $this->travel(20)->minutes();

    $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));
    $this->inertia()->get(route('keyring.confirm.challenge'))
        ->assertJsonPath('props.factor', 'password')
        ->assertJsonPath('props.alternatives', []);
    $this->flushHeaders();

    $this->post(route('keyring.confirm.verify', 'recovery'), ['code' => $codes[0]]);
    $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));
    $this->postJson(route('keyring.email.store'), ['email' => 'other@example.com'])->assertStatus(423);
});

it('keeps recovery codes when an undo leaves a factor for them to recover', function () {
    $codes = Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create(['created_at' => now()->subMonth()]);
    $kept = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create(['created_at' => now()->subMonth()]);
    $change = requestChange($this->user, 'new@example.com', Assurance::AAL2);
    $tokens = tokensFor('new@example.com', 'taylor@example.com');

    $this->travel(1)->minutes();
    $planted = Authenticator::factory()->passkey()->for($this->user, 'authenticatable')->create();

    confirmBoth($change, $tokens);
    app(EmailChanges::class)->revert($change->fresh(), $tokens['revert']);

    expect(Authenticator::find($planted->id))->toBeNull()
        ->and(Authenticator::find($kept->id))->not->toBeNull()
        ->and(Authenticator::find($codes->id))->not->toBeNull();
});

it('still asks the current address when the session proved a recovery code rather than its second factor', function () {
    Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create(['created_at' => now()->subMonth()]);
    Authenticator::factory()->recoveryCodes(['aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aa'])->for($this->user, 'authenticatable')->create(['created_at' => now()->subMonth()]);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->post(route('keyring.login.verify', 'recovery'), ['code' => 'aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aa']);
    $this->assertAuthenticatedAs($this->user);

    $this->postJson(route('keyring.email.store'), ['email' => 'new@example.com'])->assertOk();

    expect(PendingChange::query()->latest('id')->first()->current_token)->not->toBeNull();
});

it('cancels pending email changes when the password is reset', function () {
    $change = requestChange($this->user, 'attacker@example.com');
    $tokens = tokensFor('attacker@example.com', 'taylor@example.com');
    $this->post('/logout');

    $token = Password::broker()->createToken($this->user);
    $this->post(route('password.update'), [
        'token' => $token,
        'email' => 'taylor@example.com',
        'password' => 'correct horse battery staple',
        'password_confirmation' => 'correct horse battery staple',
    ])->assertRedirect(route('login'));

    expect(confirmBoth($change->fresh(), $tokens))->toBe(EmailConfirmation::Invalid)
        ->and($this->user->fresh()->email)->toBe('taylor@example.com');
});

it('ends reset links for the old address when the email changes, and they do not return with a revert', function () {
    $token = Password::broker()->createToken($this->user);

    $change = requestChange($this->user, 'new@example.com');
    $tokens = tokensFor('new@example.com', 'taylor@example.com');
    expect(confirmBoth($change, $tokens))->toBe(EmailConfirmation::Applied)
        ->and(Password::broker()->tokenExists(new User(['email' => 'taylor@example.com']), $token))->toBeFalse();

    // A link sent to the new address goes when the change is undone, too.
    $sentToNew = Password::broker()->createToken($this->user->fresh());
    expect(app(EmailChanges::class)->revert($change->fresh(), $tokens['revert']))->toBeTrue()
        ->and(Password::broker()->tokenExists(new User(['email' => 'new@example.com']), $sentToNew))->toBeFalse();

    $this->post('/logout');
    $this->post(route('password.update'), ['token' => $token, 'email' => 'taylor@example.com', 'password' => 'attacker set passphrase', 'password_confirmation' => 'attacker set passphrase'])
        ->assertSessionHasErrors('email');
    expect(Hash::check('password', $this->user->fresh()->password))->toBeTrue();
});

it('leaves a reset link for the new address working after the email changes', function () {
    $change = requestChange($this->user, 'new@example.com');
    confirmBoth($change, tokensFor('new@example.com', 'taylor@example.com'));
    $token = Password::broker()->createToken($this->user->fresh());

    $this->post('/logout');
    $this->post(route('password.update'), ['token' => $token, 'email' => 'new@example.com', 'password' => 'a brand new passphrase', 'password_confirmation' => 'a brand new passphrase'])
        ->assertRedirect(route('login'));

    expect(Hash::check('a brand new passphrase', $this->user->fresh()->password))->toBeTrue();
});

it('asks the current address to confirm when the second factor was only just added by this session', function () {
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

    $secret = $this->postJson(route('keyring.authenticators.store', 'totp'), ['password' => 'password'])->json('enrollment.secret');
    $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => totpCode($secret)])->assertOk();

    // Now that a second factor exists, the session has to use it to stay fresh.
    $this->travel(16)->minutes();
    $this->postJson(route('keyring.email.store'), ['email' => 'new@example.com'])->assertStatus(423);
    $this->get(route('keyring.confirm.challenge'));
    $this->post(route('keyring.confirm.verify', 'totp'), ['code' => totpCode($secret)]);
    $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password']);

    $this->postJson(route('keyring.email.store'), ['email' => 'new@example.com'])->assertOk();

    expect(PendingChange::query()->latest('id')->first()->current_token)->not->toBeNull();
});

it('waives the current address confirmation for a second factor that predates the session', function () {
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create(['created_at' => now()->subMonth()]);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)]);

    $this->postJson(route('keyring.email.store'), ['email' => 'new@example.com'])->assertOk();

    expect(PendingChange::query()->latest('id')->first()->current_token)->toBeNull();
});

it('still asks the current address when the second factor is too new to be the owner\'s for certain', function () {
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create(['created_at' => now()->subDays(6)]);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)]);

    $this->postJson(route('keyring.email.store'), ['email' => 'new@example.com'])->assertOk();

    expect(PendingChange::sole()->current_token)->not->toBeNull();
});

it('does not let a factor planted in one session count as established in the next', function () {
    // Whoever has the password adds an authenticator app of their own...
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect('/dashboard');
    $secret = $this->postJson(route('keyring.authenticators.store', 'totp'), ['password' => 'password'])->assertOk()->json('enrollment.secret');
    $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => totpCode($secret)])->assertOk();
    $this->post('/logout');

    // ...signs in again with it, so it predates the session, and asks.
    $this->travel(2)->minutes();
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($secret)])->assertRedirect('/dashboard');
    $this->travel(1)->minutes();
    $this->postJson(route('keyring.email.store'), ['email' => 'attacker@example.com'])->assertOk();

    $change = PendingChange::sole();
    $tokens = tokensFor('attacker@example.com', 'taylor@example.com');

    // The owner's address still has to confirm, so the change can't apply.
    expect($tokens['current'])->not->toBeNull()
        ->and(app(EmailChanges::class)->confirm($change, $tokens['confirm']))->toBe(EmailConfirmation::NeedsOtherAddress)
        ->and($this->user->fresh()->email)->toBe('taylor@example.com');

    // And "this wasn't me" takes the planted app with it.
    expect(app(EmailChanges::class)->revert($change->fresh(), $tokens['revert']))->toBeTrue()
        ->and(Authenticator::query()->where('factor', 'totp')->exists())->toBeFalse();
});

it('removes a passkey planted before the session that asked, so it can not sign back in after a revert', function () {
    $key = new VirtualAuthenticator;
    $this->actingAs($this->user)->withAssurance(Assurance::AAL1);
    $options = $this->postJson(route('keyring.authenticators.store', 'passkey'), ['password' => 'password'])->assertOk()->json('enrollment.options');
    $this->postJson(route('keyring.authenticators.confirm', 'passkey'), ['credential' => $key->register($options)])->assertOk();
    $this->post('/logout');

    $this->travel(2)->minutes();
    $options = $this->getJson(route('keyring.login.options', 'passkey'))->json('options');
    $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $key->assert($options)])->assertRedirect('/dashboard');
    $this->postJson(route('keyring.email.store'), ['email' => 'attacker@example.com'])->assertOk();

    $tokens = tokensFor('attacker@example.com', 'taylor@example.com');

    expect($tokens['current'])->not->toBeNull()
        ->and(app(EmailChanges::class)->revert(PendingChange::sole(), $tokens['revert']))->toBeTrue()
        ->and(Authenticator::query()->where('factor', 'passkey')->exists())->toBeFalse();
});

it('treats an address a soft deleted account still holds as taken', function () {
    Schema::table('users', fn (Blueprint $table) => $table->softDeletes());
    config(['auth.providers.users.model' => SoftDeletingUser::class]);
    SoftDeletingUser::create(['name' => 'Gone', 'email' => 'gone@example.com', 'password' => 'password', 'email_verified_at' => now()])->delete();
    $user = SoftDeletingUser::query()->findOrFail($this->user->id);

    $this->actingAs($user)->withAssurance(Assurance::AAL1)->postJson(route('keyring.email.store'), ['email' => 'gone@example.com'])->assertOk();

    Notification::assertSentTo(new AnonymousNotifiable, EmailAddressInUse::class, fn ($n, $c, $to) => $to->routes['mail'] === 'gone@example.com');
    Notification::assertNotSentTo(new AnonymousNotifiable, ConfirmEmailChange::class);
});

it('waives it in a test acting as a session verified with that second factor', function () {
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create(['created_at' => now()->subMonth()]);

    $this->actingAs($this->user)->verifiedWith($totp)->postJson(route('keyring.email.store'), ['email' => 'new@example.com'])->assertOk();
    expect(PendingChange::query()->latest('id')->first()->current_token)->toBeNull();

    $this->actingAs($this->user)->withAssurance(Assurance::AAL2)->postJson(route('keyring.email.store'), ['email' => 'newer@example.com'])->assertOk();
    expect(PendingChange::query()->latest('id')->first()->current_token)->not->toBeNull();
});

it('keeps the revert link working after signing out everywhere else cancels the change', function () {
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->postJson(route('keyring.email.store'), ['email' => 'attacker@example.com'])->assertOk();
    $change = PendingChange::sole();
    $tokens = tokensFor('attacker@example.com', 'taylor@example.com');

    $this->deleteJson(route('keyring.devices.destroy-others'))->assertOk();
    $planted = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    expect($change->fresh()->isPending())->toBeFalse()
        ->and(confirmBoth($change->fresh(), $tokens))->toBe(EmailConfirmation::Invalid);

    $this->post(route('keyring.email.revert.store', $change->id), ['token' => $tokens['revert']])
        ->assertSessionHas('status', 'email-change-reverted');

    expect($change->fresh()->reverted_at)->not->toBeNull()
        ->and(Authenticator::find($planted->id))->toBeNull()
        ->and($this->user->fresh()->email)->toBe('taylor@example.com');
});

it('keeps the revert link working after the change is cancelled', function () {
    $change = requestChange($this->user, 'attacker@example.com');
    $tokens = tokensFor('attacker@example.com', 'taylor@example.com');
    $planted = Authenticator::factory()->passkey()->for($this->user, 'authenticatable')->create();

    $this->deleteJson(route('keyring.email.destroy'))->assertOk();

    expect(confirmBoth($change->fresh(), $tokens))->toBe(EmailConfirmation::Invalid)
        ->and(app(EmailChanges::class)->revert($change->fresh(), $tokens['revert']))->toBeTrue()
        ->and(Authenticator::find($planted->id))->toBeNull();
});

it('stops a cancelled change being reverted once it would have expired', function () {
    $change = requestChange($this->user, 'attacker@example.com');
    $tokens = tokensFor('attacker@example.com', 'taylor@example.com');
    $this->deleteJson(route('keyring.email.destroy'))->assertOk();

    $this->travel(25)->hours();

    expect(app(EmailChanges::class)->revert($change->fresh(), $tokens['revert']))->toBeFalse();
});

it('puts the address back from the link for an earlier change that a later one replaced', function () {
    requestChange($this->user, 'first@example.com');
    $first = tokensFor('first@example.com', 'taylor@example.com');
    $earlier = PendingChange::sole();

    $later = requestChange($this->user, 'attacker@example.com');
    expect(confirmBoth($later, tokensFor('attacker@example.com', 'taylor@example.com')))->toBe(EmailConfirmation::Applied)
        ->and($this->user->fresh()->email)->toBe('attacker@example.com');

    expect(app(EmailChanges::class)->revert($earlier->fresh(), $first['revert']))->toBeTrue()
        ->and($this->user->fresh()->email)->toBe('taylor@example.com')
        ->and($later->fresh()->canRevert())->toBeFalse();
});

it('ends a sign in that was waiting for a code sent to the address the undo takes away', function () {
    Keyring::factors([PasswordFactor::class, EmailCode::asExtraStep()]);
    $this->travelTo(now()->subMonth(), fn () => Authenticator::factory()->for($this->user, 'authenticatable')->create(['factor' => 'email-code', 'name' => 'Email', 'secret' => null]));

    $change = requestChange($this->user, 'attacker@example.com', Assurance::AAL2);
    confirmBoth($change, $tokens = tokensFor('attacker@example.com', 'taylor@example.com'));
    $this->post('/logout');
    $this->flushSession();

    // Whoever moved the address gets past the password and has a code sent
    // to their own inbox.
    $this->post('/login', ['email' => 'attacker@example.com', 'password' => 'password'])->assertRedirect(route('keyring.login.challenge'));
    $this->post(route('keyring.login.send', 'email-code'));

    $code = null;
    Notification::assertSentTo($this->user, VerificationCode::class, function (VerificationCode $notification) use (&$code) {
        return (bool) ($code = $notification->code);
    });

    expect(app(EmailChanges::class)->revert($change->fresh(), $tokens['revert']))->toBeTrue();

    $this->post(route('keyring.login.verify', 'email-code'), ['code' => $code]);

    $this->assertGuest();
    expect(session()->has('keyring.attempt.login'))->toBeFalse()
        ->and(app(SessionRegistry::class)->forUser($this->user))->toBeEmpty();
});

it('ends a sign in that was waiting for its second factor when a change moves the address', function () {
    Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect(route('keyring.login.challenge'));

    Keyring::withoutProtection(fn () => $this->user->fresh()->update(['email' => 'moved@example.com']));

    $this->get(route('keyring.login.challenge'))->assertRedirect(route('login'));
    expect(session()->has('keyring.attempt.login'))->toBeFalse();
});

it('ends a sign in whose address moved while it was being checked', function () {
    // The move, start to finish, between the password check and the session.
    Event::listen(fn (FactorVerified $event) => Keyring::withoutProtection(
        fn () => $this->user->fresh()->update(['email' => 'moved@example.com']),
    ));

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertSessionHasErrors(['email' => __('auth.failed')]);

    $this->assertGuest();
    expect(app(SessionRegistry::class)->forUser($this->user))->toBeEmpty();
});

it('says a link was invalid when the token is wrong', function () {
    $change = requestChange($this->user, 'new@example.com');

    $this->post(route('keyring.email.confirm.store', $change->id), ['token' => 'wrong-token'])
        ->assertSessionHas('status', 'email-change-invalid');
});

it('cancels pending email changes on a password change, even keeping other sessions', function () {
    $change = requestChange($this->user, 'attacker@example.com');

    $this->putJson(route('user-password.update'), [
        'current_password' => 'password',
        'password' => 'a much longer passphrase',
        'password_confirmation' => 'a much longer passphrase',
        'sign_out_others' => false,
    ])->assertOk();

    expect($change->fresh()->cancelled_at)->not->toBeNull();
});

describe('the address a change replaced', function () {
    beforeEach(function () {
        $change = requestChange($this->user, 'attacker@example.com');
        confirmBoth($change, $this->tokens = tokensFor('attacker@example.com', 'taylor@example.com'));
        $this->change = $change->fresh();
    });

    it('cannot be registered while the change can be reverted', function () {
        revealTakenAddresses();
        $this->post('/logout');

        $this->post('/register', [
            'name' => 'Someone',
            'email' => 'Taylor@Example.com',
            'password' => 'correct horse battery staple',
            'password_confirmation' => 'correct horse battery staple',
        ])->assertSessionHasErrors(['email' => 'The email has already been taken.']);

        expect(User::count())->toBe(1);
    });

    it('cannot be moved to by another account', function () {
        $other = taylor(['email' => 'other@example.com']);
        $this->flushSession();

        $this->actingAs($other)->withAssurance(Assurance::AAL1)
            ->postJson(route('keyring.email.store'), ['email' => 'taylor@example.com'])->assertOk();

        Notification::assertSentTo(new AnonymousNotifiable, EmailAddressInUse::class, fn ($n, $c, $to) => $to->routes['mail'] === 'taylor@example.com');
        Notification::assertNotSentTo(new AnonymousNotifiable, ConfirmEmailChange::class, fn ($n, $c, $to) => $to->routes['mail'] === 'taylor@example.com');
    });

    it('cannot be given to another user however they are saved', function () {
        expect(fn () => taylor())->toThrow(ReservedAddressException::class);

        $other = taylor(['email' => 'other@example.com']);

        // Protected attributes are checked first, and lifting that protection
        // doesn't lift the reservation.
        expect(fn () => $other->update(['email' => 'taylor@example.com']))->toThrow(ProtectedAttributeException::class)
            ->and(fn () => Keyring::withoutProtection(fn () => $other->update(['email' => 'taylor@example.com'])))->toThrow(ReservedAddressException::class);
    });

    it('is refused by the validation rule, whatever its case', function () {
        expect(Validator::make(['email' => 'TAYLOR@example.com'], ['email' => new UnreservedAddress])->fails())->toBeTrue()
            ->and(Validator::make(['email' => 'someone@example.com'], ['email' => new UnreservedAddress])->fails())->toBeFalse();
    });

    it('stays reserved after APP_KEY is rotated', function () {
        config(['app.previous_keys' => [config('app.key')], 'app.key' => 'base64:'.base64_encode(random_bytes(32))]);

        expect(fn () => taylor())->toThrow(ReservedAddressException::class);
    });

    it('still goes back to its owner when the change is reverted', function () {
        expect(app(EmailChanges::class)->revert($this->change, $this->tokens['revert']))->toBeTrue()
            ->and($this->user->fresh()->email)->toBe('taylor@example.com');
    });

    // MySQL's default collations take these for the reserved address, so
    // its unique index would refuse to give the address back to its owner.
    it('cannot be registered under a spelling a database would take for it', function (string $lookalike) {
        revealTakenAddresses();
        $this->post('/logout');

        $this->post('/register', [
            'name' => 'Someone',
            'email' => $lookalike,
            'password' => 'correct horse battery staple',
            'password_confirmation' => 'correct horse battery staple',
        ])->assertSessionHasErrors(['email' => 'The email has already been taken.']);

        expect(User::count())->toBe(1)
            ->and(app(EmailChanges::class)->revert($this->change, $this->tokens['revert']))->toBeTrue()
            ->and($this->user->fresh()->email)->toBe('taylor@example.com');
    })->with([
        'an accent' => 'tàylor@example.com',
        'an accent in the domain' => 'taylor@exámple.com',
        'a combining accent' => "ta\u{0301}ylor@example.com",
        'full-width letters' => 'ｔａｙｌｏｒ@example.com',
        'a styled letter' => '𝐭aylor@example.com',
        'a character that does not show' => "tay\u{00AD}lor@example.com",
    ]);

    // Asked of MySQL 8.4: utf8mb4_general_ci takes "ß" for "s", and
    // utf8mb4_unicode_ci and utf8mb4_0900_ai_ci take it for "ss".
    it('is found under every spelling of a sharp s that some collation takes for it', function () {
        expect(PendingChange::fold('klauß@example.com'))
            ->toBe(PendingChange::fold('klaus@example.com'))
            ->toBe(PendingChange::fold('klauss@example.com'))
            ->toBe(PendingChange::fold('KLAUẞ@example.com'))
            ->not->toBe(PendingChange::fold('klaut@example.com'));
    });

    it('still lets a different address be registered', function (string $address) {
        $this->post('/logout');

        $this->post('/register', [
            'name' => 'Someone',
            'email' => $address,
            'password' => 'correct horse battery staple',
            'password_confirmation' => 'correct horse battery staple',
        ])->assertSessionHasNoErrors();

        expect(User::count())->toBe(2);
    })->with(['tailor@example.com', 'taylor@example.org', 'tay.lor@example.com', 'taylor+news@example.com']);

    it('is free again once the change can no longer be reverted', function () {
        $this->travel(8)->days();

        expect(taylor()->exists)->toBeTrue();
    });
});

/**
 * A signed-in session on another device, as the registry holds it.
 */
function otherSession(User $user, string $id = 'other-session'): string
{
    $now = now()->getTimestamp();

    app(SessionRegistry::class)->save(new RegisteredSession(
        id: $id,
        userId: (string) $user->getKey(),
        userType: RegisteredSession::typeOf($user),
        guard: 'web',
        deviceId: null,
        assurance: Assurance::AAL1,
        ip: '198.51.100.1',
        userAgent: 'Other device',
        authenticatedAt: $now,
        lastActivityAt: $now,
        expiresAt: $now + 86400,
    ));

    return $id;
}

describe('whose verification waives the current address', function () {
    it('still asks the current address when the session verified someone else\'s factor', function () {
        $admin = taylor(['email' => 'admin@example.com']);
        $totp = Authenticator::factory()->totp()->for($admin, 'authenticatable')->create(['created_at' => now()->subMonth()]);

        $this->post('/login', ['email' => 'admin@example.com', 'password' => 'password']);
        $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)]);
        $this->travel(1)->minutes();

        // An app's own "become this user", without clearing what the session proved.
        Route::middleware(['web', 'auth'])->post('/become/{id}', function (string $id) {
            session()->forget(Sessions::KEY);
            Auth::guard('web')->login(User::findOrFail($id));

            return 'ok';
        });
        $this->post('/become/'.$this->user->getKey())->assertOk();
        $this->travel(1)->seconds();

        $this->postJson(route('keyring.email.store'), ['email' => 'new@example.com'])->assertOk();

        expect(PendingChange::query()->ownedBy($this->user)->sole()->current_token)->not->toBeNull();
    });
});

describe('applying a change', function () {
    it('ends the account\'s other sessions and keeps the one that confirmed', function () {
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        $this->postJson(route('keyring.email.store'), ['email' => 'new@example.com'])->assertOk();
        $change = PendingChange::sole();
        $tokens = tokensFor('new@example.com', 'taylor@example.com');
        $current = app(Sessions::class)->current(request())->id;
        $other = otherSession($this->user);

        $this->post(route('keyring.email.confirm.store', $change->id), ['token' => $tokens['current']]);
        $this->post(route('keyring.email.confirm.store', $change->id), ['token' => $tokens['confirm']]);

        expect($this->user->fresh()->email)->toBe('new@example.com')
            ->and(app(SessionRegistry::class)->find($other)->revokedAt)->not->toBeNull()
            ->and(app(SessionRegistry::class)->find($current)->revokedAt)->toBeNull();

        $this->assertAuthenticatedAs($this->user->fresh());
    });

    it('gives the confirming browser a new session id', function () {
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        $this->postJson(route('keyring.email.store'), ['email' => 'new@example.com'])->assertOk();
        $change = PendingChange::sole();
        $tokens = tokensFor('new@example.com', 'taylor@example.com');
        $this->post(route('keyring.email.confirm.store', $change->id), ['token' => $tokens['current']]);
        $before = session()->getId();

        $this->withCookie(config('session.cookie'), $before)
            ->post(route('keyring.email.confirm.store', $change->id), ['token' => $tokens['confirm']])->assertSessionHas('status', 'email-changed');

        expect(session()->getId())->not->toBe($before)
            ->and(session()->getId())->not->toBeEmpty();
    });

    it('signs out everywhere when confirmed by a browser that is not signed in as the account', function () {
        $change = requestChange($this->user, 'new@example.com');
        $tokens = tokensFor('new@example.com', 'taylor@example.com');
        $other = otherSession($this->user);

        $this->flushSession();
        Auth::guard('web')->logout();
        Auth::forgetGuards();
        $this->withSession([Sessions::KEY => $other]); // left behind, so only the guard says who this is

        $this->post(route('keyring.email.confirm.store', $change->id), ['token' => $tokens['current']]);
        $this->post(route('keyring.email.confirm.store', $change->id), ['token' => $tokens['confirm']]);

        expect($this->user->fresh()->email)->toBe('new@example.com')
            ->and(app(SessionRegistry::class)->find($other)->revokedAt)->not->toBeNull();
    });

    it('does not keep the session of a browser signed in as someone else', function () {
        $change = requestChange($this->user, 'new@example.com');
        $tokens = tokensFor('new@example.com', 'taylor@example.com');
        $other = otherSession($this->user);

        $stranger = taylor(['email' => 'stranger@example.com']);
        $this->flushSession();
        Auth::guard('web')->logout();
        Auth::forgetGuards();
        $this->actingAs($stranger);

        $this->post(route('keyring.email.confirm.store', $change->id), ['token' => $tokens['current']]);
        $before = session()->getId();
        $this->withCookie(config('session.cookie'), $before)->post(route('keyring.email.confirm.store', $change->id), ['token' => $tokens['confirm']]);

        expect($this->user->fresh()->email)->toBe('new@example.com')
            ->and(app(SessionRegistry::class)->find($other)->revokedAt)->not->toBeNull()
            ->and(session()->getId())->toBe($before);
    });

    it('leaves other sessions alone when the app opts out', function () {
        config(['keyring.email_changes.sign_out_others' => false]);
        $change = requestChange($this->user, 'new@example.com');
        $tokens = tokensFor('new@example.com', 'taylor@example.com');
        $other = otherSession($this->user);

        confirmBoth($change, $tokens);

        expect(app(SessionRegistry::class)->find($other)->revokedAt)->toBeNull();
    });

    it('does not touch device tables when devices are off, but to end trust given while they were on', function () {
        withFeatures([Features::emailChanges()]);
        $change = requestChange($this->user, 'new@example.com');
        $tokens = tokensFor('new@example.com', 'taylor@example.com');
        DB::enableQueryLog();

        confirmBoth($change, $tokens);

        expect(collect(DB::getQueryLog())->pluck('query')->filter(fn (string $query) => str_contains($query, 'keyring_devices'))->reject(fn (string $query) => preg_match('/^update .keyring_devices. set .trusted_until. = \?/', $query) === 1)->all())->toBe([])
            ->and($this->user->fresh()->email)->toBe('new@example.com');
    });

    it('tells both addresses when the app has opted in', function () {
        sendNotifications();
        $change = requestChange($this->user, 'new@example.com');
        $tokens = tokensFor('new@example.com', 'taylor@example.com');

        confirmBoth($change, $tokens);

        Notification::assertSentTo($this->user, EmailChanged::class);
        Notification::assertSentTo(new AnonymousNotifiable, EmailChanged::class, fn ($notice, $channels, $to) => $to->routes['mail'] === 'taylor@example.com');
    });

    it('sends no notice the app turned off', function () {
        Keyring::notifications(['email_changed' => null]);
        $change = requestChange($this->user, 'new@example.com');
        $tokens = tokensFor('new@example.com', 'taylor@example.com');

        confirmBoth($change, $tokens);

        Notification::assertNotSentTo($this->user, EmailChanged::class);
        Notification::assertNotSentTo(new AnonymousNotifiable, EmailChanged::class);
    });

    it('tells both addresses when an applied change is reverted', function () {
        sendNotifications();
        $change = requestChange($this->user, 'new@example.com');
        $tokens = tokensFor('new@example.com', 'taylor@example.com');
        confirmBoth($change, $tokens);

        app(EmailChanges::class)->revert($change->fresh(), $tokens['revert']);

        Notification::assertSentTo($this->user, EmailChangeReverted::class, fn (EmailChangeReverted $notice) => $notice->ip !== null);
        Notification::assertSentTo(new AnonymousNotifiable, EmailChangeReverted::class, fn (EmailChangeReverted $notice, $channels, $to) => $to->routes['mail'] === 'new@example.com'
            && $notice->ip === null
            && $notice->device === null);
    });

    it('sends the app\'s own notice to the address that has no user, too', function () {
        Keyring::notifications(['email_changed' => OwnEmailChanged::class, 'email_change_reverted' => null]);
        $change = requestChange($this->user, 'new@example.com');
        $tokens = tokensFor('new@example.com', 'taylor@example.com');

        $this->post(route('keyring.email.confirm.store', $change->id), ['token' => $tokens['current']]);
        $this->post(route('keyring.email.confirm.store', $change->id), ['token' => $tokens['confirm']])->assertSessionHas('status', 'email-changed');

        Notification::assertSentTo($this->user, OwnEmailChanged::class);
        Notification::assertSentTo(new AnonymousNotifiable, OwnEmailChanged::class, fn ($notice, $channels, $to) => $to->routes['mail'] === 'taylor@example.com');
    });

    it('does not mail the address that never confirmed when a pending change is reverted', function () {
        sendNotifications();
        $change = requestChange($this->user, 'attacker@example.com');
        $tokens = tokensFor('attacker@example.com', 'taylor@example.com');

        app(EmailChanges::class)->revert($change->fresh(), $tokens['revert']);

        Notification::assertSentTo($this->user, EmailChangeReverted::class);
        Notification::assertNotSentTo(new AnonymousNotifiable, EmailChangeReverted::class);
    });
});

it('asks for nothing when the address typed is the one the account already has', function () {
    $change = requestChange($this->user, 'new@example.com');
    Notification::fake();

    $this->actingAs($this->user)->withAssurance(Assurance::AAL1)
        ->postJson(route('keyring.email.store'), ['email' => 'Taylor@Example.com'])->assertOk();

    // The change already asked for stands, and nobody is mailed.
    expect(app(EmailChanges::class)->pending($this->user)?->is($change))->toBeTrue();
    Notification::assertNothingSent();
});

it('saves nothing when the address already moved to the one asked for after the user was loaded', function () {
    $loaded = User::find($this->user->id);
    User::query()->whereKey($this->user->id)->update(['email' => 'new@example.com']);

    $request = Request::create('/');
    $request->setLaravelSession(session()->driver());

    expect(app(EmailChanges::class)->request($loaded, 'new@example.com', $request))->toBeNull()
        ->and(PendingChange::query()->count())->toBe(0);
});

it('asks the current address too when the request comes from a session keyring never signed in', function () {
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create(['created_at' => now()->subMonth()]);

    // It proved an established second factor, but there's no record of when it signed in.
    $this->verifiedWith($totp);
    expect(session()->has(Sessions::KEY))->toBeFalse();

    $request = Request::create('/');
    $request->setLaravelSession(session()->driver());

    $change = app(EmailChanges::class)->request($this->user, 'new@example.com', $request);

    expect($change->current_token)->not->toBeNull();
});

/**
 * An app's own notification, nothing to do with Keyring's.
 */
class OwnEmailChanged extends Illuminate\Notifications\Notification
{
    public function __construct(public string $when) {}

    public function via(object $notifiable): array
    {
        return ['mail'];
    }
}
