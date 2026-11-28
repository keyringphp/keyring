<?php

declare(strict_types=1);

namespace Keyring;

use Closure;
use Illuminate\Container\Attributes\Singleton;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Illuminate\Validation\ValidationException;
use Keyring\Activity\SecurityLog;
use Keyring\Changes\PasswordHolds;
use Keyring\Changes\ProtectedAttributes;
use Keyring\Concerns\BuildsResponses;
use Keyring\Concerns\HasKeyring;
use Keyring\Concerns\IdentifiesUsers;
use Keyring\Concerns\ManagesNotifications;
use Keyring\Concerns\ManagesPipeline;
use Keyring\Concerns\RegistersActions;
use Keyring\Concerns\RendersPages;
use Keyring\Concerns\SwapsModels;
use Keyring\Contracts\Factor;
use Keyring\Contracts\PrimaryFactor;
use Keyring\Devices\UserAgent;
use Keyring\Enums\ImpersonationRefusal;
use Keyring\Enums\Purpose;
use Keyring\Exceptions\EmailVerificationRequired;
use Keyring\Exceptions\ImpersonationRefused;
use Keyring\Exceptions\MissingTrait;
use Keyring\Factors\FactorRegistry;
use Keyring\Factors\Password;
use Keyring\Impersonation\Impersonation;
use Keyring\Login\Attempt;
use Keyring\Login\AttemptStore;
use Keyring\Login\Requirement;
use Keyring\Login\VerificationLink;
use Keyring\Models\SecurityEvent;
use Keyring\Pipeline\Context;
use Keyring\Pipeline\Steps\VerifyFactor;
use Keyring\Pipeline\Verifier;
use Keyring\Risk\RiskEngine;
use Keyring\Risk\RiskLocks;
use Keyring\Sso\Sso;
use Keyring\Support\Throttle;
use Keyring\Testing\FakeVerifyFactor;
use Keyring\Testing\KeyringFake;
use LogicException;
use Symfony\Component\HttpFoundation\Response;

/**
 * Built once and kept for as long as the app is, which under Octane is many
 * requests. Each of those runs in a copy of the booted app, so everything
 * here is resolved with app() when it's needed, from the copy handling the
 * request, and never from a container kept since boot.
 */
#[Singleton]
class KeyringManager
{
    use BuildsResponses, IdentifiesUsers, ManagesNotifications, ManagesPipeline, RegistersActions, RendersPages, SwapsModels;

    /** @var Closure(Authenticatable&Model, Attempt): Requirement|Requirement */
    protected Closure|Requirement $policy;

    /** @var bool|(Closure(Authenticatable&Model, Request): bool) */
    protected bool|Closure $signInAfterRegistering = true;

    /** @var (Closure(Authenticatable&Model): bool)|null */
    protected ?Closure $signInGate = null;

    /** @var (Closure(Authenticatable&Model): bool)|null */
    protected ?Closure $enrollmentGate = null;

    /** @var (Closure(Authenticatable&Model, Authenticatable&Model): bool)|null */
    protected ?Closure $impersonationGate = null;

    /** @var (Closure(Request): (string|null))|null */
    protected ?Closure $ipRecorder = null;

    /** @var (Closure(): string)|null */
    protected ?Closure $linkRoot = null;

    /** @var (Closure(string): (string|null))|null */
    protected ?Closure $deviceDescriber = null;

    /** @var array<class-string, bool> Whether each user model has the HasKeyring trait. */
    protected array $usesKeyring = [];

    public function __construct(
        protected FactorRegistry $factors,
        protected ProtectedAttributes $protection,
    ) {
        $this->policy = Requirement::aal2()->ifEnrolled();
    }

    /**
     * The factors users may sign in with. This replaces the list, so name
     * the password too if it stays.
     *
     * @param  list<class-string<Factor>|Factor|Closure(Container): Factor>  $factors
     */
    public function factors(array $factors): static
    {
        $this->factors->set($factors);

        return $this;
    }

    /**
     * Register a custom factor.
     *
     * @param  Closure(Container): Factor  $resolver
     */
    public function extend(string $key, Closure $resolver): static
    {
        $this->factors->extend($key, $resolver);

        return $this;
    }

    public function factor(string $key): Factor
    {
        return $this->factors->get($key);
    }

    public function hasFactor(string $key): bool
    {
        return $this->factors->has($key);
    }

    /**
     * @return Collection<string, Factor>
     */
    public function registered(): Collection
    {
        return $this->factors->all();
    }

    /**
     * Decide what users must prove to sign in.
     *
     * @param  Closure(Authenticatable&Model, Attempt): Requirement|Requirement  $policy
     */
    public function require(Closure|Requirement $policy): static
    {
        $this->policy = $policy;

        return $this;
    }

    /**
     * What the policy asks of this user, before considering what they've enrolled.
     */
    public function policy(Authenticatable&Model $user, Attempt $attempt): Requirement
    {
        return $this->policy instanceof Closure
            ? ($this->policy)($user, $attempt)
            : $this->policy;
    }

    /**
     * What this user must prove to complete the attempt. With $reachable, a
     * policy they can't fully meet is limited to what they can, as if it said
     * ifEnrolled(): for checks like re-verifying before adding the very key a
     * policy asks for.
     */
    public function requirementFor(Authenticatable&Model $user, Attempt $attempt, bool $reachable = false): Requirement
    {
        $requirement = $this->policy($user, $attempt);

        if ($reachable) {
            $requirement = $requirement->ifEnrolled();
        }

        // Only a key the account has had a while raises the bar: one added
        // from a stolen session signs in, but doesn't shut out the owner's
        // other factors until it's established.
        if ($requirement->noDowngrade && ! $requirement->requiresPhishingResistance
            && $attempt->keyring()->established()->canMeet(Requirement::aal1()->phishingResistant())) {
            $requirement = $requirement->withoutDowngrades();
        }

        return $requirement->onlyIfEnrolled
            ? $attempt->keyring()->reachable($requirement)
            : $requirement;
    }

    /**
     * Register Keyring's routes. Keyring does this itself unless the "routes"
     * option is false; then call it wherever you like, e.g. inside your own
     * route group with a prefix or extra middleware.
     */
    public function routes(): void
    {
        Route::middleware(config('keyring.middleware'))
            ->group(__DIR__.'/../routes/keyring.php');
    }

    /**
     * The risk engine, for choosing signals and what to do about them:
     *
     *     Keyring::risk()->signals([NewDevice::class])->respond(fn (Risk $risk) => ...);
     */
    public function risk(): RiskEngine
    {
        return app(RiskEngine::class);
    }

    /**
     * The identity providers users can sign in with, from keyring.sso.
     */
    public function sso(): Sso
    {
        return app(Sso::class);
    }

    /**
     * Pass or fail factor checks in tests without real codes or signatures.
     */
    public function fake(): KeyringFake
    {
        throw_if(app()->isProduction(), LogicException::class, 'Keyring::fake() cannot be used in production, where it would let wrong passwords and codes sign in. Only call it from your tests.');

        app()->singletonIf(KeyringFake::class);
        app()->bind(VerifyFactor::class, FakeVerifyFactor::class);

        return app(KeyringFake::class);
    }

    /**
     * Recent security activity for a settings page, leaving out the
     * unlistedActivityTypes().
     *
     * @return Collection<int, SecurityEvent>
     */
    public function activity(Authenticatable&Model $user, int $limit = 25): Collection
    {
        return app(SecurityLog::class)->activity($user, $limit);
    }

    /**
     * The entry types activity() leaves out, for an activity query of the
     * app's own: the strings in "security_log.unlisted", without Keyring's
     * own types, and the impersonation types when
     * "impersonation.show_in_activity" is false.
     *
     * @return list<string>
     */
    public function unlistedActivityTypes(): array
    {
        return app(SecurityLog::class)->unlistedActivityTypes();
    }

    /**
     * Everything the user can sign in with.
     */
    public function for(Authenticatable&Model $user): UserKeyring
    {
        $this->usesKeyring[$user::class] ??= in_array(HasKeyring::class, class_uses_recursive($user), true);

        if (! $this->usesKeyring[$user::class]) {
            throw MissingTrait::on($user::class);
        }

        return app(UserKeyring::class, ['user' => $user]);
    }

    /**
     * Whether registering signs the new user in, for an app whose
     * registration says when an address is taken ("registration.reveal_taken"):
     * pass false, or a callback deciding per user, to send them to the login
     * page instead (for example until an admin approves them). Otherwise
     * nobody is signed in by registering.
     *
     * @param  bool|(Closure(Authenticatable&Model, Request): bool)  $when
     */
    public function signInAfterRegistering(bool|Closure $when): static
    {
        $this->signInAfterRegistering = $when;

        return $this;
    }

    /**
     * Start a sign in with a factor that can, from a route of your own: a
     * social login's callback, say. It runs the same pipeline as Keyring's
     * login form (rate limits, the policy, risk), so a user with a second
     * factor is still asked for it. Answers as that form would, which for a
     * failure means throwing a ValidationException.
     *
     * @throws ValidationException
     */
    public function attempt(Request $request, string $factor = Password::KEY): Response
    {
        $factor = $this->factor($factor);

        abort_unless($factor instanceof PrimaryFactor && $factor->startsLogin(), 404);

        app(AttemptStore::class)->forget(Purpose::Login);

        return app(Verifier::class)->respond(new Context($request, Purpose::Login, $factor));
    }

    /**
     * Where emailed links start, in place of APP_URL: for an app on several
     * domains, the one this user is on. Don't take it from the request's
     * Host header, which whoever sends the request controls.
     *
     * @param  Closure(): string  $callback
     */
    public function linkRootUsing(Closure $callback): static
    {
        $this->linkRoot = $callback;

        return $this;
    }

    /**
     * Where emailed links start: APP_URL, unless the app says otherwise.
     * Never the request's Host header.
     */
    public function linkRoot(): string
    {
        return rtrim((string) ($this->linkRoot === null ? config('app.url') : ($this->linkRoot)()), '/');
    }

    /**
     * Name devices your own way, e.g. with a real user agent parser, in
     * place of Keyring's "Firefox on Windows". Return null for one it can't
     * name.
     *
     * @param  Closure(string): (string|null)  $callback
     */
    public function describeDevicesUsing(Closure $callback): static
    {
        $this->deviceDescriber = $callback;

        return $this;
    }

    /**
     * A user agent as a name people recognise, like "Firefox on Windows".
     * Also a weak risk signal (a session's browser changing), never a factor.
     *
     * A describer of the app's own is the app's code, run in the middle of
     * a sign in. One that throws is reported and gives no name, and a name
     * longer than a device's column holds is cut to fit, so neither fails
     * the sign in it was only naming a browser for.
     */
    public function describeDevice(?string $userAgent): ?string
    {
        if (blank($userAgent)) {
            return null;
        }

        if ($this->deviceDescriber === null) {
            return UserAgent::describe($userAgent);
        }

        $name = rescue(fn () => ($this->deviceDescriber)($userAgent));

        return is_string($name) ? mb_substr($name, 0, 255) : null;
    }

    /**
     * What Keyring keeps as a request's IP address, in the security log, on
     * devices and sessions, and in notices: return a shortened address, or
     * null to keep none. Rate limits always use the real one.
     *
     * @param  Closure(Request): (string|null)  $callback
     */
    public function recordIpsUsing(Closure $callback): static
    {
        $this->ipRecorder = $callback;

        return $this;
    }

    public function recordedIp(Request $request): ?string
    {
        return $this->ipRecorder === null ? $request->ip() : ($this->ipRecorder)($request);
    }

    /**
     * Decide who may be signed in at all, to keep out a banned account or
     * one nobody has approved yet. Keyring asks wherever a session starts or
     * carries on: every factor that can start a sign in, a sign in waiting
     * for its second factor, "remember me", and each request of a session
     * that's already signed in. Once the answer is no, that request is signed
     * out and every other session of the account ends with it. To end them
     * before any of them makes a request, call Sessions::signOutEverywhere().
     * An account that's turned away is answered like one that doesn't exist.
     * So is one that hasn't verified its address yet, when registration
     * hides who has an account.
     *
     * It's asked on every signed-in request, so answer from the user you're
     * given rather than with a query.
     *
     * @param  Closure(Authenticatable&Model): bool  $callback
     */
    public function allowSignInWhen(Closure $callback): static
    {
        $this->signInGate = $callback;

        return $this;
    }

    /**
     * Whether this user may be signed in: the app lets them, and they've
     * verified their address when registration hides who has an account.
     * There, a password that worked straight away would tell whoever just
     * registered an address that it was free. Until then they can only sign
     * in from the browser that followed their verification link.
     */
    public function allowsSignIn(Authenticatable&Model $user): bool
    {
        if ($this->hidesRegisteredAddresses()
            && $user instanceof MustVerifyEmail
            && ! $user->hasVerifiedEmail()
            && ! app(VerificationLink::class)->followedFor($user)) {
            return false;
        }

        return $this->signInGate === null || ($this->signInGate)($user);
    }

    /**
     * Whether registration answers the same for an address that has an
     * account and one that doesn't, which it does unless the app turned on
     * the "registration.reveal_taken" option. New users then sign in once
     * they've verified their address.
     */
    public function hidesRegisteredAddresses(): bool
    {
        return Features::enabled(Features::registration()) && ! config('keyring.registration.reveal_taken');
    }

    /**
     * Decide who may add a sign-in method, in place of Keyring's rule that
     * an app with registration on has its users verify their email first.
     * That rule is there because anyone can register someone else's address,
     * and a sign-in method they add outlives the owner's password reset: only
     * replace it with a check that the account is really its owner's.
     *
     * @param  Closure(Authenticatable&Model): bool  $callback
     */
    public function allowEnrollmentWhen(Closure $callback): static
    {
        $this->enrollmentGate = $callback;

        return $this;
    }

    /**
     * Whether the user may add a sign-in method.
     *
     * @throws EmailVerificationRequired when registration is on and nothing proves addresses
     */
    public function allowsEnrollment(Authenticatable&Model $user): bool
    {
        if ($this->enrollmentGate !== null) {
            return ($this->enrollmentGate)($user);
        }

        $verifies = $user instanceof MustVerifyEmail && Features::enabled(Features::emailVerification());

        throw_if(Features::enabled(Features::registration()) && ! $verifies, EmailVerificationRequired::forEnrollment($user::class));

        return ! $user instanceof MustVerifyEmail || $user->hasVerifiedEmail();
    }

    /**
     * Decide who may sign in as whom, with Features::impersonation(): given
     * the impersonator, then the user. Until this is called nobody may. It's
     * never asked about someone impersonating themselves, an account
     * Keyring's guard wouldn't load, or a user the app doesn't let sign in
     * (allowSignInWhen): those are always refused.
     *
     *     Keyring::allowImpersonationWhen(fn (User $impersonator, User $user) => $impersonator->isAdmin() && ! $user->isAdmin());
     *
     * It's asked again on every request while the impersonation lasts,
     * when the signed-in user is the one being impersonated, so decide
     * from its two arguments alone: not auth()->user(), $request->user()
     * or Gate::allows(), which would ask about the user. For a gate, ask
     * Gate::forUser($impersonator)->allows(...). One that throws on those
     * requests is reported and counts as a no, ending the impersonation,
     * rather than failing every request the browser makes. Asked before
     * starting, and by allowsImpersonation(), what it throws is thrown on.
     *
     * @param  Closure(Authenticatable&Model, Authenticatable&Model): bool  $callback
     */
    public function allowImpersonationWhen(Closure $callback): static
    {
        $this->impersonationGate = $callback;

        return $this;
    }

    /**
     * Whether $impersonator may sign in as $user, for a button that only
     * shows when they may. Starting asks more: that the impersonator isn't
     * impersonating already, and is in a session Keyring keeps track of.
     */
    public function allowsImpersonation(Authenticatable&Model $impersonator, Authenticatable&Model $user): bool
    {
        return $this->impersonationRefusal($impersonator, $user) === null;
    }

    /**
     * Why $impersonator may not sign in as $user, or null when they may:
     * Disabled, NoCallback, Self or NotAllowed, in that order. Like
     * allowsImpersonation(), it doesn't ask what starting asks of the
     * session too.
     */
    public function impersonationRefusal(Authenticatable&Model $impersonator, Authenticatable&Model $user): ?ImpersonationRefusal
    {
        return match (true) {
            ! Features::enabled(Features::impersonation()) => ImpersonationRefusal::Disabled,
            $this->impersonationGate === null => ImpersonationRefusal::NoCallback,
            $impersonator->is($user) => ImpersonationRefusal::Self,
            ! $this->belongsToGuard($impersonator),
            ! $this->belongsToGuard($user),
            ! $this->allowsSignIn($user),
            ($this->impersonationGate)($impersonator, $user) !== true => ImpersonationRefusal::NotAllowed,
            default => null,
        };
    }

    /**
     * Sign the browser in as $user, on behalf of whoever is signed in, for a
     * controller of your own: Keyring's keyring.impersonation.store route
     * calls this. Check the request is a POST that proved enough first, as
     * that route's middleware does, and block() the route as it is, so two
     * starts sent at once take turns. Nothing the impersonator proved carries
     * over, and the session can't prove anything as the user.
     *
     * @throws ImpersonationRefused
     */
    public function impersonate(Request $request, Authenticatable&Model $user): void
    {
        app(Impersonation::class)->start($request, $user);
    }

    /**
     * Stop impersonating. Returns the impersonator, back in their own
     * session, or null when that session had ended and the browser was
     * signed out instead.
     *
     * @throws LogicException when nobody is being impersonated
     */
    public function stopImpersonating(Request $request): (Authenticatable&Model)|null
    {
        return app(Impersonation::class)->stop($request);
    }

    /**
     * Whether the request's session is impersonating someone.
     */
    public function impersonating(?Request $request = null): bool
    {
        return app(Impersonation::class)->active($request ?? request());
    }

    /**
     * Who is impersonating the signed-in user, or null when nobody is.
     */
    public function impersonator(?Request $request = null): (Authenticatable&Model)|null
    {
        return app(Impersonation::class)->impersonator($request ?? request());
    }

    /**
     * The impersonation for a page to show: who is impersonating, since
     * when, until when, and where to stop. Null when nobody is. It's read
     * from the session, so it's cheap to share with every page.
     *
     * @return array{impersonator: array{id: string, name: ?string}, startedAt: string, expiresAt: string, stopUrl: ?string}|null
     */
    public function impersonation(?Request $request = null): ?array
    {
        return app(Impersonation::class)->toArray($request ?? request());
    }

    /**
     * Let a user who's been locked out try again without resetting their
     * password, from a support tool say. Lifts their risk lock and clears
     * the limits on the factors that can start a sign in, with whatever
     * their failures in a row had got refused, as a completed password
     * reset does. A second factor's stay.
     *
     * Name a factor to clear that one's instead, whichever kind it is: a
     * second factor refused at the cap has nothing else that brings it
     * back short of removing it. Check who's asking first. Nothing here
     * does, and for a second factor that's the only thing between whoever
     * has the password and another round of guesses.
     */
    public function unlock(Authenticatable&Model $user, ?string $factor = null): void
    {
        if ($factor !== null) {
            app(Throttle::class)->clearFactor($user, $this->factor($factor));

            return;
        }

        app(RiskLocks::class)->unlock($user);
        app(Throttle::class)->clearAccount($user);
    }

    /**
     * Hold a user until they choose a new password, when you have reason to
     * think theirs is known to someone else: a breach of your own, a report
     * from the user, a credential-stuffing run. They can still sign in, and
     * every page sends them to keyring.password_change_url until the
     * password changes, by them or by a reset. Signing out doesn't shake it
     * off. Returns false for an account with no password, which is left
     * alone. A risk response does the same with requirePasswordChange(),
     * as Keyring's own does when the BreachedPassword signal finds the
     * password just used in a breach.
     */
    public function requirePasswordChange(Authenticatable&Model $user, ?string $reason = null): bool
    {
        return app(PasswordHolds::class)->place($user, $reason);
    }

    /**
     * Whether the user is held until they choose a new password.
     */
    public function requiresPasswordChange(Authenticatable&Model $user): bool
    {
        return app(PasswordHolds::class)->holds($user);
    }

    /**
     * Stop holding a user for a new password without one being set, when
     * the evidence turned out to be wrong. An app that saves passwords
     * outside Keyring's flows calls this once it has saved a new one.
     */
    public function cancelPasswordChange(Authenticatable&Model $user): void
    {
        app(PasswordHolds::class)->lift($user);
    }

    /**
     * Whether registering signs this user in, for a registration flow of
     * your own that should follow the same rule.
     */
    public function signsInAfterRegistering(Authenticatable&Model $user, Request $request): bool
    {
        return ! $this->hidesRegisteredAddresses() && $this->allowsSignIn($user) && (is_bool($this->signInAfterRegistering)
            ? $this->signInAfterRegistering
            : ($this->signInAfterRegistering)($user, $request));
    }

    /**
     * Attributes that may only change through Keyring's flows. Pass a user
     * whose model keeps its password under another name to get that name.
     *
     * @return list<string>
     */
    public function protectedAttributes(?Model $user = null): array
    {
        return $this->protection->all($user);
    }

    /**
     * Change protected attributes outside a Keyring flow, for trusted admin
     * tooling. Every use is announced with a ProtectionBypassed event.
     *
     * @template T
     *
     * @param  Closure(): T  $callback
     * @return T
     */
    public function withoutProtection(Closure $callback, ?string $reason = null): mixed
    {
        return $this->protection->bypass($callback, $reason);
    }
}
