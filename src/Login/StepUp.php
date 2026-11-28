<?php

declare(strict_types=1);

namespace Keyring\Login;

use DateTimeInterface;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Request;
use InvalidArgumentException;
use Keyring\Contracts\Responses\ConfirmationRequiredResponse;
use Keyring\Contracts\Responses\EnrollmentRequiredResponse;
use Keyring\Devices\DeviceManager;
use Keyring\Enums\Assurance;
use Keyring\Enums\Category;
use Keyring\Enums\Purpose;
use Keyring\Factors\RecoveryCodes;
use Keyring\Impersonation\Impersonation;
use Keyring\KeyringManager;
use Keyring\Sessions\SessionAssurance;
use Keyring\UserKeyring;
use Symfony\Component\HttpFoundation\Response;

/**
 * Sends a signed-in user to prove something again before continuing.
 */
class StepUp
{
    /**
     * How many seconds ahead of this server's clock unlessMet() takes a
     * moment to be, as one another server stored a little ahead of it.
     */
    public const int CLOCK_LEEWAY = 5;

    public function __construct(
        protected AttemptStore $attempts,
        protected SessionAssurance $assurance,
        protected KeyringManager $keyring,
        protected DeviceManager $devices,
        protected Detours $detours,
    ) {}

    /**
     * Ask for step-up from a controller, when the session hasn't reached a
     * level, or the user hasn't verified at or after a moment, or both.
     * Null means the request may carry on. Otherwise it's the answer the
     * keyring and keyring.fresh middleware give: the confirm page, or
     * enrolling first for a user who can't reach what's asked.
     *
     * Freshness asks what keyring.fresh does, the strongest combination the
     * account can give, verified at or after $since. With a level as well,
     * both are asked for in one confirm, or in turn when the account can't
     * freshly prove the level (unlessFresh()). Give $since as a fixed
     * moment: once the user confirms, any moment before the confirm is
     * met, so the check can't send them round again. Each factor is stamped when it's proved,
     * so a confirm in two steps only meets moments up to its first step. A
     * moment that moves on with every request can send them round forever.
     *
     * @throws AuthenticationException when nobody is signed in to Keyring's guard
     * @throws InvalidArgumentException when nothing is asked, the level is
     *                                  none, or $since is further in the
     *                                  future than CLOCK_LEEWAY
     */
    public function unlessMet(Request $request, ?Assurance $level = null, ?DateTimeInterface $since = null): ?Response
    {
        $asked = $this->asked($level, $since);

        return $asked instanceof Assurance
            ? $this->unlessReached($request, $asked, Requirement::for($asked))
            : $this->unlessFresh($request, $asked, $level);
    }

    /**
     * Whether unlessMet() would let the request carry on, asked without
     * starting a confirm, saving the page to come back to, or sending the
     * user to enroll. For a request that must not show anything, such as an
     * OpenID Connect prompt=none, which answers login_required instead.
     *
     * @throws AuthenticationException when nobody is signed in to Keyring's guard
     * @throws InvalidArgumentException as unlessMet() does
     */
    public function meets(Request $request, ?Assurance $level = null, ?DateTimeInterface $since = null): bool
    {
        $asked = $this->asked($level, $since);

        // Throws for a guest, as unlessReached() does.
        $this->keyring->user();

        if ($asked instanceof Assurance) {
            return $this->reached($asked, Requirement::for($asked));
        }

        $requirement = $this->freshRequirement($request, $level);

        return $this->verifiedSince($asked, $requirement, $level)
            || ($level !== null && $this->inTurn($requirement) && $this->reached($level, Requirement::for($level)) && $this->verifiedSince($asked, $this->freshRequirement($request), null));
    }

    /**
     * The keyring middleware's decision: the session must have reached the
     * level, and what still counts toward it must meet the requirement.
     * What's missing is asked for, building on what still counts.
     *
     * @internal
     */
    public function unlessReached(Request $request, Assurance $level, Requirement $requirement): ?Response
    {
        // Throws for a guest. Their session can still hold what the last user
        // proved, when the guard can no longer load that user, say because
        // the account was deleted.
        $this->keyring->user();

        if ($this->reached($level, $requirement)) {
            return null;
        }

        return $this->require($request, $requirement, $this->assurance->countingToward($level));
    }

    /**
     * The keyring.fresh middleware's decision: what freshRequirement() asks,
     * verified at or after the timestamp. With a level, the session must
     * have reached it too, and a confirm asks for both at once. It asks
     * afresh rather than building on what was proved before.
     *
     * When a confirm can't give both at once, the two are asked in turn
     * (inTurn()): the level first, building on what still counts toward
     * it, then the fresh verification alone. A user with a link whose sign
     * ins are never fresh and an authenticator app, and no password, can't
     * freshly prove AAL2, but reaches it with a round trip and the app, and
     * the app is then fresh.
     *
     * @internal
     */
    public function unlessFresh(Request $request, int $since, ?Assurance $level = null): ?Response
    {
        $requirement = $this->freshRequirement($request, $level);

        if ($this->verifiedSince($since, $requirement, $level)) {
            return null;
        }

        if ($level !== null && $this->inTurn($requirement)) {
            return $this->unlessReached($request, $level, Requirement::for($level))
                ?? $this->unlessFresh($request, $since);
        }

        return $this->require($request, $requirement);
    }

    /**
     * @param  list<Verification>  $proved  what still counts from this session, to build on
     *                                      (raising assurance), or nothing to ask afresh
     */
    public function require(Request $request, Requirement $requirement, array $proved = []): Response
    {
        // Whoever is impersonating the user can't prove anything as them.
        if (app(Impersonation::class)->active($request)) {
            return app(Impersonation::class)->refuse($request);
        }

        // Without the sign-in methods to meet it on the confirm page,
        // building on what's proved, confirming can't help: the user would
        // prove what they can and be stuck, or go round in a loop.
        if (! $this->keyring->for($this->keyring->user())->canConfirm($requirement, $proved)) {
            return $this->enrollFirst($request, requirement: $requirement);
        }

        $this->begin($request, $requirement, $proved);

        return $this->keyring->response(ConfirmationRequiredResponse::class)->toResponse($request);
    }

    /**
     * Send a user who hasn't set up what's needed to keyring.enrollment_url,
     * or answer 403 when there isn't one. Where they were going is saved,
     * for the enrollment to hand back as "continue" once the account can
     * meet $requirement.
     *
     * @param  string|null  $continue  where to carry on to instead of this
     *                                 page, for one of Keyring's own pages
     *                                 that was there on another's behalf
     * @param  Requirement|null  $requirement  what the account couldn't meet;
     *                                         without one, the first sign-in
     *                                         method added hands it back
     */
    public function enrollFirst(Request $request, ?string $continue = null, ?Requirement $requirement = null): Response
    {
        $this->detours->remember($request, Detours::ENROLLMENT, $continue, $requirement);

        return $this->keyring->response(EnrollmentRequiredResponse::class)->toResponse($request);
    }

    /**
     * Start a confirm attempt, or carry on with the one in progress when it's
     * for the same requirement, so a page that asks again halfway through
     * doesn't lose what the user already proved.
     *
     * @param  list<Verification>  $proved
     */
    public function begin(Request $request, Requirement $requirement, array $proved = []): Attempt
    {
        $current = $this->attempts->current(Purpose::Confirm);

        if ($current?->requirement?->toArray() === $requirement->toArray()) {
            return $current;
        }

        return $this->attempts->start(
            Purpose::Confirm,
            $this->keyring->user(),
            requirement: $requirement,
            verifications: $proved,
        );
    }

    /**
     * What a fresh verification asks of the signed-in user: the strongest
     * combination their account can give, at least what signing in would
     * ask of them, and a possession factor whenever they have one. Only
     * what can be proved recently counts (Requirement::freshlyProved()):
     * not a link at an identity provider whose sign ins are never fresh.
     * Otherwise a stolen session plus one phished factor could add new ones
     * without ever touching the rest.
     *
     * The policy is asked twice: about this browser as a sign in would find
     * it, and about one nothing is known of. The stricter answer stands, so
     * a policy that asks more of a new device is heard here, and one that
     * asks less of a trusted device gets no discount.
     *
     * With a level, it asks for that level's requirement as well, and takes
     * a recovery code beside another factor as the level alone would.
     */
    public function freshRequirement(Request $request, ?Assurance $level = null): Requirement
    {
        $user = $this->keyring->user();
        // Only what a confirm can prove recently. A link at a provider whose
        // sign ins are never fresh can't, so a user with one and a second
        // factor, and no password, gives the second factor alone.
        $keyring = $this->keyring->for($user)->withoutFallbacks()->freshlyProvable();

        $here = Attempt::start(Purpose::Login, $user);
        $here->resolveDevice($this->devices->find($request, $user)?->id);

        $policy = $this->keyring->requirementFor($user, $here, reachable: true)
            ->atLeast($this->keyring->requirementFor($user, Attempt::start(Purpose::Login, $user), reachable: true));

        // Together they must still be something the account can prove, or
        // it could never add anything again.
        $requirement = $keyring->reachable($policy->atLeast($this->strongest($keyring, $policy)));

        if ($keyring->has(Category::Possession)) {
            $requirement = $requirement->atLeast(Requirement::aal1()->including(Category::Possession));
        }

        if ($level !== null) {
            $requirement = $requirement->atLeast(Requirement::for($level));
        }

        // A recovery code stands in for a lost factor beside another one. It
        // is never the whole of a verification: with one factor to prove,
        // that factor is what's asked for.
        $requirement = $requirement->freshlyProved();

        return $requirement->factors < 2 ? $requirement->withoutRecoveryCodes() : $requirement;
    }

    /**
     * What unlessMet() and meets() are asked: a level alone, or the moment
     * to have verified since, as a timestamp no later than now. Both refuse
     * the same arguments here.
     *
     * @throws InvalidArgumentException
     */
    protected function asked(?Assurance $level, ?DateTimeInterface $since): Assurance|int
    {
        if ($level === Assurance::None) {
            throw new InvalidArgumentException('Ask for a level of at least AAL1.');
        }

        if ($level === null && $since === null) {
            throw new InvalidArgumentException('Ask for a level, a verification since a moment, or both.');
        }

        $now = now()->getTimestamp();

        // Nothing verified later could reach a moment that hasn't come yet,
        // until it does, so the user would confirm and be asked again. A
        // moment just ahead is another server's clock, and is taken as now.
        if ($since !== null && $since->getTimestamp() > $now + static::CLOCK_LEEWAY) {
            throw new InvalidArgumentException('A verification can\'t be asked for since a moment in the future.');
        }

        return $since === null ? $level : min($since->getTimestamp(), $now);
    }

    /**
     * Whether a level and a fresh verification are asked in turn: a confirm
     * can't give their requirement together (freshRequirement() with the
     * level), since the account can't freshly prove the level.
     */
    protected function inTurn(Requirement $requirement): bool
    {
        return ! $this->keyring->for($this->keyring->user())->canConfirm($requirement);
    }

    /**
     * Whether the session has reached the level, and what still counts
     * toward it meets the requirement.
     */
    protected function reached(Assurance $level, Requirement $requirement): bool
    {
        return $this->assurance->level()->atLeast($level) && $requirement->isMetBy($this->assurance->countingToward($level));
    }

    /**
     * Whether the user proved what the requirement asks at or after the
     * timestamp, by when they really proved it, with a recovery code
     * counting only where it takes one.
     * With a level, the session must have reached it too.
     */
    protected function verifiedSince(int $since, Requirement $requirement, ?Assurance $level): bool
    {
        if ($level !== null && ! $this->reached($level, Requirement::for($level))) {
            return false;
        }

        $proved = $this->assurance->provedSince($since);

        if (! $requirement->acceptsRecoveryCodes) {
            $proved = array_values(array_filter($proved, fn (Verification $verification) => $verification->factor !== RecoveryCodes::KEY));
        }

        return $requirement->isMetBy($proved);
    }

    /**
     * The most the account's authenticators can prove together, whatever
     * the policy asks at sign in. NIST SP 800-63B-4 (Sec. 4.1.2.1) has a new
     * authenticator bound at the highest level the account can reach, or at
     * the level the new one will be used at if that's lower. Keyring always
     * asks for the highest: otherwise a user who holds a key that can't
     * leave its device could add another after proving only a password and
     * a code.
     *
     * A key nothing vouches for is asked for too: if it is what it says, it
     * is the best the account has. A recovery code is taken in a lost key's
     * place, as it is at sign in, unless the policy takes none there. An
     * account with nothing beyond one factor proves that, so it can always
     * add its first.
     *
     * Only established keys count, as they do for noDowngrade(): otherwise
     * a key added from a stolen session would be the one thing the owner
     * had to prove to remove it.
     */
    protected function strongest(UserKeyring $keyring, Requirement $policy): Requirement
    {
        $strongest = array_find([Requirement::aal3(), Requirement::aal2()->deviceBound()], $keyring->established()->canMeet(...));

        return $strongest?->acceptingInstead($policy->noDowngrade ? $policy->downgradeExceptions : [RecoveryCodes::KEY])
            ?? $keyring->reachable(Requirement::aal2());
    }
}
