<?php

declare(strict_types=1);

namespace Keyring\Http\Middleware;

use Closure;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use Illuminate\Support\Uri;
use Keyring\Impersonation\Impersonation;
use Keyring\KeyringManager;
use Keyring\Login\Requirement;
use Keyring\Login\StepUp;
use Symfony\Component\HttpFoundation\Response;

/**
 * Users must have set up what a level needs before going further, e.g.
 * keyring.enrolled (AAL2) on the whole app: they sign in with what they have,
 * then add a second factor. Recovery codes don't count, and an emailed code
 * isn't a factor. Users who haven't are sent to keyring.enrollment_url. Guests
 * are let through, so it can sit in the web group and leave them to auth.
 * So is a browser impersonating someone: it can't add anything for them.
 */
class RequireEnrollment
{
    /**
     * Routes users still need: Keyring's own (enrolling, confirming, devices),
     * signing out, verifying their email and changing their password.
     *
     * @var list<string>
     */
    protected array $except = ['keyring.*', 'logout', 'verification.*', 'user-password.update'];

    public function __construct(
        protected KeyringManager $keyring,
        protected StepUp $stepUp,
    ) {}

    public function handle(Request $request, Closure $next, string $level = 'aal2', string ...$also): Response
    {
        $requirement = Requirement::named($level, ...$also);
        $url = config('keyring.enrollment_url');

        $user = $this->keyring->guard()->user();

        if (! $user instanceof Model || $this->isExcepted($request, $url) || app(Impersonation::class)->active($request) || $this->keyring->for($user)->withoutFallbacks()->canMeet($requirement)) {
            return $next($request);
        }

        return $this->stepUp->enrollFirst($request, requirement: $this->toCarryOn($request, $requirement));
    }

    /**
     * What the page is saved with: this level, and any keyring:{level} the
     * route asks for too, whichever alias it's under. Otherwise a user who
     * adds enough for this one would be handed the page, only to be sent
     * back to enroll by the route's own level.
     */
    protected function toCarryOn(Request $request, Requirement $requirement): Requirement
    {
        $route = $request->route();

        foreach ($route instanceof Route ? app(Router::class)->gatherRouteMiddleware($route) : [] as $middleware) {
            [$class, $parameters] = is_string($middleware) ? array_pad(explode(':', $middleware, 2), 2, '') : [null, ''];

            if (is_string($class) && is_a($class, RequireAssurance::class, true)) {
                $requirement = $requirement->atLeast(Requirement::named(...explode(',', $parameters ?: 'aal2')));
            }
        }

        return $requirement;
    }

    /**
     * The page they're sent to is always let through too, so it can't send
     * them round in a loop.
     */
    protected function isExcepted(Request $request, ?string $url): bool
    {
        return $request->routeIs(...$this->except, ...config('keyring.enrollment_except'))
            || ($url !== null && $request->is(Uri::of($url)->path()));
    }
}
