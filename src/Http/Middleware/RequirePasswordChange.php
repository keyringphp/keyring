<?php

declare(strict_types=1);

namespace Keyring\Http\Middleware;

use Closure;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Uri;
use Keyring\Changes\PasswordHolds;
use Keyring\Contracts\Responses\PasswordChangeRequiredResponse;
use Keyring\Impersonation\Impersonation;
use Keyring\KeyringManager;
use Keyring\Login\Detours;
use Symfony\Component\HttpFoundation\Response;

/**
 * Keeps a user who has to choose a new password (Keyring::requirePasswordChange(),
 * or a risk response) on the page where they do, keyring.password_change_url,
 * until they have. Guests are let through, so it sits in the web group next
 * to the session middleware. So is a browser impersonating someone: only
 * the user can choose their password.
 */
class RequirePasswordChange
{
    /**
     * Routes they still need: changing the password, the confirmation that
     * takes, signing out and verifying their email.
     *
     * @var list<string>
     */
    protected array $except = ['user-password.update', 'keyring.confirm.*', 'logout', 'verification.*'];

    public function __construct(
        protected KeyringManager $keyring,
        protected PasswordHolds $holds,
        protected Detours $detours,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        $user = $this->keyring->guard()->user();

        if (! $user instanceof Model || ! $request->hasSession() || $this->isExcepted($request) || app(Impersonation::class)->active($request) || ! $this->holds->holdsSession($user)) {
            return $next($request);
        }

        // Saved here rather than in the response, so an app's own response
        // gets it too: the new password carries them on to it.
        $this->detours->remember($request, Detours::PASSWORD_CHANGE);

        return $this->keyring->response(PasswordChangeRequiredResponse::class)->toResponse($request);
    }

    /**
     * The page they're sent to is let through for every method, so a form
     * that posts back to its own address works too.
     */
    protected function isExcepted(Request $request): bool
    {
        $url = config('keyring.password_change_url');

        return $request->routeIs(...$this->except)
            || ($url !== null && $request->is(Uri::of($url)->path()));
    }
}
