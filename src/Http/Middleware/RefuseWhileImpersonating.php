<?php

declare(strict_types=1);

namespace Keyring\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Keyring\Impersonation\Impersonation;
use Symfony\Component\HttpFoundation\Response;

/**
 * Refuses a route to a browser that's impersonating someone, with a 403
 * (keyring.not-impersonating). Keyring puts it on every route that changes
 * how the user signs in or proves who they are, and on starting another
 * impersonation. Put it on your own routes that only the user should use,
 * like deleting their account or changing billing details.
 */
class RefuseWhileImpersonating
{
    public function __construct(
        protected Impersonation $impersonation,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        return $this->impersonation->active($request) ? $this->impersonation->refuse($request) : $next($request);
    }
}
