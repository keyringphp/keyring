<?php

declare(strict_types=1);

namespace Keyring\Http\Controllers;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\QueryException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Keyring\Contracts\Responses\SignedOutResponse;
use Keyring\Enums\ImpersonationEndReason;
use Keyring\Http\Controllers\Concerns\RespondsWithStatus;
use Keyring\Http\Responses\ChoosesFormat;
use Keyring\Impersonation\Impersonation;
use Keyring\KeyringManager;
use Symfony\Component\HttpFoundation\Response;

/**
 * Starting and stopping an impersonation. Both clear what the browser
 * cached and stored for the site, as signing out does: none of one
 * account's pages stay for the other to see. An Inertia visit is told to
 * load the next page in full, as the session middleware does when an
 * impersonation ends by itself, rather than swapping it into a page that
 * was the other account's.
 */
class ImpersonationController
{
    use ChoosesFormat, RespondsWithStatus;

    public function __construct(
        protected KeyringManager $keyring,
        protected Impersonation $impersonation,
    ) {}

    /**
     * Sign in as the user with this ID, as Keyring's guard loads them. One
     * that doesn't exist is refused like one that may not be impersonated,
     * so the answer doesn't say which IDs have an account. The log says
     * which it was. So is one the database won't look up at all, like
     * "abc" for an integer key on PostgreSQL, rather than failing: an error
     * in SQLSTATE class 22, data the column won't take. Any other error,
     * a deadlock or a dropped connection say, is thrown on.
     */
    public function store(Request $request, string $user): Response
    {
        try {
            $found = $this->keyring->provider()->retrieveById($user);
        } catch (QueryException $e) {
            throw_unless(str_starts_with((string) ($e->errorInfo[0] ?? $e->getCode()), '22'), $e);

            $found = null;
        }

        $this->impersonation->start($request, $found instanceof Model ? $found : $this->impersonation->refuseUnknown($request, $user));

        return $this->answer($request, 'impersonation-started', $this->impersonation->redirectTo());
    }

    /**
     * Stop impersonating, and go back to being whoever started it. When
     * their own session has ended meanwhile, the browser is signed out.
     * With nobody being impersonated, a second stop from a stale tab say,
     * it's back already: a JSON client gets a 409 "not-impersonating", and
     * a page visit goes to impersonation.return_url as a stop would.
     */
    public function destroy(Request $request): Response
    {
        if (! $this->impersonation->active($request)) {
            return $this->notImpersonating($request);
        }

        if (! ($reason = $this->impersonation->end($request, ImpersonationEndReason::Stopped))->returns()) {
            return $this->keyring->response(SignedOutResponse::class, reason: $reason->value)->toResponse($request);
        }

        return $this->answer($request, 'impersonation-ended', $this->impersonation->returnTo());
    }

    protected function notImpersonating(Request $request): Response
    {
        $url = $this->impersonation->returnTo();

        if ($this->wantsJson($request)) {
            return new JsonResponse(['status' => 'not-impersonating', 'message' => $this->keyring->statusMessage('not-impersonating'), 'redirect' => $url], Response::HTTP_CONFLICT);
        }

        $request->session()->flash('status', 'not-impersonating');

        return $request->hasHeader('X-Inertia') ? $this->loadInFull($url) : redirect()->to($url);
    }

    protected function answer(Request $request, string $status, string $url): Response
    {
        if (! $request->hasHeader('X-Inertia')) {
            return $this->clearSiteData($this->status($status, redirect: $url)->toResponse($request));
        }

        $request->session()->flash('status', $status);

        return $this->clearSiteData($this->loadInFull($url));
    }
}
