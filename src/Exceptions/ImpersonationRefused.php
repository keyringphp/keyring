<?php

declare(strict_types=1);

namespace Keyring\Exceptions;

use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Keyring\Enums\ImpersonationRefusal;
use Keyring\Http\Responses\ChoosesFormat;

/**
 * Keyring::impersonate() wouldn't sign in as that user: Laravel answers it
 * with a 403, whatever the reason. $reason says why, for code of the app's
 * own. It's never ImpersonationRefusal::NotFound, which is only logged:
 * an ID nobody has is thrown as NotAllowed. JSON clients get the
 * "impersonation-refused" status with it, the same for every reason, so
 * the answer never says why.
 */
class ImpersonationRefused extends AuthorizationException
{
    use ChoosesFormat;

    public function __construct(
        public readonly ImpersonationRefusal $reason,
    ) {
        parent::__construct(__('keyring::status.impersonation-refused'));
    }

    public function render(Request $request): ?JsonResponse
    {
        if (! $this->wantsJson($request)) {
            return null;
        }

        return new JsonResponse(['status' => 'impersonation-refused', 'message' => $this->getMessage()], 403);
    }
}
