<?php

declare(strict_types=1);

namespace Keyring\Facades;

use Illuminate\Support\Facades\Facade;
use Keyring\KeyringManager;

/**
 * @method static \Keyring\KeyringManager factors(list<class-string<\Keyring\Contracts\Factor>|\Keyring\Contracts\Factor|\Closure> $factors)
 * @method static \Keyring\KeyringManager extend(string $key, \Closure $resolver)
 * @method static \Keyring\Contracts\Factor factor(string $key)
 * @method static bool hasFactor(string $key)
 * @method static \Illuminate\Support\Collection<string, \Keyring\Contracts\Factor> registered()
 * @method static \Keyring\KeyringManager require(\Closure|\Keyring\Login\Requirement $policy)
 * @method static \Keyring\Login\Requirement policy(\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model $user, \Keyring\Login\Attempt $attempt)
 * @method static \Keyring\Login\Requirement requirementFor(\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model $user, \Keyring\Login\Attempt $attempt, bool $reachable = false)
 * @method static \Keyring\KeyringManager page(string $name, \Closure|string $component)
 * @method static mixed render(string $name, array<string, mixed> $props = [])
 * @method static void routes()
 * @method static \Keyring\KeyringManager pipeline(\Closure $callback)
 * @method static list<class-string> steps()
 * @method static list<class-string> dangerouslyChangedSteps()
 * @method static \Keyring\Risk\RiskEngine risk()
 * @method static \Keyring\Sso\Sso sso()
 * @method static \Keyring\KeyringManager notifications(array<string, class-string<\Illuminate\Notifications\Notification>|null> $notifications)
 * @method static bool hasNotification(string $type)
 * @method static \Illuminate\Notifications\Notification|null notification(string $type, array<string, mixed> $arguments = [])
 * @method static \Illuminate\Notifications\Notification requiredNotification(string $type, array<string, mixed> $arguments = [])
 * @method static \Keyring\Testing\KeyringFake fake()
 * @method static \Keyring\KeyringManager createUsersUsing(string $action)
 * @method static \Keyring\KeyringManager resetUserPasswordsUsing(string $action)
 * @method static \Keyring\KeyringManager updateUserPasswordsUsing(string $action)
 * @method static \Keyring\KeyringManager validateEmailChangesUsing(string $action)
 * @method static \Illuminate\Support\Collection<int, \Keyring\Models\SecurityEvent> activity(\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model $user, int $limit = 25)
 * @method static list<string> unlistedActivityTypes()
 * @method static string|null statusMessage(mixed $status)
 * @method static mixed result(string|null $key = null, mixed $default = null)
 * @method static \Keyring\KeyringManager respondWith(string $contract, \Closure|string $implementation)
 * @method static \Illuminate\Contracts\Support\Responsable response(string $contract, mixed ...$with)
 * @method static \Illuminate\Contracts\Auth\StatefulGuard guard()
 * @method static \Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model user()
 * @method static \Illuminate\Contracts\Auth\UserProvider provider(string|null $guard = null)
 * @method static bool belongsToGuard(\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model $user)
 * @method static \Keyring\UserKeyring for(\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model $user)
 * @method static string username()
 * @method static string email()
 * @method static \Keyring\KeyringManager allowSignInWhen(\Closure $callback)
 * @method static \Keyring\KeyringManager allowEnrollmentWhen(\Closure $callback)
 * @method static \Keyring\KeyringManager allowImpersonationWhen(\Closure $callback)
 * @method static bool allowsImpersonation(\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model $impersonator, \Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model $user)
 * @method static \Keyring\Enums\ImpersonationRefusal|null impersonationRefusal(\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model $impersonator, \Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model $user)
 * @method static void impersonate(\Illuminate\Http\Request $request, \Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model $user)
 * @method static (\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model)|null stopImpersonating(\Illuminate\Http\Request $request)
 * @method static bool impersonating(\Illuminate\Http\Request|null $request = null)
 * @method static (\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model)|null impersonator(\Illuminate\Http\Request|null $request = null)
 * @method static array{impersonator: array{id: string, name: string|null}, startedAt: string, expiresAt: string, stopUrl: string|null}|null impersonation(\Illuminate\Http\Request|null $request = null)
 * @method static \Symfony\Component\HttpFoundation\Response attempt(\Illuminate\Http\Request $request, string $factor = 'password')
 * @method static \Keyring\KeyringManager linkRootUsing(\Closure $callback)
 * @method static string linkRoot()
 * @method static \Keyring\KeyringManager describeDevicesUsing(\Closure $callback)
 * @method static string|null describeDevice(string|null $userAgent)
 * @method static \Keyring\KeyringManager recordIpsUsing(\Closure $callback)
 * @method static string|null recordedIp(\Illuminate\Http\Request $request)
 * @method static void unlock(\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model $user, string|null $factor = null)
 * @method static bool requirePasswordChange(\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model $user, string|null $reason = null)
 * @method static bool requiresPasswordChange(\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model $user)
 * @method static void cancelPasswordChange(\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model $user)
 * @method static bool allowsSignIn(\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model $user)
 * @method static bool hidesRegisteredAddresses()
 * @method static bool allowsEnrollment(\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model $user)
 * @method static string normalizeUsername(string $username)
 * @method static \Keyring\KeyringManager normalizeUsernamesUsing(\Closure $callback)
 * @method static \Keyring\KeyringManager findUsersUsing(\Closure $callback)
 * @method static (\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model)|null findUser(\Illuminate\Http\Request $request)
 * @method static \Keyring\KeyringManager signInAfterRegistering(\Closure|bool $when)
 * @method static bool signsInAfterRegistering(\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model $user, \Illuminate\Http\Request $request)
 * @method static list<string> protectedAttributes(\Illuminate\Database\Eloquent\Model|null $user = null)
 * @method static mixed withoutProtection(\Closure $callback, string|null $reason = null)
 * @method static \Keyring\KeyringManager useAuthenticatorModel(string $model)
 * @method static class-string<\Keyring\Models\Authenticator> authenticatorModel()
 * @method static \Keyring\KeyringManager useDeviceModel(string $model)
 * @method static class-string<\Keyring\Models\Device> deviceModel()
 * @method static \Keyring\KeyringManager usePendingChangeModel(string $model)
 * @method static class-string<\Keyring\Models\PendingChange> pendingChangeModel()
 * @method static \Keyring\KeyringManager useSecurityEventModel(string $model)
 * @method static class-string<\Keyring\Models\SecurityEvent> securityEventModel()
 * @method static \Keyring\KeyringManager useFailureCountModel(string $model)
 * @method static class-string<\Keyring\Models\FailureCount> failureCountModel()
 *
 * @see KeyringManager
 */
class Keyring extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return KeyringManager::class;
    }
}
