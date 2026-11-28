<?php

declare(strict_types=1);

namespace App\Providers;

use App\Actions\Keyring\CreateNewUser;
use App\Actions\Keyring\ResetUserPassword;
use App\Actions\Keyring\UpdateUserPassword;
use App\Actions\Keyring\ValidateEmailChange;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Support\ServiceProvider;
use Keyring\Facades\Keyring;
use Keyring\Factors;
use Keyring\Login\Requirement;
use Keyring\Risk\Signals;

class KeyringServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        // How your users can sign in. A line that's commented out is one to
        // add later: uncomment it, and turn on Features::manageAuthenticators()
        // in config/keyring.php so users can set it up. See "Factors".
        Keyring::factors([
            Factors\Password::class,
            Factors\Totp::class,
            // These go with any of the others, so losing one isn't the end of an account.
            Factors\RecoveryCodes::class,
            Factors\WebAuthn::passkeys(),
            Factors\WebAuthn::securityKeys(),
            // A step at sign in, not a second factor: a password and an emailed code is AAL1.
            Factors\EmailCode::asExtraStep(),
        ]);

        // What they must prove: a second factor once they've set one up, and
        // a passkey or security key whenever they have one. See "Policies".
        Keyring::require(Requirement::aal2()->ifEnrolled()->noDowngrade());

        // Everyone needs a second factor: until they've set one up, every page
        // sends them to the "enrollment_url" in config/keyring.php.
        $this->app->make(Kernel::class)->appendMiddlewareToGroup('web', 'keyring.enrolled');

        // What makes a sign in or a session look like someone else's. Each
        // signal that fires adds to a score, and Keyring answers the total: a
        // second factor from a user who has one, then a notice, and at the
        // top a refused sign in. The ones that are on can't add up to that
        // for a user who signs in with a password alone. See "Risk".
        Keyring::risk()->signals([
            Signals\SessionFingerprintChanged::class,
            // These two read the security log: Features::securityLog().
            Signals\RepeatedFactorFailures::class,
            Signals\SuccessAfterFailures::class,
            // These two go by an account's devices: Features::devices().
            Signals\NewDevice::class,
            Signals\InactiveAccount::class,
            // Off: with the ones above it could refuse a user who has no
            // second factor to give. It needs Features::emailChanges().
            // Signals\RecentlyChangedRecovery::class,
            // Off: it counts failures on other accounts from the same IP
            // address, which an office or a mobile network shares. With the
            // ones above it can reach the score that refuses a sign in, even
            // for a user with a second factor. It reads the security log.
            // Signals\CredentialStuffing::class,
            // Off: it asks Have I Been Pwned at every sign in, and holds a
            // user whose password it finds until they choose another. Set
            // "password_change_url" in config/keyring.php before turning it on.
            // Signals\BreachedPassword::class,
            // Off: these two need a locator, "devices.locator" in the config.
            // Signals\NewCountry::class,
            // Signals\ImpossibleTravel::class,
        ]);

        // Who may sign in as whom, with Features::impersonation() on in
        // config/keyring.php. Until this says so, nobody may. See "Impersonation".
        // Keyring::allowImpersonationWhen(fn ($impersonator, $user) => $impersonator->is_admin && ! $user->is_admin);

        // Your code for the account changes, in app/Actions/Keyring. Keyring
        // does the security work around them.
        Keyring::createUsersUsing(CreateNewUser::class);
        Keyring::resetUserPasswordsUsing(ResetUserPassword::class);
        Keyring::updateUserPasswordsUsing(UpdateUserPassword::class);
        Keyring::validateEmailChangesUsing(ValidateEmailChange::class);
    }
}
