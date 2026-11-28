<?php

declare(strict_types=1);

namespace Keyring\Tests;

use App\Actions\Keyring\CreateNewUser;
use App\Actions\Keyring\ResetUserPassword;
use App\Actions\Keyring\UpdateUserPassword;
use App\Actions\Keyring\ValidateEmailChange;
use Carbon\CarbonImmutable;
use ErrorException;
use Illuminate\Auth\Events\Registered;
use Illuminate\Auth\Listeners\SendEmailVerificationNotification;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\Event;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\Features;
use Keyring\KeyringServiceProvider;
use Keyring\Sso\HostResolver;
use Keyring\Testing\InteractsWithKeyring;
use Keyring\Tests\Fixtures\User;
use Orchestra\Testbench\TestCase as Orchestra;

use function Orchestra\Testbench\load_migration_paths;

abstract class TestCase extends Orchestra
{
    use InteractsWithKeyring, RefreshDatabase;

    protected function getPackageProviders($app): array
    {
        return [
            KeyringServiceProvider::class,
        ];
    }

    protected function defineEnvironment($app): void
    {
        // Like Laravel's starter kits, so nothing relies on mutable dates.
        Date::use(CarbonImmutable::class);

        $app['config']->set('database.default', getenv('DB_CONNECTION') ?: 'testing');
        $app['config']->set('auth.providers.users.model', User::class);

        // Every feature, so the suite covers them all. Tests of a feature
        // being off turn it off themselves.
        $app['config']->set('keyring.features', Features::all());
        // What a new Laravel app uses, so nothing relies on PHP serialization.
        $app['config']->set('session.serialization', 'json');

        // Migrated once per process, with each test in a transaction. Loaded
        // through testbench's defineDatabaseMigrations() instead, the tables
        // are dropped and made again around every other test. A test that
        // changes the schema on MySQL commits it, and Laravel then migrates
        // afresh for the next one.
        load_migration_paths($app, [__DIR__.'/database/migrations', __DIR__.'/../database/migrations']);
    }

    protected function setUp(): void
    {
        parent::setUp();

        // While testing, Laravel drops deprecations without a word. Thrown,
        // they fail the test that hit one, so a removal can't arrive unseen.
        // Not on the oldest versions allowed, which raise ones only a newer
        // release of theirs takes away.
        if (! getenv('KEYRING_TEST_LOWEST')) {
            $this->withoutDeprecationHandling();
        }

        // No test asks the network's DNS about a provider's hosts.
        HostResolver::fake();

        // A full install: the usual sign-in methods, and the actions
        // registered like the published provider does.
        Keyring::factors([Password::class, WebAuthn::passkeys(), Totp::class, RecoveryCodes::class]);
        Keyring::createUsersUsing(CreateNewUser::class)
            ->resetUserPasswordsUsing(ResetUserPassword::class)
            ->updateUserPasswordsUsing(UpdateUserPassword::class)
            ->validateEmailChangesUsing(ValidateEmailChange::class);

        // Laravel's own listener for new users, which an app's event service
        // provider registers and testbench leaves out.
        Event::listen(Registered::class, SendEmailVerificationNotification::class);
    }

    /**
     * Throw deprecations, as Laravel's own version does, except one Laravel
     * itself raises on Symfony 8.2 and has fixed for its next release
     * (laravel/framework#62654). Remove this once that release is out.
     */
    protected function withoutDeprecationHandling(): static
    {
        $this->originalDeprecationHandler ??= set_error_handler(function (int $level, string $message, string $file = '', int $line = 0): bool {
            if (str_contains($message, 'Directly setting property "headers" of "Illuminate\\Http\\')) {
                return true;
            }

            if (in_array($level, [E_DEPRECATED, E_USER_DEPRECATED], true) || (error_reporting() & $level)) {
                throw new ErrorException($message, 0, $level, $file, $line);
            }

            return true;
        });

        return $this;
    }

    /**
     * Send these cookies and none of the ones set for earlier requests.
     *
     * @param  array<string, string>  $cookies
     */
    public function withOnlyCookies(array $cookies): static
    {
        $this->defaultCookies = [];

        return $this->withCookies($cookies);
    }

    /**
     * Make requests the way an Inertia page visit would, so pages come back as JSON.
     */
    protected function inertia(): static
    {
        return $this->withHeaders(['X-Inertia' => 'true']);
    }
}
