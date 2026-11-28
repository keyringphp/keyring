<?php

declare(strict_types=1);

use App\Actions\Keyring\ResetUserPassword;
use App\Actions\Keyring\UpdateUserPassword;
use App\Actions\Keyring\ValidateEmailChange;
use App\Providers\KeyringServiceProvider;
use Illuminate\Console\Scheduling\Event;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Encryption\Encrypter;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event as Events;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Keyring\Changes\AuthenticatorChanges;
use Keyring\Console\InstallCommand;
use Keyring\Contracts\ResetsUserPasswords;
use Keyring\Contracts\SessionRegistry;
use Keyring\Contracts\UpdatesUserPasswords;
use Keyring\Contracts\ValidatesEmailChanges;
use Keyring\Devices\NullLocator;
use Keyring\Enums\Assurance;
use Keyring\Enums\FreezeReason;
use Keyring\Events\RiskAssessed;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\Features;
use Keyring\Models\Authenticator;
use Keyring\Models\PendingChange;
use Keyring\Models\SecurityEvent;
use Keyring\Notifications\SuspiciousActivity;
use Keyring\Risk\Checkpoint;
use Keyring\Risk\Level;
use Keyring\Risk\Signals\InactiveAccount;
use Keyring\Risk\Signals\NewDevice;
use Keyring\Risk\Signals\RepeatedFactorFailures;
use Keyring\Risk\Signals\SessionFingerprintChanged;
use Keyring\Risk\Signals\SuccessAfterFailures;
use Keyring\Sessions\RegisteredSession;
use Keyring\Testing\VirtualAuthenticator;
use Keyring\Tests\Fixtures\SoftDeletingUser;
use Keyring\Tests\Fixtures\User;
use Keyring\Tests\Fixtures\WrappedUserProvider;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PragmaRX\Google2FA\Google2FA;
use Symfony\Component\Console\Output\BufferedOutput;

describe('keyring:install', function () {
    beforeEach(function () {
        $this->sandbox = sys_get_temp_dir().'/keyring-install-'.uniqid();
        $files = new Filesystem;
        $files->ensureDirectoryExists($this->sandbox.'/bootstrap');
        $files->ensureDirectoryExists($this->sandbox.'/config');
        $files->put($this->sandbox.'/bootstrap/providers.php', "<?php\n\nreturn [\n    App\\Providers\\AppServiceProvider::class,\n];\n");

        $this->app->useAppPath($this->sandbox.'/app');
        $this->app->useBootstrapPath($this->sandbox.'/bootstrap');
        $this->app->useConfigPath($this->sandbox.'/config');
        $this->app->useDatabasePath($this->sandbox.'/database');
    });

    afterEach(function () {
        (new Filesystem)->deleteDirectory($this->sandbox);
    });

    // A new app starts small: everything past the password is there to turn on.
    it('installs the password alone without being asked for more, with registration, resets, verification, password changes and the security log', function (array $options) {
        $this->artisan('keyring:install', [...$options, '--no-interaction' => true])
            ->expectsOutputToContain('Users sign in with a password alone. To add an authenticator app, passkeys or security keys, uncomment its line')
            ->doesntExpectOutputToContain('Turned on managing sign-in methods')
            ->assertSuccessful();

        $config = require config_path('keyring.php');
        $provider = file_get_contents($this->sandbox.'/app/Providers/KeyringServiceProvider.php');

        expect($config['features'])->toBe([Features::registration(), Features::resetPasswords(), Features::emailVerification(), Features::updatePasswords(), Features::securityLog()])
            // The same features Keyring's own config starts with.
            ->toBe((require __DIR__.'/../../config/keyring.php')['features'])
            ->and($config['registration'])->toBe(['reveal_taken' => false])
            ->and($config['enrollment_url'])->toBeNull()
            // There to fill in: nobody but the app knows where its support is.
            ->and($config)->toHaveKey('support_contact', null)
            ->and(file_get_contents(config_path('keyring.php')))->toContain('// Features::devices(),')
            // Keyring's emails are its own, so the provider lists none and
            // none are published.
            ->and($provider)->not->toContain('Notifications')
            ->and(is_dir($this->sandbox.'/app/Notifications'))->toBeFalse()
            ->and($provider)
            // The risk signals the default features can feed, and the rest
            // there to turn on.
            ->toContain("            Signals\SessionFingerprintChanged::class,\n")
            ->toContain("            Signals\SuccessAfterFailures::class,\n")
            ->toContain("            // Signals\NewDevice::class,\n")
            ->toContain("            // Signals\BreachedPassword::class,\n")
            ->toContain("            // Signals\CredentialStuffing::class,\n")
            // The other sign-in methods are there to uncomment, and the
            // policy that asks for one a user has set up is already on.
            ->toContain("        Keyring::factors([\n            Factors\Password::class,\n            // Factors\Totp::class,\n")
            ->toContain("            // Factors\RecoveryCodes::class,\n            // Factors\WebAuthn::passkeys(),\n            // Factors\WebAuthn::securityKeys(),\n")
            ->toContain("            // Factors\EmailCode::asExtraStep(),\n        ]);")
            ->toContain("\n        Keyring::require(Requirement::aal2()->ifEnrolled()->noDowngrade());\n")
            // Nothing a user could set up, so nothing makes them. The line is
            // there to uncomment, naming its class in full: no import to lose.
            ->toContain("        // \$this->app->make(\Illuminate\Contracts\Http\Kernel::class)->appendMiddlewareToGroup('web', 'keyring.enrolled');\n")
            ->not->toContain('use Illuminate\Contracts\Http\Kernel;')
            ->not->toContain('use Keyring\Factors\\')
            // Every action, so turning a feature on later works.
            ->toContain('Keyring::updateUserPasswordsUsing(UpdateUserPassword::class);')
            ->and(array_map(basename(...), glob($this->sandbox.'/app/Actions/Keyring/*.php')))->toEqualCanonicalizing([
                'CreateNewUser.php', 'PasswordValidationRules.php', 'ResetUserPassword.php', 'UpdateUserPassword.php', 'ValidateEmailChange.php',
            ])
            ->and(file_get_contents($this->sandbox.'/bootstrap/providers.php'))->toContain('App\Providers\KeyringServiceProvider::class');

        expectValidPhp($this->sandbox.'/app/Providers/KeyringServiceProvider.php');
    })->with(['nothing asked for' => [[]], '--factor=none' => [['--factor' => ['none']]]]);

    it('adds the sign-in methods and features picked, and what they need', function () {
        $this->artisan('keyring:install', [
            '--factor' => ['totp', 'passkeys'],
            '--feature' => [Features::updatePasswords(), Features::devices()],
            '--no-interaction' => true,
        ])->expectsOutputToContain('Turned on managing sign-in methods')->assertSuccessful();

        $config = require config_path('keyring.php');
        $provider = file_get_contents($this->sandbox.'/app/Providers/KeyringServiceProvider.php');

        expect($config['features'])->toBe([Features::updatePasswords(), Features::manageAuthenticators(), Features::devices()])
            ->and($provider)->toContain("            Signals\NewDevice::class,\n")
            ->toContain("\n            Factors\Totp::class,\n")->toContain("\n            Factors\RecoveryCodes::class,\n")->toContain("\n            Factors\WebAuthn::passkeys(),\n")
            ->toContain("\n        Keyring::require(")
            // The two that weren't picked are there to turn on later.
            ->toContain("\n            // Factors\WebAuthn::securityKeys(),\n")->toContain("\n            // Factors\EmailCode::asExtraStep(),\n");

        expectValidPhp($this->sandbox.'/app/Providers/KeyringServiceProvider.php');
        expectValidPhp(config_path('keyring.php'));
    });

    it('turns on every sign-in method and starting signal when all of them are picked', function () {
        $this->artisan('keyring:install', [
            '--factor' => ['totp', 'passkeys', 'security-keys', 'email-codes'],
            '--feature' => [Features::securityLog(), Features::devices()],
            '--no-interaction' => true,
        ])->assertSuccessful();

        $provider = file_get_contents($this->sandbox.'/app/Providers/KeyringServiceProvider.php');

        expect($provider)
            ->not->toContain('// Factors\\')
            ->toContain("\n            Factors\Totp::class,\n")
            ->toContain("\n            Factors\RecoveryCodes::class,\n")
            ->toContain("\n            Factors\WebAuthn::passkeys(),\n")
            ->toContain("\n            Factors\WebAuthn::securityKeys(),\n")
            ->toContain("\n            Factors\EmailCode::asExtraStep(),\n")
            ->toContain("            Signals\SessionFingerprintChanged::class,\n")
            ->toContain("            Signals\RepeatedFactorFailures::class,\n")
            ->toContain("            Signals\SuccessAfterFailures::class,\n")
            ->toContain("            Signals\NewDevice::class,\n")
            ->toContain("            Signals\InactiveAccount::class,\n")
            // The ones that need more than Keyring has are still there to turn on.
            ->toContain("            // Signals\BreachedPassword::class,\n");

        expectValidPhp($this->sandbox.'/app/Providers/KeyringServiceProvider.php');
    });

    it('adds recovery codes to any second sign-in method, so losing it isn\'t the end of the account', function (string $factor) {
        $this->artisan('keyring:install', ['--factor' => [$factor], '--no-interaction' => true])->assertSuccessful();

        expect(file_get_contents($this->sandbox.'/app/Providers/KeyringServiceProvider.php'))->toContain("\n            Factors\RecoveryCodes::class,\n");
    })->with(['passkeys', 'security-keys', 'email-codes']);

    it('makes everyone set up a second factor once there is one to set up, without asking', function (string $factor) {
        $this->artisan('keyring:install', ['--factor' => [$factor], '--no-interaction' => true])
            ->expectsOutputToContain('Build your page for adding a sign-in method at /settings/security')
            ->assertSuccessful();

        expect(file_get_contents($this->sandbox.'/app/Providers/KeyringServiceProvider.php'))
            ->toContain("\$this->app->make(Kernel::class)->appendMiddlewareToGroup('web', 'keyring.enrolled');")
            ->toContain('use Illuminate\Contracts\Http\Kernel;')
            ->toContain('Keyring::require(Requirement::aal2()->ifEnrolled()->noDowngrade());')
            ->and((require config_path('keyring.php'))['enrollment_url'])->toBe('/settings/security')
            ->and((require config_path('keyring.php'))['features'])->toContain(Features::manageAuthenticators());

        expectValidPhp($this->sandbox.'/app/Providers/KeyringServiceProvider.php');
        expectValidPhp(config_path('keyring.php'));
    })->with(['totp', 'passkeys', 'security-keys']);

    it('leaves a second factor to each user when asked to, or when the only one is an emailed code', function (array $options) {
        $this->artisan('keyring:install', [...$options, '--no-interaction' => true])
            ->expectsOutputToContain('Nothing makes users set up a second factor')
            ->assertSuccessful();

        expect(file_get_contents($this->sandbox.'/app/Providers/KeyringServiceProvider.php'))
            ->toContain("        // \$this->app->make(\Illuminate\Contracts\Http\Kernel::class)->appendMiddlewareToGroup('web', 'keyring.enrolled');\n")
            ->not->toContain('use Illuminate\Contracts\Http\Kernel;')
            ->toContain("\n        Keyring::require(")
            ->and((require config_path('keyring.php'))['enrollment_url'])->toBeNull();

        expectValidPhp($this->sandbox.'/app/Providers/KeyringServiceProvider.php');
    })->with([
        'asked to' => [['--factor' => ['totp'], '--optional-second-factor' => true]],
        'email codes' => [['--factor' => ['email-codes']]],
    ]);

    it('refuses to require a second factor nobody could set up, before writing anything', function (array $factors, string $why) {
        $this->artisan('keyring:install', ['--factor' => $factors, '--require-second-factor' => true, '--no-interaction' => true])
            ->expectsOutputToContain($why)
            ->assertFailed();

        expect(file_exists(config_path('keyring.php')))->toBeFalse();
    })->with([
        'the password alone' => [[], 'Requiring a second factor needs one users can set up. Add --factor=totp, --factor=passkeys, --factor=security-keys.'],
        'email codes' => [['email-codes'], 'Requiring a second factor needs one users can set up, and an emailed code isn\'t one. Add --factor=totp'],
    ]);

    it('calls email codes a step at sign in and not a second factor, wherever it names them', function () {
        $this->artisan('keyring:install', ['--factor' => ['email-codes'], '--no-interaction' => true])
            ->expectsOutputToContain('Email codes are an extra step at sign in, not a second factor: a password and an emailed code is still AAL1.')
            ->assertSuccessful();

        expect(file_get_contents($this->sandbox.'/app/Providers/KeyringServiceProvider.php'))
            ->toContain("            // A step at sign in, not a second factor: a password and an emailed code is AAL1.\n            Factors\EmailCode::asExtraStep(),\n        ]);");

        expectValidPhp($this->sandbox.'/app/Providers/KeyringServiceProvider.php');
    });

    it('leaves email codes commented out, and unmentioned, for an app that did not pick them', function (array $factors) {
        $this->artisan('keyring:install', ['--factor' => $factors, '--no-interaction' => true])
            ->doesntExpectOutputToContain('Email codes')
            ->assertSuccessful();

        expect(file_get_contents($this->sandbox.'/app/Providers/KeyringServiceProvider.php'))
            ->toContain("            // A step at sign in, not a second factor: a password and an emailed code is AAL1.\n            // Factors\EmailCode::asExtraStep(),\n        ]);");

        expectValidPhp($this->sandbox.'/app/Providers/KeyringServiceProvider.php');
    })->with(['the password alone' => [[]], 'an authenticator app and security keys' => [['totp', 'security-keys']]]);

    it('ends by pointing at what whoever runs the app will need', function () {
        // Read whole: the list is one write, which the test client can only
        // find one expected line in.
        $output = new BufferedOutput;

        expect(Artisan::call('keyring:install', ['--no-interaction' => true], $output))->toBe(0)
            ->and($output->fetch())
            ->toContain('Once it\'s running, see "After Installing" in the "Installation" docs.')
            ->toContain('Sessions end after two hours unused. Set sessions.idle in config/keyring.php to change that')
            ->toContain('Run the Laravel scheduler (schedule:run): it prunes the security log and other old records every day')
            ->toContain('Signed-in routes outside the web group need the keyring.session middleware')
            ->toContain('php artisan keyring:sign-out signs one user out everywhere, or everyone with --all')
            // The suite hashes with bcrypt, as a new Laravel app does.
            ->toContain('Passwords are hashed with bcrypt, which reads 72 bytes')
            ->toContain('Set HASH_DRIVER=argon2id to take any up to passwords.max');

        config(['hashing.driver' => 'argon2id']);
        (new Filesystem)->delete(config_path('keyring.php'));

        expect(Artisan::call('keyring:install', ['--no-interaction' => true, '--force' => true], $output))->toBe(0)
            ->and($output->fetch())->not->toContain('bcrypt');

        // What it says is so.
        expect((require __DIR__.'/../../config/keyring.php')['sessions']['idle'])->toBe('2h')
            ->and((require __DIR__.'/../../config/keyring.php')['prune_at'])->not->toBeNull()
            ->and(app('router')->getMiddleware())->toHaveKey('keyring.session');
    });

    it('turns on email verification with registration, which leaves new users signed out until they verify', function (array $factors) {
        $this->artisan('keyring:install', ['--factor' => $factors, '--feature' => [Features::registration()], '--no-interaction' => true])
            ->expectsOutputToContain('Turned on email verification')
            ->expectsOutputToContain('MustVerifyEmail')
            ->assertSuccessful();

        expect((require config_path('keyring.php'))['features'])->toContain(Features::emailVerification());
    })->with(['the password alone' => [[]], 'a passkey' => [['passkeys']]]);

    it('refuses sign-in methods and features it doesn\'t know, before writing anything', function () {
        $this->artisan('keyring:install', ['--factor' => ['totpp'], '--feature' => ['devicez'], '--no-interaction' => true])
            ->expectsOutputToContain('Unknown --factor: totpp')
            ->expectsOutputToContain('Unknown --feature: devicez')
            ->assertFailed();

        expect(file_exists(config_path('keyring.php')))->toBeFalse();
    });

    it('lists every feature in its --feature help', function () {
        $help = Artisan::all()['keyring:install']->getDefinition()->getOption('feature')->getDescription();

        expect(Str::after($help, '): '))->toBe(collect(Features::all())->join(', ', ' or '));
    });

    it('says where to tell the emails who users can contact', function () {
        $this->artisan('keyring:install', ['--factor' => ['totp'], '--no-interaction' => true])
            ->expectsOutputToContain('Set support_contact in config/keyring.php')
            ->assertSuccessful();
    });

    it('asks which sign-in methods and features to set up, with the safe answers as the defaults', function () {
        $this->artisan('keyring:install')
            ->expectsChoice('Which sign-in methods besides the password?', ['passkeys'], ['totp' => 'Authenticator app', 'passkeys' => 'Passkeys', 'security-keys' => 'Security keys, as a second factor', 'email-codes' => 'Email codes, as an extra step at sign in (not a second factor)'])
            ->expectsConfirmation('Require a second factor for everyone?', 'yes')
            ->expectsQuestion('Which features?', [Features::resetPasswords(), Features::manageAuthenticators()])
            ->assertSuccessful();

        expect((require config_path('keyring.php'))['features'])->toBe([Features::resetPasswords(), Features::manageAuthenticators()])
            ->and(file_get_contents($this->sandbox.'/app/Providers/KeyringServiceProvider.php'))->toContain("\n            Factors\WebAuthn::passkeys(),\n")->toContain("\n        \$this->app->make(Kernel::class)->appendMiddlewareToGroup('web', 'keyring.enrolled');")->toContain("\n            // Factors\Totp::class,\n");
    });

    it('does not ask about a second factor when the password is the only sign-in method', function () {
        $this->artisan('keyring:install')
            ->expectsChoice('Which sign-in methods besides the password?', [], ['totp' => 'Authenticator app', 'passkeys' => 'Passkeys', 'security-keys' => 'Security keys, as a second factor', 'email-codes' => 'Email codes, as an extra step at sign in (not a second factor)'])
            ->expectsQuestion('Which features?', [Features::registration(), Features::resetPasswords(), Features::emailVerification(), Features::updatePasswords()])
            ->assertSuccessful();

        expect(file_get_contents($this->sandbox.'/app/Providers/KeyringServiceProvider.php'))
            ->not->toContain("\n        \$this->app->make(");
    });

    // The config an app already has is left alone, so the provider written
    // beside it can ask for something the config doesn't turn on.
    it('says so when a config it kept leaves nobody able to set up the sign-in methods picked', function () {
        file_put_contents(config_path('keyring.php'), "<?php\n\nreturn ['features' => ['registration', 'email-verification']];\n");
        config(['keyring.features' => ['registration', 'email-verification']]);

        $this->artisan('keyring:install', ['--factor' => ['totp'], '--no-interaction' => true])
            ->expectsOutputToContain('Add Features::manageAuthenticators() to the features in config/keyring.php')
            ->assertSuccessful();

        expect(file_get_contents($this->sandbox.'/app/Providers/KeyringServiceProvider.php'))->toContain("\n            Factors\\Totp::class,\n");
    });

    it('can run again without duplicating migrations or overwriting customised files', function () {
        $this->artisan('keyring:install', ['--no-interaction' => true])->assertSuccessful();
        file_put_contents($this->sandbox.'/app/Providers/KeyringServiceProvider.php', '<?php // mine');

        $this->artisan('keyring:install', ['--factor' => ['passkeys'], '--no-interaction' => true])
            ->expectsOutputToContain('keyring.php, it already exists')
            ->doesntExpectOutputToContain('Turned on')
            ->doesntExpectOutputToContain('HasKeyring')
            ->doesntExpectOutputToContain('php artisan migrate')
            // The provider is what would require a second factor, and it's kept.
            ->doesntExpectOutputToContain('second factor')
            ->assertSuccessful();

        expect(glob(database_path('migrations/*_create_keyring_authenticators_table.php')))->toHaveCount(1)
            ->and(glob(database_path('migrations/*_create_keyring_*')))->toHaveCount(8)
            ->and(file_get_contents($this->sandbox.'/app/Providers/KeyringServiceProvider.php'))->toBe('<?php // mine');
    });

    it('adds the migrations a later version brought to an app that has the earlier ones', function () {
        $this->artisan('keyring:install', ['--no-interaction' => true])->assertSuccessful();

        $kept = glob(database_path('migrations/*_create_keyring_sessions_table.php'));
        new Filesystem()->delete([
            ...glob(database_path('migrations/*_create_keyring_failure_counts_table.php')),
            ...glob(database_path('migrations/*_create_keyring_password_holds_table.php')),
        ]);

        // An upgrade comes some time after the install.
        $this->travel(1)->days();

        $this->artisan('keyring:install', ['--no-interaction' => true])
            ->expectsOutputToContain('php artisan migrate')
            ->assertSuccessful();

        $published = array_map(basename(...), glob(database_path('migrations/*_create_keyring_*')));

        expect($published)->toHaveCount(8)
            ->and(glob(database_path('migrations/*_create_keyring_sessions_table.php')))->toBe($kept)
            // In Keyring's order, after the ones the app already had.
            ->and(array_map(fn (string $name) => Str::after($name, '_create_'), array_slice($published, -2)))
            ->toBe(['keyring_failure_counts_table.php', 'keyring_password_holds_table.php']);
    });
});

describe('the risk signals a new provider starts with', function () {
    /**
     * The provider keyring:install writes for these features, and the
     * signal lines in it: [on, commented out].
     *
     * @param  list<string>  $features
     * @return array{list<string>, list<string>}
     */
    function publishedSignals(array $features): array
    {
        $provider = (fn () => $this->provider(new Filesystem, [], false, $features))->call(new InstallCommand);

        preg_match_all('/^ +(\/\/ )?Signals\\\\(\w+)::class,$/m', $provider, $lines, PREG_SET_ORDER);

        return [
            array_column(array_filter($lines, fn (array $line) => $line[1] === ''), 2),
            array_column(array_filter($lines, fn (array $line) => $line[1] !== ''), 2),
        ];
    }

    it('turns on the ones a feature that is on can feed, and leaves the rest there commented out', function (array $features, array $on, array $off) {
        expect(publishedSignals($features))->toBe([$on, [...$off, 'RecentlyChangedRecovery', 'CredentialStuffing', 'BreachedPassword', 'NewCountry', 'ImpossibleTravel']]);
    })->with([
        'the default features' => [
            ['registration', 'reset-passwords', 'email-verification', 'update-passwords', 'security-log'],
            ['SessionFingerprintChanged', 'RepeatedFactorFailures', 'SuccessAfterFailures'],
            ['NewDevice', 'InactiveAccount'],
        ],
        'devices too' => [
            ['security-log', 'devices'],
            ['SessionFingerprintChanged', 'RepeatedFactorFailures', 'SuccessAfterFailures', 'NewDevice', 'InactiveAccount'],
            [],
        ],
        'devices without the security log' => [
            ['devices'],
            ['SessionFingerprintChanged', 'NewDevice', 'InactiveAccount'],
            ['RepeatedFactorFailures', 'SuccessAfterFailures'],
        ],
        'neither' => [
            [],
            ['SessionFingerprintChanged'],
            ['RepeatedFactorFailures', 'SuccessAfterFailures', 'NewDevice', 'InactiveAccount'],
        ],
        // Email changes turn nothing on: the signal that reads them stays off.
        'every feature' => [
            Features::all(),
            ['SessionFingerprintChanged', 'RepeatedFactorFailures', 'SuccessAfterFailures', 'NewDevice', 'InactiveAccount'],
            [],
        ],
    ]);

    it('writes a provider that is valid PHP whichever are on', function (array $features) {
        $path = sys_get_temp_dir().'/keyring-provider-'.uniqid().'.php';
        file_put_contents($path, (fn () => $this->provider(new Filesystem, [], false, $features))->call(new InstallCommand));

        expectValidPhp($path);
        File::delete($path);
    })->with(['none of them' => [[]], 'all of them' => [Features::all()]]);

    it('makes no network call and needs no locator', function () {
        // The stub as a whole, which has every signal a feature can turn on.
        new KeyringServiceProvider($this->app)->boot();
        Http::preventStrayRequests();
        config(['keyring.devices.locator' => NullLocator::class]);

        $signals = [...Keyring::risk()->signalsFor(Checkpoint::Login), ...Keyring::risk()->signalsFor(Checkpoint::Request)];

        expect(array_map(get_class(...), $signals))->toEqualCanonicalizing([
            SessionFingerprintChanged::class, RepeatedFactorFailures::class, SuccessAfterFailures::class, NewDevice::class, InactiveAccount::class,
        ]);

        $this->post('/login', ['email' => taylor()->email, 'password' => 'password'])->assertRedirect('/dashboard');
        $this->get('/user/sessions')->assertOk();
    });

    // A step-up asks for a second factor from a user who has one. Refusing
    // the sign in is what would keep someone out, and it takes a score the
    // signals that are on can't reach for a user with a password alone.
    it('cannot keep out a user who signs in with a password alone, with every one of them finding something', function () {
        new KeyringServiceProvider($this->app)->boot();
        Keyring::factors([Password::class]);
        Notification::fake();
        $user = taylor();

        // Last signed in a hundred days ago, in another browser.
        $this->post('/login', ['email' => $user->email, 'password' => 'password'])->assertRedirect('/dashboard');
        $this->post('/logout');
        $this->travel(100)->days();
        $this->flushSession();
        $this->defaultCookies = [];

        // Then five wrong passwords, and the right one.
        config(['keyring.limits.per_account' => 100]);

        foreach (range(1, 5) as $guess) {
            $this->post('/login', ['email' => $user->email, 'password' => 'wrong-'.$guess])->assertSessionHasErrors('email');
        }

        Events::listen(RiskAssessed::class, function (RiskAssessed $event) use (&$assessed) {
            $assessed = $event;
        });

        $this->post('/login', ['email' => $user->email, 'password' => 'password'])->assertRedirect('/dashboard');
        $this->assertAuthenticatedAs($user);

        expect(array_column($assessed->risk->toArray(), 'signal'))->toEqualCanonicalizing(['success_after_failures', 'new_device', 'inactive_account'])
            ->and($assessed->risk->level)->toBe(Level::High)
            ->and($assessed->action->deny)->toBeFalse()
            ->and($assessed->action->lockSeconds)->toBeNull();

        // They're told, and nothing they could reach before is closed to them.
        Notification::assertSentTo($user, SuspiciousActivity::class);
        $this->get('/user/sessions')->assertOk();
    });
});

function passkeysTable(): void
{
    Schema::create('passkeys', function (Blueprint $table) {
        $table->id();
        $table->foreignId('user_id');
        $table->string('name');
        $table->string('credential_id');
        $table->json('credential');
        $table->timestamp('last_used_at')->nullable();
        $table->timestamps();
    });
}

describe('keyring:import fortify', function () {
    beforeEach(function () {
        Keyring::factors([Password::class, Totp::class, WebAuthn::passkeys(), RecoveryCodes::class]);

        Schema::table('users', function (Blueprint $table) {
            $table->text('two_factor_secret')->nullable();
            $table->text('two_factor_recovery_codes')->nullable();
            $table->timestamp('two_factor_confirmed_at')->nullable();
        });

        $this->user = taylor();
    });

    afterEach(function () {
        Model::encryptUsing(null);
    });

    it('refuses to import into factors that aren\'t registered', function () {
        Keyring::factors([Password::class]);
        DB::table('users')->update(['two_factor_secret' => encrypt('secret'), 'two_factor_confirmed_at' => now()]);

        $this->artisan('keyring:import', ['source' => 'fortify'])
            ->expectsOutputToContain('Register totp, recovery in Keyring::factors() first')
            ->assertFailed();

        expect(Authenticator::count())->toBe(0);
    });

    it('refuses to import from anything but fortify', function () {
        DB::table('users')->update(['two_factor_secret' => encrypt('secret'), 'two_factor_confirmed_at' => now()]);

        $this->artisan('keyring:import', ['source' => 'breeze'])
            ->expectsOutputToContain('Only "fortify" can be imported for now.')
            ->assertFailed();

        expect(Authenticator::count())->toBe(0);
    });

    it('refuses to import without an eloquent user provider to find the users with', function () {
        WrappedUserProvider::use();
        DB::table('users')->update(['two_factor_secret' => encrypt('secret'), 'two_factor_confirmed_at' => now()]);

        $this->artisan('keyring:import', ['source' => 'fortify'])
            ->expectsOutputToContain('Importing needs an Eloquent user provider.')
            ->assertFailed();

        expect(Authenticator::count())->toBe(0);
    });

    it('imports fortify two factor and recovery codes, once', function () {
        $secret = app(Google2FA::class)->generateSecretKey();

        DB::table('users')->update([
            'two_factor_secret' => encrypt($secret),
            'two_factor_recovery_codes' => encrypt(json_encode(['aBcDeFgHi1-JkLmNoPqR2', 'ZyXwVuTsR9-qPoNmLkJi8'])),
            'two_factor_confirmed_at' => now(),
        ]);

        $this->artisan('keyring:import', ['source' => 'fortify', '--dry-run' => true])->assertSuccessful();
        expect(Authenticator::count())->toBe(0);

        $this->artisan('keyring:import', ['source' => 'fortify'])->assertSuccessful();
        $this->artisan('keyring:import', ['source' => 'fortify'])->expectsOutputToContain('Already imported')->assertSuccessful();

        $keyring = $this->user->keyring->refresh();
        expect($keyring->of('totp'))->toHaveCount(1)
            ->and($keyring->of('totp')->first()->secret)->toBe($secret)
            ->and($keyring->of('recovery'))->toHaveCount(1);

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        $this->get(route('keyring.login.challenge', ['recovery']));
        $this->post(route('keyring.login.verify', 'recovery'), ['code' => 'aBcDeFgHi1-JkLmNoPqR2'])->assertRedirect('/dashboard');
    });

    it('keeps when fortify\'s two factor and a laravel passkey were added, so they\'re established', function () {
        $this->freezeSecond();

        $confirmed = now()->subMonths(3)->startOfSecond();
        DB::table('users')->update([
            'two_factor_secret' => encrypt(app(Google2FA::class)->generateSecretKey()),
            'two_factor_recovery_codes' => encrypt(json_encode(['aBcDeFgHi1-JkLmNoPqR2'])),
            'two_factor_confirmed_at' => $confirmed,
        ]);
        passkeysTable();
        DB::table('passkeys')->insert(['user_id' => $this->user->id, 'name' => 'MacBook', ...passkeyRow($this->user), 'created_at' => now()->subYear()->startOfSecond()]);

        $this->artisan('keyring:import', ['source' => 'fortify'])->assertSuccessful();

        $keyring = $this->user->keyring->refresh();
        expect($keyring->of('totp')->sole()->created_at->toIso8601String())->toBe($confirmed->toIso8601String())
            ->and($keyring->of('recovery')->sole()->created_at->toIso8601String())->toBe($confirmed->toIso8601String())
            ->and($keyring->of('passkey')->sole()->created_at->toIso8601String())->toBe(now()->subYear()->startOfSecond()->toIso8601String())
            ->and($keyring->all()->every($keyring->isEstablished(...)))->toBeTrue()
            ->and(app(AuthenticatorChanges::class)->frozen($this->user))->toBeNull();
    });

    it('adds a secret fortify never confirmed as new, so the account is frozen until it\'s established', function () {
        config(['fortify.features' => ['two-factor-authentication']]);
        DB::table('users')->update(['two_factor_secret' => encrypt(app(Google2FA::class)->generateSecretKey())]);

        $this->artisan('keyring:import', ['source' => 'fortify'])->assertSuccessful();

        expect(app(AuthenticatorChanges::class)->frozen($this->user)?->reason)->toBe(FreezeReason::NewAuthenticator);
    });

    it('keeps the case of fortify\'s recovery codes, which is what makes them long enough to store hashed', function () {
        DB::table('users')->update([
            'two_factor_secret' => encrypt(app(Google2FA::class)->generateSecretKey()),
            'two_factor_recovery_codes' => encrypt(json_encode(['aBcDeFgHi1-JkLmNoPqR2'])),
            'two_factor_confirmed_at' => now(),
        ]);

        $this->artisan('keyring:import', ['source' => 'fortify'])->assertSuccessful();

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        $this->post(route('keyring.login.verify', 'recovery'), ['code' => 'abcdefghi1-jklmnopqr2'])->assertSessionHasErrors('code');
        $this->assertGuest();

        $this->post(route('keyring.login.verify', 'recovery'), ['code' => 'aBcDeFgHi1 JkLmNoPqR2'])->assertRedirect('/dashboard');
    });

    it('leaves behind recovery codes too short to store hashed, and says so', function () {
        $secret = app(Google2FA::class)->generateSecretKey();

        DB::table('users')->update([
            'two_factor_secret' => encrypt($secret),
            'two_factor_recovery_codes' => encrypt(json_encode(['aBcDeFgHi1-JkLmNoPqR2', 'abcde-12345'])),
            'two_factor_confirmed_at' => now(),
        ]);

        $this->artisan('keyring:import', ['source' => 'fortify'])
            ->expectsOutputToContain("Skipped the recovery codes of user {$this->user->id}: they aren't the 20 letters and digits Fortify makes")
            ->assertSuccessful();

        $keyring = $this->user->keyring->refresh();
        expect($keyring->of('totp')->sole()->secret)->toBe($secret)
            ->and($keyring->of('recovery'))->toBeEmpty();
    });

    it('imports unconfirmed secrets only when asked', function () {
        config(['fortify.features' => ['two-factor-authentication'], 'fortify-options.two-factor-authentication' => ['confirm' => true]]);
        DB::table('users')->update(['two_factor_secret' => encrypt(app(Google2FA::class)->generateSecretKey())]);

        $this->artisan('keyring:import', ['source' => 'fortify'])
            ->expectsOutputToContain("Skipped user {$this->user->id}: its secret was never confirmed")
            ->assertSuccessful();
        expect($this->user->keyring->refresh()->of('totp'))->toBeEmpty();

        $this->artisan('keyring:import', ['source' => 'fortify', '--unconfirmed' => true])->assertSuccessful();

        expect($this->user->keyring->refresh()->of('totp'))->toHaveCount(1);
    });

    it('never brings back what a user removed, or adds to what they set up in keyring', function () {
        DB::table('users')->update([
            'two_factor_secret' => encrypt(app(Google2FA::class)->generateSecretKey()),
            'two_factor_recovery_codes' => encrypt(json_encode(['aBcDeFgHi1-JkLmNoPqR2'])),
            'two_factor_confirmed_at' => now(),
        ]);
        $this->artisan('keyring:import', ['source' => 'fortify'])->assertSuccessful();

        // The phone is lost: the user swaps the imported app for a new one.
        $this->user->keyring->of('totp')->first()->delete();
        $new = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

        $this->artisan('keyring:import', ['source' => 'fortify'])->assertSuccessful();

        $keyring = $this->user->keyring->refresh();
        expect($keyring->of('totp')->pluck('id')->all())->toBe([$new->id])
            ->and($keyring->of('recovery'))->toHaveCount(1);

        $other = taylor(['email' => 'abigail@example.com']);
        Authenticator::factory()->securityKey()->for($other, 'authenticatable')->create(['factor' => 'passkey']);
        DB::table('users')->where('id', $other->id)->update(['two_factor_secret' => encrypt('secret'), 'two_factor_confirmed_at' => now()]);

        $this->artisan('keyring:import', ['source' => 'fortify'])
            ->expectsOutputToContain("Skipped user {$other->id}: they already have sign-in methods in Keyring")
            ->assertSuccessful();
        expect($other->keyring->refresh()->of('totp'))->toBeEmpty();
    });

    it('imports a secret with no confirmation when fortify enforces it without one, and challenges the user', function () {
        config(['fortify.features' => ['two-factor-authentication']]);
        DB::table('users')->update(['two_factor_secret' => encrypt(app(Google2FA::class)->generateSecretKey())]);

        $this->artisan('keyring:import', ['source' => 'fortify'])->assertSuccessful();

        expect($this->user->keyring->refresh()->of('totp'))->toHaveCount(1);

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
            ->assertRedirect(route('keyring.login.challenge'));
        $this->assertGuest();
    });

    it('asks which rule applies when fortify\'s config can\'t say', function () {
        DB::table('users')->update(['two_factor_secret' => encrypt(app(Google2FA::class)->generateSecretKey())]);

        $this->artisan('keyring:import', ['source' => 'fortify'])
            ->expectsOutputToContain("Failed user {$this->user->id}: its secret was never confirmed and Fortify's confirm option can't be read.")
            ->assertFailed();
        $this->artisan('keyring:import', ['source' => 'fortify', '--fortify-confirm' => 'maybe'])->assertFailed();
        $this->artisan('keyring:import', ['source' => 'fortify', '--fortify-confirm' => 'on'])->assertSuccessful();
        expect($this->user->keyring->refresh()->of('totp'))->toBeEmpty();

        $this->artisan('keyring:import', ['source' => 'fortify', '--fortify-confirm' => 'off'])->assertSuccessful();
        expect($this->user->keyring->refresh()->of('totp'))->toHaveCount(1);
    });

    it('fails closed on a secret it can\'t decrypt, and imports it once it can', function () {
        $secret = app(Google2FA::class)->generateSecretKey();
        DB::table('users')->update([
            'two_factor_secret' => new Encrypter(random_bytes(32), 'aes-256-cbc')->encrypt($secret),
            'two_factor_confirmed_at' => now(),
        ]);

        $this->artisan('keyring:import', ['source' => 'fortify', '--dry-run' => true])
            ->expectsOutputToContain("Failed user {$this->user->id}: its two factor secret or recovery codes can't be decrypted")
            ->assertFailed();
        expect(Authenticator::count())->toBe(0);

        $this->artisan('keyring:import', ['source' => 'fortify'])
            ->expectsOutputToContain("Failed user {$this->user->id}")
            ->assertFailed();
        $this->artisan('keyring:import', ['source' => 'fortify'])->assertFailed();

        expect($this->user->keyring->refresh()->of('totp'))->toHaveCount(1);
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
            ->assertRedirect(route('keyring.login.challenge'));
        $this->assertGuest();
        $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($secret)]);
        $this->assertGuest();

        DB::table('users')->update(['two_factor_secret' => encrypt($secret)]);
        $this->artisan('keyring:import', ['source' => 'fortify'])->assertSuccessful();

        $keyring = $this->user->keyring->refresh();
        expect($keyring->of('totp'))->toHaveCount(1)
            ->and($keyring->of('totp')->first()->secret)->toBe($secret);
    });

    it('fails a row whose recovery codes are in an unexpected format', function () {
        DB::table('users')->update([
            'two_factor_secret' => encrypt(app(Google2FA::class)->generateSecretKey()),
            'two_factor_recovery_codes' => encrypt('not json'),
            'two_factor_confirmed_at' => now(),
        ]);

        $this->artisan('keyring:import', ['source' => 'fortify'])
            ->expectsOutputToContain("Failed user {$this->user->id}: its two factor secret or recovery codes are in an unexpected format")
            ->assertFailed();
    });

    it('decrypts with the encrypter eloquent is using', function () {
        $encrypter = new Encrypter(random_bytes(32), 'aes-256-cbc');
        Model::encryptUsing($encrypter);
        $secret = app(Google2FA::class)->generateSecretKey();
        DB::table('users')->update(['two_factor_secret' => $encrypter->encrypt($secret), 'two_factor_confirmed_at' => now()]);

        $this->artisan('keyring:import', ['source' => 'fortify'])->assertSuccessful();

        expect($this->user->keyring->refresh()->of('totp')->first()->secret)->toBe($secret);
    });

    it('reports passkeys it can\'t import', function () {
        passkeysTable();
        DB::table('passkeys')->insert([
            ['id' => 1, 'user_id' => 999, 'name' => 'Orphan', 'credential_id' => 'a', 'credential' => '{}'],
            ['id' => 2, 'user_id' => $this->user->id, 'name' => 'Broken', 'credential_id' => 'b', 'credential' => '{}'],
        ]);

        $this->artisan('keyring:import', ['source' => 'fortify'])
            ->expectsOutputToContain("Failed passkey 1 of user 999: that user doesn't exist")
            ->expectsOutputToContain("Failed passkey 2 of user {$this->user->id}: its credential is in an unexpected format")
            ->assertFailed();
        expect(Authenticator::count())->toBe(0);
    });

    it('will not import a passkey whose record it could not read back', function (string $id, string $credential) {
        passkeysTable();
        DB::table('passkeys')->insert(['id' => 1, 'user_id' => $this->user->id, 'name' => 'Junk', 'credential_id' => $id, 'credential' => $credential]);

        $this->artisan('keyring:import', ['source' => 'fortify'])
            ->expectsOutputToContain("Failed passkey 1 of user {$this->user->id}: its credential is in an unexpected format")
            ->assertFailed();

        expect(Authenticator::count())->toBe(0);
    })->with([
        'json that is not a credential record' => ['YWJjZGVmZ2g', '{"counter":0}'],
        'an id that is not base64url' => ['not base64url!', '{"counter":0}'],
    ]);

    it('finishes a two factor import that failed before, though the passkey came across', function () {
        $secret = app(Google2FA::class)->generateSecretKey();
        passkeysTable();
        DB::table('users')->update([
            'two_factor_secret' => new Encrypter(random_bytes(32), 'aes-256-cbc')->encrypt($secret),
            'two_factor_confirmed_at' => now(),
        ]);
        DB::table('passkeys')->insert(['user_id' => $this->user->id, 'name' => 'MacBook', ...passkeyRow($this->user)]);

        $this->artisan('keyring:import', ['source' => 'fortify'])->assertFailed();
        expect(Authenticator::query()->where('factor', 'totp')->sole()->secret)->toBeNull()
            ->and(Authenticator::query()->where('factor', 'passkey')->count())->toBe(1);

        DB::table('users')->update(['two_factor_secret' => encrypt($secret)]);
        $this->artisan('keyring:import', ['source' => 'fortify'])->assertSuccessful();

        expect(Authenticator::query()->where('factor', 'totp')->sole()->secret)->toBe($secret)
            ->and(Authenticator::query()->where('factor', 'passkey')->count())->toBe(1);
    });

    it('says so when it leaves out a passkey an earlier run did not bring across', function () {
        passkeysTable();
        DB::table('users')->update(['two_factor_secret' => encrypt(app(Google2FA::class)->generateSecretKey()), 'two_factor_confirmed_at' => now()]);
        DB::table('passkeys')->insert(['id' => 1, 'user_id' => $this->user->id, 'name' => 'MacBook', 'credential_id' => 'YWJjZGVmZ2g', 'credential' => '{}']);

        $this->artisan('keyring:import', ['source' => 'fortify'])->assertFailed();

        DB::table('passkeys')->update(passkeyRow($this->user));

        // It can't tell a row that failed from one the user removed since, so
        // it stays out, and the run says which.
        $this->artisan('keyring:import', ['source' => 'fortify'])
            ->expectsOutputToContain("Skipped passkey 1 of user {$this->user->id}: an earlier import left this out, or they removed it since")
            ->assertSuccessful();

        expect(Authenticator::query()->where('factor', 'passkey')->exists())->toBeFalse();
    });

    it('imports users the model\'s global scopes hide, so a restored user keeps their factors', function () {
        Schema::table('users', fn (Blueprint $table) => $table->softDeletes());
        config(['auth.providers.users.model' => SoftDeletingUser::class]);
        passkeysTable();
        DB::table('users')->update([
            'two_factor_secret' => encrypt(app(Google2FA::class)->generateSecretKey()),
            'two_factor_confirmed_at' => now(),
            'deleted_at' => now(),
        ]);
        DB::table('passkeys')->insert(['user_id' => $this->user->id, 'name' => 'MacBook', ...passkeyRow($this->user)]);

        $this->artisan('keyring:import', ['source' => 'fortify'])->assertSuccessful();

        expect(Authenticator::pluck('factor')->all())->toEqualCanonicalizing(['totp', 'passkey']);

        DB::table('users')->update(['deleted_at' => null]);
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
            ->assertRedirect(route('keyring.login.challenge'));
        $this->assertGuest();
    });

    it('imports laravel passkeys so they keep working', function () {
        $key = new VirtualAuthenticator;

        $this->actingAs($this->user)->withAssurance(Assurance::AAL1);
        $options = $this->postJson(route('keyring.authenticators.store', 'passkey'), ['password' => 'password'])->json('enrollment.options');
        $this->postJson(route('keyring.authenticators.confirm', 'passkey'), ['credential' => $key->register($options), 'name' => 'MacBook']);
        $this->post('/logout');

        // Pretend that passkey was made by laravel/passkeys instead.
        $made = Authenticator::where('factor', 'passkey')->sole();
        passkeysTable();
        DB::table('passkeys')->insert([
            'user_id' => $this->user->id,
            'name' => 'MacBook',
            'credential_id' => $made->credential_id,
            'credential' => $made->public_key,
            'created_at' => now(),
        ]);
        Authenticator::query()->delete();

        $this->artisan('keyring:import', ['source' => 'fortify'])->assertSuccessful();

        $options = $this->getJson(route('keyring.login.options', 'passkey'))->json('options');
        $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $key->assert($options)])->assertRedirect('/dashboard');

        expect($this->user->keyring->refresh()->of('passkey')->first()->name)->toBe('MacBook');
    });

    it('imports a passkey whose name isn\'t valid text as what can be read of it', function () {
        if (DB::getDriverName() !== 'sqlite') {
            $this->markTestSkipped('PostgreSQL and strict MySQL refuse to store text that isn\'t valid UTF-8.');
        }

        passkeysTable();
        DB::table('passkeys')->insert(['user_id' => $this->user->id, 'name' => "MacBook \xff", ...passkeyRow($this->user)]);

        $this->artisan('keyring:import', ['source' => 'fortify'])->assertSuccessful();

        $name = Authenticator::query()->where('factor', 'passkey')->sole()->name;
        expect(mb_check_encoding($name, 'UTF-8'))->toBeTrue()->and($name)->toStartWith('MacBook ');
    });

    it('imports a passkey whose algorithm the app does not take, and says it will be refused', function (bool $dryRun) {
        $key = VirtualAuthenticator::rsa();
        $other = User::create(['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => 'password']);

        // laravel/passkeys offers RS256, so it holds keys Keyring's default list leaves out.
        passkeysTable();
        config(['keyring.webauthn.algorithms' => ['ES256', 'RS256']]);
        DB::table('passkeys')->insert([
            ['user_id' => $this->user->id, 'name' => 'Windows Hello', ...passkeyRow($this->user, $key)],
            ['user_id' => $this->user->id, 'name' => 'MacBook', ...passkeyRow($this->user)],
            ['user_id' => $other->id, 'name' => 'Windows Hello', ...passkeyRow($other, VirtualAuthenticator::rsa())],
        ]);
        config(['keyring.webauthn.algorithms' => ['ES256', 'EdDSA']]);

        $this->artisan('keyring:import', ['source' => 'fortify', '--dry-run' => $dryRun])
            ->expectsOutputToContain("2 imported passkeys signing with RS256 will be refused at sign in: RS256 isn't in webauthn.algorithms. Add 'RS256' to that list in config/keyring.php to keep them working, or their users will need to add a new passkey. Users {$this->user->id}, {$other->id}.")
            ->assertSuccessful();

        // Kept, so it's still theirs and works once the app takes RS256.
        expect(Authenticator::query()->where('factor', 'passkey')->count())->toBe($dryRun ? 0 : 3);

        if ($dryRun) {
            return;
        }

        $signIn = fn () => $this->post(route('keyring.login.factor', 'passkey'), [
            'credential' => $key->assert($this->getJson(route('keyring.login.options', 'passkey'))->json('options')),
        ]);

        $signIn()->assertSessionHasErrors('credential');
        $this->assertGuest();

        config(['keyring.webauthn.algorithms' => ['ES256', 'EdDSA', 'RS256']]);

        $signIn()->assertRedirect('/dashboard');
        $this->assertAuthenticatedAs($this->user);
    })->with(['for real' => false, 'on a dry run' => true]);

    it('says nothing about refused passkeys when the app takes every algorithm imported', function () {
        passkeysTable();
        config(['keyring.webauthn.algorithms' => ['ES256', 'EdDSA', 'RS256']]);
        DB::table('passkeys')->insert([
            ['user_id' => $this->user->id, 'name' => 'Windows Hello', ...passkeyRow($this->user, VirtualAuthenticator::rsa())],
            ['user_id' => $this->user->id, 'name' => 'MacBook', ...passkeyRow($this->user)],
        ]);

        $this->artisan('keyring:import', ['source' => 'fortify'])
            ->doesntExpectOutputToContain('refused at sign in:')
            ->assertSuccessful();

        expect(Authenticator::query()->where('factor', 'passkey')->count())->toBe(2);
    });

    it('imports a passkey whose public key can not be read, and says it will be refused', function (string $publicKey) {
        passkeysTable();
        $row = passkeyRow($this->user);
        $row['credential'] = json_encode([...json_decode($row['credential'], true), 'credentialPublicKey' => Base64UrlSafe::encodeUnpadded($publicKey)]);
        DB::table('passkeys')->insert(['user_id' => $this->user->id, 'name' => 'MacBook', ...$row]);
        Exceptions::fake();

        $this->artisan('keyring:import', ['source' => 'fortify'])
            ->expectsOutputToContain("1 imported passkey signing with a key that can't be read will be refused at sign in: this server can't check those signatures, so their users will need to add a new passkey. User {$this->user->id}.")
            ->assertSuccessful();

        expect(Authenticator::query()->where('factor', 'passkey')->count())->toBe(1);
        Exceptions::assertNothingReported();
    })->with([
        'not cbor' => "\xff\x00",
        'cbor that is not a key' => "\x01",
        'a key that names no algorithm' => "\xa1\x01\x02",
    ]);

    it('says when an imported rsa key is shorter than the app allows', function () {
        passkeysTable();
        config(['keyring.webauthn.algorithms' => ['ES256', 'RS256']]);
        DB::table('passkeys')->insert(['user_id' => $this->user->id, 'name' => 'Windows Hello', ...passkeyRow($this->user, VirtualAuthenticator::rsa())]);
        config(['keyring.webauthn.minimum_rsa_bits' => 3072]);

        $this->artisan('keyring:import', ['source' => 'fortify'])
            ->expectsOutputToContain("1 imported passkey signing with RS256 will be refused at sign in: the RSA key is shorter than webauthn.minimum_rsa_bits in config/keyring.php allows. Lower that (2048 is the least Keyring takes) to keep them working, or their users will need to add a new passkey. User {$this->user->id}.")
            ->assertSuccessful();

        expect(Authenticator::query()->where('factor', 'passkey')->count())->toBe(1);
    });
});

it('prunes old devices, email changes, security events and ended sessions', function () {
    $user = User::create(['name' => 'Taylor', 'email' => 'taylor@example.com', 'password' => 'password']);
    $old = Keyring::deviceModel()::make(['token_hash' => 'a', 'revoked_at' => now()->subDays(31)]);
    $old->authenticatable()->associate($user)->save();
    $current = Keyring::deviceModel()::make(['token_hash' => 'b']);
    $current->authenticatable()->associate($user)->save();

    $change = function (array $attributes) use ($user): PendingChange {
        $change = new PendingChange(['attribute' => 'email', 'value' => 'new@example.com', 'confirm_token' => 'c', 'revert_token' => 'r', 'expires_at' => now()->addDay(), ...$attributes]);
        $change->authenticatable()->associate($user)->save();

        return $change;
    };
    $ended = [
        $change(['expires_at' => now()->subDays(31)]),
        $change(['cancelled_at' => now()->subDays(31)]),
        $change(['reverted_at' => now()->subDays(31)]),
        $change(['applied_at' => now()->subDays(40), 'revertable_until' => now()->subDays(31)]),
    ];
    $kept = [
        $change([]),
        $change(['expires_at' => now()->subDay()]),
        $change(['applied_at' => now()->subDays(40), 'expires_at' => now()->subDays(40), 'revertable_until' => now()->subDay()]),
    ];

    $event = fn (int $daysAgo) => SecurityEvent::query()->forceCreate([
        'authenticatable_type' => $user->getMorphClass(),
        'authenticatable_id' => $user->id,
        'type' => 'signed_in',
        'created_at' => now()->subDays($daysAgo),
    ]);
    $event(181);
    $recent = $event(1);

    $registry = app(SessionRegistry::class);
    // One that expired with nothing to end it waits a day for the sweep.
    $registry->save(new RegisteredSession('ended', (string) $user->id, RegisteredSession::typeOf($user), 'web', null, Assurance::AAL1, null, null, 0, 0, now()->subDay()->subMinute()->getTimestamp()));
    $registry->save(new RegisteredSession('live', (string) $user->id, RegisteredSession::typeOf($user), 'web', null, Assurance::AAL1, null, null, 0, 0, now()->addDay()->getTimestamp()));

    $this->artisan('keyring:prune')->assertSuccessful();

    expect(Keyring::deviceModel()::pluck('id')->all())->toBe([$current->id])
        ->and(PendingChange::pluck('id')->sort()->values()->all())->toBe(collect($kept)->pluck('id')->sort()->values()->all())
        ->and(SecurityEvent::pluck('id')->all())->toBe([$recent->id])
        ->and($registry->find('ended'))->toBeNull()
        ->and($registry->find('live'))->not->toBeNull();
});

it('leaves sessions kept in the cache to run out on their own', function () {
    config(['keyring.sessions.driver' => 'cache']);
    $user = taylor();
    $registry = app(SessionRegistry::class);
    $registry->save(new RegisteredSession('live', (string) $user->id, RegisteredSession::typeOf($user), 'web', null, Assurance::AAL1, null, null, 0, 0, now()->addHour()->getTimestamp()));

    $this->artisan('keyring:prune')->expectsOutputToContain('Pruned 0 ended sessions.')->assertSuccessful();

    expect($registry->find('live'))->not->toBeNull();

    // Its record goes with the time it was kept for.
    $this->travel(2)->hours();

    expect($registry->find('live'))->toBeNull();
});

describe('keyring:sign-out', function () {
    beforeEach(function () {
        $this->user = taylor();
        $this->other = User::create(['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => 'password', 'email_verified_at' => now()]);

        /** A session of the user's, started a moment ago. */
        $this->session = function (User $user, string $id, array $with = []): RegisteredSession {
            $now = now()->getTimestamp();

            return tap(
                new RegisteredSession($id, (string) $user->id, RegisteredSession::typeOf($user), 'web', null, Assurance::AAL1, null, null, $now, $now, $now + 3600)->with($with),
                fn (RegisteredSession $session) => app(SessionRegistry::class)->save($session),
            );
        };
    });

    it('signs one user out of every session, named by ID', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        $registry = app(SessionRegistry::class);

        ($this->session)($this->user, 'laptop');
        ($this->session)($this->user, 'phone');
        ($this->session)($this->other, 'theirs');
        $this->user->forceFill(['remember_token' => 'remembered'])->save();
        $device = $this->user->devices()->forceCreate(['token_hash' => hash('sha256', 'laptop'), 'trusted_until' => now()->addDay()]);

        $this->artisan('keyring:sign-out', ['user' => (string) $this->user->id])
            ->expectsOutputToContain("Signed out taylor@example.com (ID {$this->user->id}): 2 sessions ended.")
            ->assertSuccessful();

        // As Sessions::signOutEverywhere() leaves things: no way back in
        // without signing in.
        expect($registry->forUser($this->user))->toBeEmpty()
            ->and($registry->find('laptop')->revokedAt)->not->toBeNull()
            ->and($this->user->fresh()->remember_token)->not->toBe('remembered')
            ->and($device->fresh()->isTrusted())->toBeFalse()
            ->and($registry->forUser($this->other)->map->id->all())->toBe(['theirs'])
            ->and(SecurityEvent::query()->where('type', 'sessions_revoked')->sole()->meta)->toBe(['count' => 2]);
    })->with(['database', 'cache']);

    it('finds a user by their username too, however it was typed', function () {
        ($this->session)($this->user, 'laptop');

        $this->artisan('keyring:sign-out', ['user' => ' Taylor@Example.com'])
            ->expectsOutputToContain('1 session ended.')
            ->assertSuccessful();

        expect(app(SessionRegistry::class)->forUser($this->user))->toBeEmpty();
    });

    it('finds a user by ID or username through a user provider of the app\'s own', function (string $name) {
        WrappedUserProvider::use();
        ($this->session)($this->user, 'laptop');
        ($this->session)($this->other, 'theirs');

        $this->artisan('keyring:sign-out', ['user' => $name === 'id' ? (string) $this->user->id : 'taylor@example.com'])
            ->expectsOutputToContain("Signed out taylor@example.com (ID {$this->user->id}): 1 session ended.")
            ->assertSuccessful();

        expect(app(SessionRegistry::class)->forUser($this->user))->toBeEmpty()
            ->and(app(SessionRegistry::class)->forUser($this->other))->toHaveCount(1);
    })->with(['id', 'username']);

    it('signs out nobody when the name is one user\'s ID and another\'s username', function () {
        config(['keyring.username' => 'name']);
        $this->user->forceFill(['name' => (string) $this->other->id])->save();

        ($this->session)($this->user, 'named');
        ($this->session)($this->other, 'numbered');

        $this->artisan('keyring:sign-out', ['user' => (string) $this->other->id])
            ->expectsOutputToContain("could be Abigail (ID {$this->other->id}) or {$this->other->id} (ID {$this->user->id})")
            ->assertFailed();

        expect(app(SessionRegistry::class)->find('named')->revokedAt)->toBeNull()
            ->and(app(SessionRegistry::class)->find('numbered')->revokedAt)->toBeNull();

        // Said to be an ID, it can only mean one of them.
        $this->artisan('keyring:sign-out', ['user' => (string) $this->other->id, '--id' => true])->assertSuccessful();

        expect(app(SessionRegistry::class)->find('named')->revokedAt)->toBeNull()
            ->and(app(SessionRegistry::class)->find('numbered')->revokedAt)->not->toBeNull();
    });

    it('takes a username that is the same user\'s ID for that user', function () {
        config(['keyring.username' => 'name']);
        $this->user->forceFill(['name' => (string) $this->user->id])->save();
        ($this->session)($this->user, 'laptop');

        $this->artisan('keyring:sign-out', ['user' => (string) $this->user->id])->assertSuccessful();

        expect(app(SessionRegistry::class)->find('laptop')->revokedAt)->not->toBeNull();
    });

    it('says so when nobody goes by the name', function (string $name) {
        ($this->session)($this->user, 'laptop');

        $this->artisan('keyring:sign-out', ['user' => $name])
            ->expectsOutputToContain("No user has the ID or username [{$name}].")
            ->assertFailed();

        expect(app(SessionRegistry::class)->find('laptop')->revokedAt)->toBeNull();
    })->with(['nobody@example.com', '999999', '99999999999999999999999999']);

    it('needs one user or --all, and not both', function (array $arguments) {
        ($this->session)($this->user, 'laptop');

        $this->artisan('keyring:sign-out', $arguments)
            ->expectsOutputToContain('Name one user to sign out, or pass --all to sign out everyone.')
            ->assertExitCode(2);

        expect(app(SessionRegistry::class)->find('laptop')->revokedAt)->toBeNull();
    })->with([
        'neither' => [[]],
        'both' => [['user' => '1', '--all' => true, '--force' => true]],
    ]);

    it('signs everyone out once it has asked', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        $registry = app(SessionRegistry::class);

        ($this->session)($this->user, 'laptop');
        ($this->session)($this->other, 'theirs');

        $this->artisan('keyring:sign-out', ['--all' => true])
            ->expectsConfirmation('Sign every user out of every session?', 'no')
            ->assertFailed();

        expect($registry->forUser($this->user))->toHaveCount(1)
            ->and($registry->forUser($this->other))->toHaveCount(1);

        $this->artisan('keyring:sign-out', ['--all' => true])
            ->expectsConfirmation('Sign every user out of every session?', 'yes')
            ->assertSuccessful();

        expect($registry->forUser($this->user))->toBeEmpty()
            ->and($registry->forUser($this->other))->toBeEmpty()
            ->and($registry->find('laptop')->revokedAt)->not->toBeNull()
            ->and($registry->find('theirs')->revokedAt)->not->toBeNull();
    })->with(['database', 'cache']);

    it('signs everyone out without asking when forced', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        ($this->session)($this->user, 'laptop');

        $this->artisan('keyring:sign-out', ['--all' => true, '--force' => true])->assertSuccessful();

        expect(app(SessionRegistry::class)->forUser($this->user))->toBeEmpty();
    })->with(['database', 'cache']);

    it('ends a session whichever record it has moved to, and the records it left behind', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        $registry = app(SessionRegistry::class);

        $first = ($this->session)($this->user, 'first');
        $registry->replace('first', $second = $first->with(['id' => 'second']));
        $registry->replace('second', $second->with(['id' => 'third']));

        $this->artisan('keyring:sign-out', ['--all' => true, '--force' => true])->assertSuccessful();

        expect($registry->find('first')->revokedAt)->not->toBeNull()
            ->and($registry->find('second')->revokedAt)->not->toBeNull()
            ->and($registry->find('third')->revokedAt)->not->toBeNull();
    })->with(['database', 'cache']);

    it('leaves a session that signs in afterwards alone', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);

        $this->artisan('keyring:sign-out', ['--all' => true, '--force' => true])->assertSuccessful();

        $this->travel(1)->seconds();
        ($this->session)($this->user, 'afterwards');

        expect(app(SessionRegistry::class)->forUser($this->user)->map->id->all())->toBe(['afterwards']);
    })->with(['database', 'cache']);

    it('ends more sessions than it revokes in one go', function () {
        $now = now()->getTimestamp();

        DB::table('keyring_sessions')->insert(array_map(fn (int $n) => new RegisteredSession("session-{$n}", (string) $this->user->id, RegisteredSession::typeOf($this->user), 'web', null, Assurance::AAL1, null, null, $now, $now, $now + 3600)->toArray(), range(1, 1001)));

        $this->artisan('keyring:sign-out', ['--all' => true, '--force' => true])->assertSuccessful();

        expect(DB::table('keyring_sessions')->whereNull('revoked_at')->count())->toBe(0);
    });

    it('keeps a session signed out that was moving to a new record as everyone was signed out, on the cache driver', function () {
        config(['keyring.sessions.driver' => 'cache']);
        $registry = app(SessionRegistry::class);

        $session = ($this->session)($this->user, 'remembered');
        $this->travel(1)->minutes();
        $registry->revokeEveryone();

        // Stored a moment later, by a request that read the old record first.
        $registry->save($session->with(['id' => 'resumed', 'lastActivityAt' => now()->getTimestamp()]));

        expect($registry->find('resumed')->revokedAt)->not->toBeNull()
            ->and($registry->forUser($this->user))->toBeEmpty();
    });
});

it('schedules the prune itself, every day, so nothing is kept because a line was left out', function () {
    $pruning = collect(app(Schedule::class)->events())->filter(fn (Event $event) => str_contains((string) $event->command, 'keyring:prune'));

    expect($pruning)->toHaveCount(1)
        ->and($pruning->first()->expression)->toBe('0 3 * * *');

    // The scheduled command is the one that prunes.
    $this->artisan('schedule:list')->expectsOutputToContain('keyring:prune')->assertSuccessful();
});

it('lets the app move the daily prune, or schedule it for itself', function (?string $at, array $expressions) {
    config(['keyring.prune_at' => $at]);
    app()->forgetInstance(Schedule::class);

    expect(collect(app(Schedule::class)->events())
        ->filter(fn (Event $event) => str_contains((string) $event->command, 'keyring:prune'))
        ->map(fn (Event $event) => $event->expression)->values()->all())->toBe($expressions);
})->with([
    'another time' => ['01:30', ['30 1 * * *']],
    'not at all' => [null, []],
]);

it('describes the setup in artisan about', function () {
    $this->artisan('about', ['--only' => 'keyring'])
        ->expectsOutputToContain('password, passkey, totp, recovery')
        ->expectsOutputToContain('registration, reset-passwords, email-verification')
        ->assertSuccessful();
});

it('publishes a provider that sends everyone without a second factor to set one up, when that was asked for', function () {
    config(['keyring.enrollment_url' => '/settings/security']);
    Route::middleware('web')->get('/anywhere', fn () => 'through');
    Route::middleware('web')->get('/settings/security', fn () => 'set one up');

    // The stub as a whole, which has the line keyring:install keeps for a yes.
    new KeyringServiceProvider($this->app)->boot();

    $this->get('/anywhere')->assertOk();

    $user = taylor();
    $this->actingAs($user)->get('/anywhere')->assertRedirect('/settings/security')->assertSessionHas('status', 'enroll-first');
    $this->get('/settings/security')->assertOk()->assertSee('set one up');

    Authenticator::factory()->totp()->for($user, 'authenticatable')->create();

    $this->get('/anywhere')->assertOk()->assertSee('through');
});

// Adding a sign-in method later is uncommenting its line, in an app whose
// code style may have removed any import only a comment named.
it('publishes a provider whose commented-out lines work once uncommented', function () {
    $provider = (fn () => $this->provider(new Filesystem, [], false))->call(new InstallCommand);

    expect($provider)->not->toContain('use Illuminate\Contracts\Http\Kernel;')->not->toContain('use Keyring\Factors\\');

    $class = 'UncommentedKeyringServiceProvider';
    $path = sys_get_temp_dir().'/keyring-provider-'.uniqid().'.php';
    file_put_contents($path, str_replace(
        ['class KeyringServiceProvider', '// Factors\\', '// $this->app->make('],
        ["class {$class}", 'Factors\\', '$this->app->make('],
        $provider,
    ));

    require $path;
    File::delete($path);

    new ("App\\Providers\\{$class}")($this->app)->boot();

    expect(Keyring::registered()->keys()->all())->toBe(['password', 'totp', 'recovery', 'passkey', 'security-key', 'email-code'])
        ->and(app(Router::class)->getMiddlewareGroups()['web'])->toContain('keyring.enrolled');
});

it('publishes a provider that boots, with everything picked', function () {
    // The stub as a whole; keyring:install removes what isn't picked.
    new KeyringServiceProvider($this->app)->boot();

    expect(app(UpdatesUserPasswords::class))->toBeInstanceOf(UpdateUserPassword::class)
        ->and(app(ResetsUserPasswords::class))->toBeInstanceOf(ResetUserPassword::class)
        ->and(app(ValidatesEmailChanges::class))->toBeInstanceOf(ValidateEmailChange::class)
        ->and(Keyring::registered()->keys()->all())->toBe(['password', 'totp', 'recovery', 'passkey', 'security-key', 'email-code']);
});
