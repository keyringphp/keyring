<?php

declare(strict_types=1);

namespace Keyring\Console;

use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Str;
use Keyring\Concerns\HasKeyring;
use Keyring\Facades\Keyring;
use Keyring\Features;
use Symfony\Component\Console\Attribute\AsCommand;

use function Laravel\Prompts\confirm;
use function Laravel\Prompts\multiselect;

#[AsCommand(name: 'keyring:install')]
#[Description('Install Keyring: pick sign-in methods and features, then publish the config, migrations, a provider and your actions')]
#[Signature('keyring:install
        {--factor=* : A sign-in method to add besides the password: totp, passkeys, security-keys or email-codes. Without one, or with none, users sign in with the password alone}
        {--feature=* : A feature to turn on, replacing the defaults (registration, reset-passwords, email-verification, update-passwords and security-log): registration, reset-passwords, email-verification, update-passwords, manage-authenticators, devices, email-changes, security-log or impersonation}
        {--require-second-factor : Make every user set up a second factor (the default once you add an authenticator app, passkeys or security keys)}
        {--optional-second-factor : Leave setting up a second factor to each user}
        {--force : Overwrite files that already exist}')]
class InstallCommand extends Command
{
    /**
     * The features turned on unless others are picked. What config/keyring.php
     * ships with says the same.
     */
    protected const array FEATURES = ['registration', 'reset-passwords', 'email-verification', 'update-passwords', 'security-log'];

    /**
     * Sign-in methods besides the password, and each one's line in the
     * provider's Keyring::factors() call. The ones that aren't picked stay
     * there commented out, so adding one later is uncommenting its line.
     * None is picked unless asked for: a new app starts with the password.
     *
     * An emailed code is named for what it is: a step at sign in. NIST
     * SP 800-63B-4 takes email as no authenticator, so a password and a
     * code is still AAL1, and the provider says so above its line.
     */
    protected const array FACTORS = [
        'totp' => ['Authenticator app', 'Factors\Totp::class,'],
        'passkeys' => ['Passkeys', 'Factors\WebAuthn::passkeys(),'],
        'security-keys' => ['Security keys, as a second factor', 'Factors\WebAuthn::securityKeys(),'],
        'email-codes' => ['Email codes, as an extra step at sign in (not a second factor)', 'Factors\EmailCode::asExtraStep(),'],
    ];

    /**
     * The provider's line for recovery codes. They come with any of the
     * sign-in methods above, so losing the only one isn't the end of the
     * account, and they're no use to an account that has none.
     */
    protected const string RECOVERY_CODES = 'Factors\RecoveryCodes::class,';

    /** What --factor takes to mean the password alone, without being asked. */
    protected const string NO_FACTORS = 'none';

    /**
     * The provider's comment above the line that makes everyone set up a
     * second factor, and what replaces it when that line is commented out.
     * The line then names the kernel in full, so uncommenting it works in an
     * app whose code style has since removed the import.
     */
    protected const array ENROLLMENT = [
        "        // Everyone needs a second factor: until they've set one up, every page\n        // sends them to the \"enrollment_url\" in config/keyring.php.\n        \$this->app->make(Kernel::class)" => "        // To make everyone set up a second factor, uncomment this and set\n        // \"enrollment_url\" in config/keyring.php to your page for adding one.\n        // \$this->app->make(\\Illuminate\\Contracts\\Http\\Kernel::class)",
    ];

    /**
     * The sign-in methods that count as a second factor everyone can be made
     * to set up. An emailed code doesn't: the inbox also resets the password.
     */
    protected const array SECOND_FACTORS = ['totp', 'passkeys', 'security-keys'];

    /**
     * The risk signals the provider starts with, and the feature each reads
     * from. One whose feature is off is left commented out, there to turn on
     * with it. They need no network call and nothing the app hasn't got, and
     * their scores can't add up to a refused sign in for a user with only a
     * password. The rest are in the provider commented out, each with what
     * it needs.
     */
    protected const array SIGNALS = [
        'SessionFingerprintChanged' => null,
        'RepeatedFactorFailures' => 'security-log',
        'SuccessAfterFailures' => 'security-log',
        'NewDevice' => 'devices',
        'InactiveAccount' => 'devices',
    ];

    /**
     * Where users are sent to set up a second factor, as the Quick Start
     * names the settings page.
     */
    protected const string ENROLLMENT_URL = '/settings/security';

    protected const string STUBS = __DIR__.'/../../stubs';

    protected const string MIGRATIONS = __DIR__.'/../../database/migrations';

    public function handle(Filesystem $files): int
    {
        $unknown = array_filter([
            '--factor' => [array_diff((array) $this->option('factor'), array_keys(self::FACTORS), [self::NO_FACTORS]), [...array_keys(self::FACTORS), self::NO_FACTORS]],
            '--feature' => [array_diff((array) $this->option('feature'), Features::all()), Features::all()],
        ], fn (array $option) => $option[0] !== []);

        foreach ($unknown as $option => [$values, $known]) {
            $this->components->error("Unknown {$option}: ".implode(', ', $values).'. Pick from: '.implode(', ', $known).'.');
        }

        if ($unknown !== []) {
            return self::FAILURE;
        }

        $factors = $this->factors();

        // Nobody could meet it, and every page would send them to set up
        // a sign-in method the app doesn't offer.
        if ($this->option('require-second-factor') && array_intersect($factors, self::SECOND_FACTORS) === []) {
            $this->components->error('Requiring a second factor needs one users can set up'.(in_array('email-codes', $factors, true) ? ', and an emailed code isn\'t one' : '').'. Add --factor='.implode(', --factor=', self::SECOND_FACTORS).'.');

            return self::FAILURE;
        }

        // The provider and actions are your code from here on. Every action
        // is published, so turning a feature on later just works.
        $provider = app_path('Providers/KeyringServiceProvider.php');
        $writesProvider = ! $files->exists($provider) || $this->option('force');

        // The provider is what makes it so, so one that's kept isn't asked.
        $enrolled = $writesProvider && $this->requiresSecondFactor($factors);

        // An existing config is the app's, so there's nothing to ask about it.
        if ($writesConfig = ! $files->exists(config_path('keyring.php')) || $this->option('force')) {
            $features = $this->features($factors);
            $files->put(config_path('keyring.php'), $this->config($files, $features, $enrolled));
        } else {
            $this->components->warn('Skipped '.config_path('keyring.php').', it already exists.');
            $features = config('keyring.features');
        }

        $migrations = $this->publishMigrations($files);

        if ($writesProvider) {
            $files->ensureDirectoryExists(dirname($provider));
            $files->put($provider, $this->provider($files, $factors, $enrolled, $features));
        } else {
            $this->components->warn("Skipped {$provider}, it already exists.");
        }

        foreach ($files->files(self::STUBS.'/app/Actions/Keyring') as $file) {
            $this->write($files, app_path('Actions/Keyring/'.$file->getFilename()), $file->getContents());
        }

        ServiceProvider::addProviderToBootstrapFile('App\\Providers\\KeyringServiceProvider');

        $this->components->info('Keyring installed.');
        $this->components->bulletList(array_filter([
            $this->userModelHasKeyring() ? null : 'Add <comment>use Keyring\Concerns\HasKeyring;</comment> to your User model',
            in_array(Features::emailVerification(), $features, true) ? 'Make your User model implement <comment>MustVerifyEmail</comment>' : null,
            $migrations === 0 && $this->migrated() ? null : 'Run <comment>php artisan migrate</comment>',
            config('keyring.pages') === false
                ? 'Build Keyring\'s pages in your frontend, see the "Headless Frontends" docs'
                : 'Build the <comment>auth/*</comment> pages Keyring renders, see the "Quick Start" docs, or for a frontend Laravel doesn\'t serve, the "Headless Frontends" docs',
            $writesConfig ? 'Set <comment>support_contact</comment> in <comment>config/keyring.php</comment> to a page or an address users can reach you at: the emails then say who to contact if something wasn\'t them' : null,
            match (true) {
                $enrolled && config('keyring.enrollment_url') === null && ! $writesConfig => 'Set <comment>enrollment_url</comment> in <comment>config/keyring.php</comment> to your page for adding a sign-in method: users are sent there until they have a second factor',
                $enrolled => 'Build your page for adding a sign-in method at <comment>'.self::ENROLLMENT_URL.'</comment>, or point <comment>enrollment_url</comment> in <comment>config/keyring.php</comment> at yours: users are sent there until they have a second factor',
                $writesProvider && $factors === [] => 'Users sign in with a password alone. To add an authenticator app, passkeys or security keys, uncomment its line in your KeyringServiceProvider and <comment>Features::manageAuthenticators()</comment> in <comment>config/keyring.php</comment>',
                $writesProvider => 'Nothing makes users set up a second factor. To require one, see "Requiring a Second Factor" in the "Policies" docs',
                default => null,
            },
            // A config that was kept isn't changed, so it may not have what
            // the provider just written needs.
            $writesProvider && $factors !== [] && ! in_array(Features::manageAuthenticators(), $features, true)
                ? 'Add <comment>Features::manageAuthenticators()</comment> to the features in <comment>config/keyring.php</comment>: without it nobody can set up the sign-in methods you picked'.($enrolled ? ', and everyone is sent to set one up' : '')
                : null,
            $writesProvider && in_array('email-codes', $factors, true) ? 'Email codes are an extra step at sign in, not a second factor: a password and an emailed code is still AAL1. See "Email Codes" in the "Factors" docs' : null,
            'Add features later by uncommenting them in <comment>config/keyring.php</comment>',
        ]));

        // What whoever runs the app will want to know before it's live.
        $this->components->info('Once it\'s running, see "After Installing" in the "Installation" docs.');
        $this->components->bulletList([
            'Sessions end after two hours unused. Set <comment>sessions.idle</comment> in <comment>config/keyring.php</comment> to change that',
            ...Hash::getDefaultDriver() === 'bcrypt' ? ['Passwords are hashed with bcrypt, which reads 72 bytes: longer ones are refused, and that can be under 64 characters of non-Latin text. Set <comment>HASH_DRIVER=argon2id</comment> to take any up to <comment>passwords.max</comment>'] : [],
            'Run the Laravel scheduler (<comment>schedule:run</comment>): it prunes the security log and other old records every day',
            'Signed-in routes outside the <comment>web</comment> group need the <comment>keyring.session</comment> middleware',
            '<comment>php artisan keyring:sign-out</comment> signs one user out everywhere, or everyone with <comment>--all</comment>',
        ]);

        return self::SUCCESS;
    }

    /**
     * Whether every user must set up a second factor. Yes whenever there's
     * one they could set up, unless told otherwise.
     *
     * @param  list<string>  $factors
     */
    protected function requiresSecondFactor(array $factors): bool
    {
        return match (true) {
            array_intersect($factors, self::SECOND_FACTORS) === [] => false,
            $this->option('require-second-factor') => true,
            $this->option('optional-second-factor') => false,
            $this->input->isInteractive() => confirm(
                label: 'Require a second factor for everyone?',
                default: true,
                hint: 'Users sign in with their password, then must set one up at '.self::ENROLLMENT_URL.' before going further.',
            ),
            default => true,
        };
    }

    protected function userModelHasKeyring(): bool
    {
        $provider = Keyring::provider();

        return $provider instanceof EloquentUserProvider && in_array(HasKeyring::class, class_uses_recursive($provider->getModel()), true);
    }

    protected function migrated(): bool
    {
        return rescue(fn () => Schema::hasTable('keyring_authenticators'), false, report: false);
    }

    /**
     * @return list<string>
     */
    protected function factors(): array
    {
        $chosen = (array) $this->option('factor');

        if ($chosen === [] && $this->input->isInteractive()) {
            $chosen = multiselect(
                label: 'Which sign-in methods besides the password?',
                options: array_map(fn (array $factor) => $factor[0], self::FACTORS),
                hint: 'None is fine. Each one stays in app/Providers/KeyringServiceProvider.php, commented out, to add later.',
            );
        }

        // "none" is in no list, so it leaves the password alone.
        return array_values(array_intersect(array_keys(self::FACTORS), $chosen));
    }

    /**
     * @param  list<string>  $factors
     * @return list<string>
     */
    protected function features(array $factors): array
    {
        $chosen = (array) $this->option('feature');

        if ($chosen === []) {
            $chosen = $this->input->isInteractive() ? multiselect(
                label: 'Which features?',
                options: [
                    Features::registration() => 'Registration',
                    Features::resetPasswords() => 'Password resets',
                    Features::emailVerification() => 'Email verification',
                    Features::updatePasswords() => 'Changing the password',
                    Features::manageAuthenticators() => 'Managing sign-in methods (needed to set any up)',
                    Features::devices() => 'Devices: "trust this device" and where you\'re signed in',
                    Features::emailChanges() => 'Email changes, confirmed and undoable',
                    Features::securityLog() => 'Security log and "was this you?" alerts',
                    Features::impersonation() => 'Impersonation: signing in as another user, once you say who may',
                ],
                default: [...self::FEATURES, ...$factors === [] ? [] : [Features::manageAuthenticators()]],
                scroll: 8,
                hint: 'Signing in and out, challenges and step-up are always on.',
            ) : self::FEATURES;
        }

        // Users can't set up the sign-in methods without it.
        if ($factors !== [] && ! in_array(Features::manageAuthenticators(), $chosen, true)) {
            $chosen[] = Features::manageAuthenticators();
            $this->components->info('Turned on managing sign-in methods, so users can set up the ones you picked.');
        }

        // Registering answers the same whether or not an address has an
        // account, so a new user signs in once they've proved theirs. Anyone
        // can register someone else's address, too.
        if (in_array(Features::registration(), $chosen, true) && ! in_array(Features::emailVerification(), $chosen, true)) {
            $chosen[] = Features::emailVerification();
            $this->components->info('Turned on email verification, so users prove their address before they sign in. Registration needs it unless you set registration.reveal_taken in config/keyring.php.');
        }

        return array_values(array_intersect(Features::all(), $chosen));
    }

    /**
     * The short config, with the features left out commented, so they're
     * there to turn on later.
     *
     * @param  list<string>  $features
     */
    protected function config(Filesystem $files, array $features, bool $enrolled): string
    {
        $config = $files->get(self::STUBS.'/config/keyring.php');

        foreach (array_diff(Features::all(), $features) as $feature) {
            $method = Str::camel($feature);
            $config = str_replace("        Features::{$method}(),", "        // Features::{$method}(),", $config);
        }

        return $enrolled
            ? str_replace("'enrollment_url' => null,", "'enrollment_url' => '".self::ENROLLMENT_URL."',", $config)
            : $config;
    }

    /**
     * The provider with the chosen sign-in methods on and the rest commented
     * out, the middleware that makes everyone set up a second factor when
     * that was asked for, and the risk signals the features can feed.
     *
     * @param  list<string>  $factors
     * @param  list<string>  $features
     */
    protected function provider(Filesystem $files, array $factors, bool $enrolled, array $features = self::FEATURES): string
    {
        $provider = $files->get(self::STUBS.'/app/Providers/KeyringServiceProvider.php');

        if (! $enrolled) {
            $provider = strtr($provider, self::ENROLLMENT);
        }

        // A signal whose feature is off would find nothing.
        $signals = array_keys(array_filter(self::SIGNALS, fn (?string $feature) => $feature !== null && ! in_array($feature, $features, true)));

        return $this->withoutUnusedImports($this->commentedOut($provider, [
            ...array_column(array_diff_key(self::FACTORS, array_flip($factors)), 1),
            ...$factors === [] ? [self::RECOVERY_CODES] : [],
            ...array_map(fn (string $signal) => "Signals\\{$signal}::class,", $signals),
        ]));
    }

    /**
     * Comment out the provider's lines that read exactly these, leaving each
     * one there to turn on later.
     *
     * @param  list<string>  $lines
     */
    protected function commentedOut(string $provider, array $lines): string
    {
        return $lines === []
            ? $provider
            : (string) preg_replace('/^( +)('.implode('|', array_map(fn (string $line) => preg_quote($line, '/'), $lines)).')$/m', '$1// $2', $provider);
    }

    /**
     * Drop the imports only a commented-out line names: the app's code style
     * would, and the lines that need one name their class in full.
     */
    protected function withoutUnusedImports(string $code): string
    {
        $live = (string) preg_replace('/^ *\/\/.*$/m', '', $code);

        return (string) preg_replace_callback('/^use [\w\\\\]+\\\\(\w+);\n/m', fn (array $import) => preg_match_all('/\b'.$import[1].'\b/', $live) > 1 ? $import[0] : '', $code);
    }

    /**
     * Publish the migrations this app doesn't have yet, and return how many
     * that was. Publishing the whole tag again would add the ones it has a
     * second time under new timestamps, so each is matched by its name. One
     * added by a later version follows the app's own, in Keyring's order.
     */
    protected function publishMigrations(Filesystem $files): int
    {
        $missing = array_values(array_filter(
            $files->glob(self::MIGRATIONS.'/*.php'),
            fn (string $path) => $files->glob(database_path('migrations/*_'.self::migrationName($path))) === [],
        ));

        foreach ($missing as $index => $path) {
            $files->ensureDirectoryExists(database_path('migrations'));
            $files->copy($path, database_path('migrations/'.now()->addSeconds($index)->format('Y_m_d_His').'_'.self::migrationName($path)));
        }

        return count($missing);
    }

    /**
     * A migration's file name without the date it starts with.
     */
    protected static function migrationName(string $path): string
    {
        return (string) preg_replace('/^\d{4}_\d{2}_\d{2}_\d{6}_/', '', basename($path));
    }

    /**
     * Write a file the app owns, leaving anything already there unless --force.
     */
    protected function write(Filesystem $files, string $to, string $contents): void
    {
        if ($files->exists($to) && ! $this->option('force')) {
            $this->components->warn("Skipped {$to}, it already exists.");

            return;
        }

        $files->ensureDirectoryExists(dirname($to));
        $files->put($to, $contents);
    }
}
