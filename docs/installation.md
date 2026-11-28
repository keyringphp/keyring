# Installation

- [Introduction](#introduction)
- [Requirements](#requirements)
- [Installing Keyring](#installing-keyring)
- [What Gets Published](#what-gets-published)
- [Preparing Your User Model](#preparing-your-user-model)
- [Frontend](#frontend)
- [Routes Keyring Registers](#routes-keyring-registers)
- [After Installing](#after-installing)

## Introduction

The [Quick Start](quick-start.md) gives you the short version. This page covers the details you'll want as you set things up.

## Requirements

- PHP 8.5 or later
- Laravel 13.31 or later
- Inertia v3 (optional). Without Inertia, Keyring renders Blade views instead. See [Pages](sign-in-flow.md#pages).
- The `sodium` PHP extension, if you want passkeys and security keys that sign with Ed25519. Without it, Keyring only offers ES256 keys by default.

## Installing Keyring

To get started, install the package with Composer, then run the `keyring:install` Artisan command and your migrations:

```bash
composer require keyring/keyring

php artisan keyring:install
php artisan migrate
```

The `keyring:install` Artisan command asks you three questions:

1. **Which sign-in methods besides the password?** None by default. A new app starts with the password, and the other methods stay in your provider, commented out, so you can add them later. Recovery codes come with any of them. Email codes are listed as what they are: an extra step at sign in, not a second factor. A password and an emailed code is still AAL1 (see [Email Codes](factors.md#what-turning-email-codes-on-means)), and the provider says so above their line.
2. **Require a second factor for everyone?** This question is asked when you pick an authenticator app, passkeys, or security keys, and the answer is yes by default. Users can still sign in with what they have, but every page then sends them to `/settings/security` until they've set one up (see [Requiring a Second Factor](policies.md#requiring-a-second-factor)). The question isn't asked with the password alone or with only email codes. Nobody could meet the requirement in those cases, so nothing requires a second factor.
3. **Which features?** By default, you get registration, password resets, email verification, changing the password, and the security log. If you picked a sign-in method, you also get managing sign-in methods. Registration always brings email verification with it, because by default [new users sign in once they've verified their address](sign-in-flow.md#without-revealing-who-has-an-account).

Without prompts (`--no-interaction`, or in CI), you get the same defaults, which means the password alone. You may also answer the questions with options:

```bash
php artisan keyring:install --factor=totp --factor=passkeys --feature=registration --feature=manage-authenticators --require-second-factor
```

| Option | Values |
|---|---|
| `--factor` | `totp`, `passkeys`, `security-keys`, or `email-codes`. `none` keeps the password alone without asking. |
| `--feature` | `registration`, `reset-passwords`, `email-verification`, `update-passwords`, `manage-authenticators`, `devices`, `email-changes`, `security-log`, or `impersonation`. |
| `--require-second-factor`, `--optional-second-factor` | Answer the second question. |

The `--feature` option replaces the defaults (`registration`, `reset-passwords`, `email-verification`, `update-passwords`, and `security-log`), so list those too if you want them. An unknown value stops the command before it writes anything, and so does requiring a second factor without a sign-in method that counts.

If you need to overwrite files that already exist, pass `--force`. Without it, existing files are skipped. And when `config/keyring.php` is already there, the command doesn't ask which features to turn on.

The command is safe to run again. A migration you already have is never added a second time under a new timestamp, and a migration that a later version brings is added on its own. Running it again on an older install also adds any new actions, but it leaves your provider alone, so you'll need to register those actions there yourself. Until you do, a new action's routes fail with an exception that says which `Keyring::*Using()` call is missing. A new email needs nothing from you. Keyring's emails are its own, so an email that a later version brings is sent from the start.

If you're moving from Fortify, read [Upgrading From Fortify](upgrading-from-fortify.md) before you migrate.

## What Gets Published

The `keyring:install` command publishes the following files:

| File | What It Is |
|---|---|
| `config/keyring.php` | A short config file with the guard, username, home, your features, how registration answers, your enrollment page, and your support contact. Every other option keeps Keyring's default. You may copy any option from [Configuration](configuration.md) to change it. |
| `database/migrations/*_create_keyring_*_table.php` | Eight tables: `keyring_authenticators`, `keyring_devices`, `keyring_sessions`, `keyring_pending_changes`, `keyring_events`, `keyring_failure_counts`, `keyring_password_holds`, and `keyring_sign_in_changes`. They're all created now, so you won't need a new migration to turn on a feature later. Tables for features you don't use stay empty. |
| `database/migrations/*_add_origin_to_keyring_sessions_table.php` | Adds the `origin` column to `keyring_sessions`, which lets a session keep its [handle](devices-and-sessions.md#listing-and-ending-sessions) when it moves to a new record. |
| `database/migrations/*_add_announcements_to_keyring_sessions_table.php` | Adds `announced_at`, `end_reason`, `announce_attempts`, and `announce_after` to `keyring_sessions`, which let [`keyring:sweep`](devices-and-sessions.md#sweeping-ended-sessions) announce every session that ends. |
| `database/migrations/*_add_impersonation_to_keyring_sessions_table.php` | Adds `impersonator_id`, `impersonator_type`, and `impersonator_session` to `keyring_sessions`, which [impersonation](impersonation.md) needs. Only an impersonated session writes them. |
| `app/Providers/KeyringServiceProvider.php` | Where you register sign-in methods, the policy, the risk signals, and your actions. It lists every sign-in method, with the ones you didn't pick commented out. It does the same for the `keyring.enrolled` middleware, which requires a second factor, and for the [risk signals](risk.md) that your features can't feed yet. To add one later, uncomment its line. The provider is added to `bootstrap/providers.php` for you. |
| `app/Actions/Keyring/*.php` | Your code for the features that need it. All of these are published and registered, so a feature works as soon as you turn it on: registration (`CreateNewUser`), password resets (`ResetUserPassword`), password changes (`UpdateUserPassword`), email change requests (`ValidateEmailChange`), and the password rules they share (`PasswordValidationRules`). Keyring does the security work around them. |

Keyring's emails aren't published. They're [Keyring's own](security-log-and-emails.md#security-emails) and are sent from the start. To change one, give `Keyring::notifications()` your own class for it.

You may also publish individual files with the `keyring-config`, `keyring-migrations`, and `keyring-lang` tags. The `keyring-config` tag publishes the full config file, with every option and its default:

```bash
php artisan vendor:publish --tag=keyring-config
```

The migrations use `morphs()` to link rows to users. If your users have UUID or ULID keys, set Laravel's default morph key type before you run the migrations. For example, you may call `Schema::morphUsingUlids()`. You may also edit the published migrations instead.

## Preparing Your User Model

Add the `HasKeyring` trait to your user model:

```php
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Keyring\Concerns\HasKeyring;

class User extends Authenticatable implements MustVerifyEmail
{
    use HasKeyring;

    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
        ];
    }
}
```

The `HasKeyring` trait does three things for you:

- It adds `$user->keyring`, `$user->authenticators()`, and `$user->devices()`.
- Once Keyring handles changes to the `password` and `email` attributes, which happens when you enable `Features::updatePasswords()` and `Features::emailChanges()`, the trait stops those attributes from changing outside Keyring's own flows. See [Protected Changes](protected-changes.md).
- When you delete a user, the trait revokes their sessions, ends their reset links, and deletes their authenticators, devices, and pending changes. With soft deletes, the sessions and reset links end straight away, along with "remember me" cookies, device trust, and any pending email change. Everything else waits for a force delete. A restored user keeps their sign-in methods and signs in again.

The published actions hash the password themselves, so they work with or without the `hashed` cast shown above. When you use the cast, a password that's already hashed isn't hashed again.

`MustVerifyEmail` and `Features::emailVerification()` go together. If your model has the interface but the feature is off, registering throws an exception that says so, before anything is saved. Registration needs both, because a new user is signed out until they've verified their address: the application won't boot with registration on and the feature off, and registering throws without the interface. The exception is [`registration.reveal_taken`](sign-in-flow.md#saying-when-an-address-is-taken), which needs neither. If your users implement `MustVerifyEmail`, they must also verify their address before they can add a sign-in method. See [Managing Authenticators](authenticators.md#email-verification).

By default, Keyring looks users up by the `email` attribute. You may change this with `username` (see [Configuration](configuration.md#guard-and-users)). Lookups trim and lowercase the input, so store addresses the same way. The `Keyring::normalizeUsername` method does exactly that, and the published `CreateNewUser` action uses it. To normalise differently, see [Finding the User](sign-in-flow.md#finding-the-user).

## Frontend

If you plan to offer passkeys or security keys, install `@keyringjs/keyring`, Keyring's browser package. It also has helpers for the challenge page:

```bash
npm install @keyringjs/keyring
```

See [Frontend](frontend.md) for what the package provides.

## Routes Keyring Registers

By default, Keyring registers its routes under the `web` middleware group, and every signed-in route checks Keyring's guard (`auth:{guard}`). Some of the routes use the same names as Laravel's conventions, such as `login`, `logout`, `register`, `password.request`, `password.reset`, `verification.notice`, and so on. If you have routes of your own with those names, remove them. You can find the full list in [The Sign In Flow](sign-in-flow.md#routes), [Step-Up](step-up.md), [Managing Authenticators](authenticators.md#routes), [Devices & Sessions](devices-and-sessions.md#routes), and [Protected Changes](protected-changes.md#routes).

If you want to change the prefix, domain, or middleware, or turn the routes off, see [Configuration](configuration.md#routes).

## After Installing

- Set `APP_URL` to the address your users actually visit. Keyring builds emailed links from it. Passkeys and security keys only work on that origin, unless you configure others. See [Passkeys & Security Keys](passkeys.md#relying-party-and-origins).
- Build your [pages](quick-start.md#your-pages). If you required a second factor, you'll also need the page at `enrollment_url`.
- If your queue isn't `sync`, run a queue worker. [Security emails](security-log-and-emails.md#security-emails) are queued, so they wait for the worker, while sign-in codes go out straight away.
- You may add [features](quick-start.md#adding-features) and [sign-in methods](quick-start.md#adding-sign-in-methods) as you need them.
- Run Laravel's scheduler (`* * * * * php artisan schedule:run`) if you don't already. Keyring adds `keyring:prune` to the schedule, and it runs daily. That command clears out old devices, finished email changes, old security log entries, ended sessions, and old sign-in changes. See [Pruning](devices-and-sessions.md#pruning).
- Sessions end after two hours of inactivity, whatever `session.lifetime` says, unless the browser ticked "remember me". To change that, set `sessions.idle`. See [Timeouts](devices-and-sessions.md#timeouts).
- If you have signed-in routes outside the `web` group, they need the `keyring.session` middleware. Otherwise, a revoked or timed-out session keeps working on those routes. See [The Session Middleware](devices-and-sessions.md#the-session-middleware).
- To hear about every session that ends, including ones that time out with no request, set `sessions.sweep_every`. Keyring then schedules `keyring:sweep`. See [Sweeping Ended Sessions](devices-and-sessions.md#sweeping-ended-sessions).
- The `keyring:sign-out` Artisan command signs one user out everywhere. Pass `--all` to sign everyone out instead. It's useful for a stolen laptop, or for an account that someone else got into. See [For Administrators](devices-and-sessions.md#for-administrators).

`keyring:install` ends by listing a few things to check before going live: the idle timeout, a bcrypt note when bcrypt is the default hasher, the scheduler, the `keyring.session` middleware, and `keyring:sign-out`.
