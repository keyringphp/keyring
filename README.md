<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="art/logo-dark.svg">
    <img src="art/logo-light.svg" alt="Keyring" width="320">
  </picture>
</p>

<p align="center">Factor-driven authentication for Laravel. Start with a password, then add passkeys, second factors, devices, and step-up.</p>

<p align="center">
  <a href="https://packagist.org/packages/keyring/keyring"><img src="https://img.shields.io/packagist/v/keyring/keyring" alt="Latest version"></a>
  <a href="https://www.npmjs.com/package/@keyringjs/keyring"><img src="https://img.shields.io/npm/v/@keyringjs/keyring?label=npm" alt="npm version"></a>
  <a href="LICENSE.md"><img src="https://img.shields.io/packagist/l/keyring/keyring" alt="License"></a>
</p>

## Introduction

Keyring is a frontend agnostic authentication backend for Laravel. It registers the routes and controllers needed for sign in, registration, password resets, and email verification, and lets you grow from there with passkeys, authenticator apps, security keys, single sign-on, step-up authentication, and device management.

Every way a user can prove who they are is a **factor**. Users may hold as many **authenticators** as they like, and your **policy** decides what they need to prove. You're free to write factors of your own, too.

> [!NOTE]
> Keyring is new and hasn't been production-tested yet. Until 1.0, a minor release may change the public API. See [What's Stable](#whats-stable) for details.

## Features

- **Many authenticators per user.** Authenticator apps, passkeys, security keys, email codes, and recovery codes, with "try another way" built in. [Factors](docs/factors.md)
- **Single sign-on.** Sign in with Google, Microsoft, GitHub, or any OpenID Connect provider, through the same pipeline as the login form, with no extra package. [Single Sign-On](docs/sso.md)
- **Your own factors.** Add SMS, push notifications, or anything else without new routes, controllers, or tables. [Extending Keyring](docs/extending.md)
- **Devices and sessions.** A list of each user's sessions and "sign out everywhere else" on any session driver, plus trusted devices and new device emails. [Devices & Sessions](docs/devices-and-sessions.md)
- **Step-up authentication.** The `keyring:aal2` and `keyring.fresh:15m` middleware accept a passkey or code, not just a password. [Step-Up](docs/step-up.md)
- **Protected account changes.** Email changes are confirmed from both addresses and may be undone. [Protected Changes](docs/protected-changes.md)
- **Impersonation.** Support staff sign in as a user and come back, only once you say who may, behind a fresh second factor, with a time limit, Keyring's security changes refused meanwhile, and both accounts' security logs saying who did it. [Impersonation](docs/impersonation.md)
- **Risk signals.** New devices, new countries, impossible travel, session cookies reused in another browser, and breached passwords. [Risk](docs/risk.md)
- **A security log and security emails.** Sent from day one, and each one may be replaced, restyled, or turned off. [Security Log & Emails](docs/security-log-and-emails.md)
- **Built on OWASP ASVS 5.0.0 and NIST SP 800-63B-4.** Every requirement is mapped on [one page](docs/owasp-asvs.md).
- **Headless.** You build the pages with Inertia or Blade, or in a separate frontend like Nuxt that gets each page as JSON, and a small browser package handles WebAuthn for Vue and React. [Frontend](docs/frontend.md), [Headless Frontends](docs/headless.md)

## Installation

Keyring requires PHP 8.5+ and Laravel 13.31+. Inertia v3 is optional. Without it, Keyring renders Blade views that you provide.

To get started, install Keyring using the Composer package manager, then run the `keyring:install` Artisan command and your migrations:

```bash
composer require keyring/keyring

php artisan keyring:install

php artisan migrate
```

The `keyring:install` command will ask which sign-in methods and features you would like, and set each of them up for you. Next, add the `HasKeyring` trait to your application's `User` model:

```php
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Keyring\Concerns\HasKeyring;

class User extends Authenticatable implements MustVerifyEmail
{
    use HasKeyring;
}
```

If you plan to offer passkeys, you should also install Keyring's browser package:

```bash
npm install @keyringjs/keyring
```

From here, the [Quick Start](docs/quick-start.md) walks through the pages you'll need to build. If your application already uses Fortify, see [Upgrading From Fortify](docs/upgrading-from-fortify.md).

## Start Small, Add What You Need

A fresh installation includes password sign in, registration, password resets, email verification, and password changes. Rate limiting, password rules, session timeouts, the security log, and security emails are all enabled from the start.

Everything else is already in your application, commented out. To enable a feature, uncomment it:

| To Add | Uncomment |
|---|---|
| Authenticator apps, passkeys, security keys, or email codes | Its line in `Keyring::factors([...])`, along with `Features::manageAuthenticators()` |
| A second factor for everyone | The `keyring.enrolled` line in your provider |
| Trusted devices, a list of where each user is signed in, and new device emails | `Features::devices()` |
| Confirmed, undoable email changes | `Features::emailChanges()` |
| Impersonating users, for support | `Features::impersonation()`, and the `Keyring::allowImpersonationWhen` line in your provider |
| More risk signals | Their lines in `Keyring::risk()->signals([...])` |

The [Adding Features](docs/quick-start.md#adding-features) documentation covers the pages each one needs.

## Documentation

- **Getting Started:** [Quick Start](docs/quick-start.md) · [Installation](docs/installation.md) · [Configuration](docs/configuration.md) · [Upgrading From Fortify](docs/upgrading-from-fortify.md)
- **Signing In:** [Factors](docs/factors.md) · [Policies](docs/policies.md) · [The Sign In Flow](docs/sign-in-flow.md) · [Step-Up](docs/step-up.md) · [Passkeys & Security Keys](docs/passkeys.md) · [Single Sign-On](docs/sso.md) · [More Identity Providers](docs/sso-providers.md)
- **Account Security:** [Managing Authenticators](docs/authenticators.md) · [Devices & Sessions](docs/devices-and-sessions.md) · [Protected Changes](docs/protected-changes.md) · [Impersonation](docs/impersonation.md) · [Risk](docs/risk.md) · [Security Log & Emails](docs/security-log-and-emails.md) · [Events](docs/events.md)
- **Building Your Application:** [Frontend](docs/frontend.md) · [Headless Frontends](docs/headless.md) · [Extending Keyring](docs/extending.md) · [Recipes](docs/recipes.md) · [Testing](docs/testing.md) · [Example Application](https://github.com/keyringphp/example)
- **Security:** [Security](docs/security.md) · [OWASP ASVS and NIST SP 800-63B](docs/owasp-asvs.md)

The [changelog](CHANGELOG.md) lists what changed in each release, and the [upgrade guide](UPGRADE.md) covers anything you need to do when updating.

## What's Stable

Everything described in the documentation is public API: configuration options, routes, middleware, the facade, builders, contracts, events, emails, security log entry types, Artisan commands, testing helpers, and the browser package's exports. Any change to these will be called out in the [upgrade guide](UPGRADE.md). Before 1.0, a minor release may include one.

The rest of `src/`, such as controllers and pipeline internals, may change in any release. The same goes for any class in `Keyring\Support` that the documentation doesn't mention. If you find yourself extending one of these, [Extending Keyring](docs/extending.md) likely has a supported way to do it. If it doesn't, feel free to open an issue.

## Contributing

Thank you for considering contributing to Keyring! You can find the contribution guide in [CONTRIBUTING.md](CONTRIBUTING.md).

## Security Vulnerabilities

Please review [our security policy](SECURITY.md) on how to report security vulnerabilities.

## License

Keyring is open-sourced software licensed under the [MIT license](LICENSE.md).
