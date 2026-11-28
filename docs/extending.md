# Extending Keyring

- [Introduction](#introduction)
- [What You Can Change](#what-you-can-change)
- [Replacing a Controller or Service](#replacing-a-controller-or-service)
- [Changing the Routes](#changing-the-routes)
- [What Stays Fixed](#what-stays-fixed)

## Introduction

Once you've run `keyring:install` and a migration, Keyring works. From there, nearly everything it does is yours to change. The code that an application is expected to own is published into your application. That includes the config, the migrations, a service provider, and the [actions](protected-changes.md). The rest stays in the package, notifications included, where it keeps receiving fixes. You change it through options and hooks, and the [notifications](security-log-and-emails.md#security-emails) through `Keyring::notifications()`.

This page lists all of them, along with where each one is explained. The [Recipes](recipes.md) page has worked examples of the most common ones.

## What You Can Change

| To change | Use | See |
|---|---|---|
| Which features are on | The `features` list | [Adding Features](quick-start.md#adding-features) |
| Any number, lifetime, or limit | `config/keyring.php` | [Configuration](configuration.md) |
| How users sign in | `Keyring::factors()`, `Keyring::extend()`, your own `Factor` | [Factors](factors.md) |
| What they must prove | `Keyring::require()` | [Policies](policies.md) |
| The steps a verification runs | `Keyring::pipeline()` | [The Pipeline](sign-in-flow.md#the-verification-pipeline) |
| Signing in with Google, Microsoft, GitHub or an OpenID Connect provider | The `SingleSignOn` factor and `sso.providers` | [Single Sign-On](sso.md) |
| An identity provider Keyring has no driver for, or a change to one it has | `Keyring::sso()->extend()`, your own `IdentityProvider` | [Custom Drivers](sso.md#custom-drivers) |
| Signing in from a route of your own, like a provider's callback | `Keyring::attempt()` and a factor that can start a login | [Starting a Sign In Yourself](sign-in-flow.md#starting-a-sign-in-yourself) |
| How a user is found, and how usernames are normalised | `Keyring::findUsersUsing()`, `Keyring::normalizeUsernamesUsing()` | [Finding the User](sign-in-flow.md#finding-the-user) |
| The attribute users sign in with, and the one holding their address | `username` and `email` | [Guard and Users](configuration.md#guard-and-users) |
| Creating users, resetting and changing passwords, validating a new address | The published actions in `app/Actions/Keyring` | [Protected Changes](protected-changes.md) |
| Every email: wording, template, channel, or whether it's sent | `Keyring::notifications()`, with your own class for a type or `null`, and `SecurityNotice::toMailUsing()` | [Security Emails](security-log-and-emails.md#security-emails) |
| What a page renders | `Keyring::page()` | [Pages](sign-in-flow.md#pages) |
| What Keyring answers with | `Keyring::respondWith()` and the contracts in `Keyring\Contracts\Responses` | [Responses](sign-in-flow.md#responses) |
| Validation and status messages | The `keyring-lang` translation files | [Messages and Translations](configuration.md#messages-and-translations) |
| The route prefix, domain, and middleware | `prefix`, `domain`, and `middleware` | [Routes](configuration.md#routes) |
| The middleware on account changes | `changes_middleware` | [Account Changes and Enrollment](configuration.md#account-changes-and-enrollment) |
| What starting an impersonation takes, how long it lasts, and whether the user sees it | `impersonation.*` | [Impersonation](configuration.md#impersonation) |
| The form rate limits | The `keyring`, `keyring-pages`, and `keyring-login-options` rate limiters | [Rate Limits](configuration.md#pending-logins-timebox-and-rate-limits) |
| Who may sign in at all | `Keyring::allowSignInWhen()` | [Who May Sign In](sign-in-flow.md#who-may-sign-in) |
| Who may add a sign-in method | `Keyring::allowEnrollmentWhen()` | [Who May Enroll](authenticators.md#who-may-enroll) |
| Who may impersonate whom | `Keyring::allowImpersonationWhen()` | [Who May Impersonate Whom](impersonation.md#who-may-impersonate-whom) |
| Whether registration says when an address is taken | `registration.reveal_taken` | [Registration](sign-in-flow.md#registration) |
| Whether registering signs the user in, when it says so | `Keyring::signInAfterRegistering()` | [Saying When an Address Is Taken](sign-in-flow.md#saying-when-an-address-is-taken) |
| Risk signals and what they do | `Keyring::risk()`, your own `Signal` | [Risk](risk.md) |
| Where a request is located | `devices.locator`, your own `LocatesIps` | [Devices & Sessions](devices-and-sessions.md) |
| Whose key attestation is trusted | `webauthn.attestation_roots`, your own `TrustsAuthenticators` | [Passkeys & Security Keys](passkeys.md#trusting-each-model-separately) |
| How a browser is described | `Keyring::describeDevicesUsing()` | [Devices & Sessions](devices-and-sessions.md) |
| Where sessions are registered | `sessions.driver`, your own `SessionRegistry` | [The Session Registry](devices-and-sessions.md#the-session-registry) |
| Whether Keyring checks sessions on the `web` group | `sessions.middleware` | [The Session Middleware](devices-and-sessions.md#the-session-middleware) |
| What's stored as an IP address | `Keyring::recordIpsUsing()` | [What's Stored](security-log-and-emails.md#whats-stored) |
| Where emailed links start | `Keyring::linkRootUsing()` | [Emailed Links](security.md#emailed-links) |
| The models | `Keyring::useAuthenticatorModel()` and the other four | [The Keyring Facade](configuration.md#the-keyring-facade) |
| Which attributes are protected | `protected`, `Keyring::withoutProtection()` | [Protected Changes](protected-changes.md) |

Devices, email changes, and every sign-in method except the password are off until you turn them on. The [risk signals](risk.md) come from whatever your `KeyringServiceProvider` lists. The provider that `keyring:install` publishes starts with a set. An application without that provider has none. The [security notices](security-log-and-emails.md#security-emails) are Keyring's own, and are sent by default with or without that provider.

## Replacing a Controller or Service

Keyring's controllers and services are resolved from the container. That means you can swap one out by binding your own class in the `register()` method of a service provider. Extend Keyring's class, and override whatever you need:

```php
use App\Http\Controllers\AuthenticatorController;
use Keyring\Http\Controllers\AuthenticatorController as KeyringAuthenticatorController;

$this->app->bind(KeyringAuthenticatorController::class, AuthenticatorController::class);
```

The services behind them work the same way. They include `Keyring\Login\SignIn`, `Keyring\Login\StepUp`, `Keyring\Login\Detours`, `Keyring\Changes\AuthenticatorChanges`, `EmailChanges` and `PasswordChanges`, `Keyring\Devices\DeviceManager`, `Keyring\Support\Throttle`, and `Keyring\WebAuthn\Ceremonies`. Their methods are public or protected, never private.

`Detours` keeps the page a user was going to when Keyring sent them to enroll or to choose a new password, for them to [carry on to afterwards](policies.md#carrying-on-afterwards). Every page it saves goes through its `remember()` method, which checks it and then calls `put()` with the request, the key for the detour (`Detours::ENROLLMENT` or `Detours::PASSWORD_CHANGE`), and the URL being saved. Override `put()` to keep out pages you never want a user carried on to. Look at `$url`, not the request, because on the confirm page the request is the confirm page and `$url` is the page the confirmation was for. For example, an OpenID provider that answers a `prompt=none` authorize request with an error has nothing to come back to:

```php
namespace App\Login;

use Illuminate\Http\Request;
use Illuminate\Support\Uri;
use Keyring\Login\Detours as KeyringDetours;

class Detours extends KeyringDetours
{
    protected function put(Request $request, string $key, string $url): void
    {
        if (Uri::of($url)->query()->get('prompt') === 'none') {
            return;
        }

        parent::put($request, $key, $url);
    }
}
```

Bind it with `$this->app->bind(KeyringDetours::class, Detours::class)`. A page you skip leaves what was saved before alone. The requirement that sent the user to enroll is in `$this->requiring` while `put()` runs, and the parent saves it with the page, so call the parent rather than writing to the session yourself.

Think of this as a last resort. A class you've replaced stops receiving Keyring's fixes for whatever you override. So prefer an option or hook from the table above when one does the job, and in a method you do override, call the parent's method for everything you aren't changing.

## Changing the Routes

The `prefix`, `domain`, and `middleware` options cover most changes. To register the routes inside a group of your own, set `routes` to `false`, and call `Keyring::routes()` in that group. Your group then decides the prefix and domain, and Keyring still adds the `middleware` option. If you need to change a route itself, you may copy `vendor/keyring/keyring/routes/keyring.php` into your application, and load that copy instead. Keep the route names, though. Keyring's controllers, responses, and emailed links find routes by name. See [Routes](configuration.md#routes).

## What Stays Fixed

A few things have no switch. Turning them off would quietly remove a protection:

- Email codes can't be registered as a factor with plain `EmailCode::class`. Keyring refuses it. Register `EmailCode::asExtraStep()` instead, whose name says what you're accepting. See [What Turning Email Codes On Means](factors.md#what-turning-email-codes-on-means).
- A user can't remove their last way to sign in. Removing the last second factor also requires the password, typed again, and that password must be long enough to stand alone.
- An email change is confirmed from the new address and announced to the old one. The old address can undo it.
- Trusting a device takes a real second factor. A confirm page opened without a step-up behind it never accepts recovery codes.
- You can't drop the steps that check rate limits, the policy, and risk from the pipeline by accident. The `dangerouslyReplace()` method is there for when you mean it.
- Emailed links are never built from the request's `Host` header.

Keyring also needs Eloquent user models that use the `HasKeyring` trait, and a session guard. It doesn't sign users in with token guards.

The field names that forms post (`remember`, `trust`, `code`, `credential`, and `authenticator`), the route names, and the status slugs are fixed too. The [browser package](frontend.md) and your pages rely on them.
