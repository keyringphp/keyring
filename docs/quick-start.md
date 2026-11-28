# Quick Start

- [Introduction](#introduction)
- [Installing](#installing)
- [Your Pages](#your-pages)
- [Your Settings Page](#your-settings-page)
- [Testing](#testing)
- [Adding Features](#adding-features)
- [Adding Sign-In Methods](#adding-sign-in-methods)
- [What Keyring Does Without Being Asked](#what-keyring-does-without-being-asked)

## Introduction

Signing in with a password, signing out, challenges, and step-up are always on. A default installation adds registration, password resets, email verification, password changes, and the security log. Everything else is a feature or sign-in method that you may add whenever your application needs it.

## Installing

To get started, install Keyring using Composer, then run the `keyring:install` Artisan command and your database migrations:

```bash
composer require keyring/keyring

php artisan keyring:install

php artisan migrate
```

The `keyring:install` command will ask which sign-in methods you would like besides the password, whether everyone must set up a second factor (if you picked a sign-in method that can be one), and which features to enable. Recovery codes are included with any second sign-in method, so losing it isn't the end of an account.

If you accept every default, or run the command with `--no-interaction`, you'll get the password, registration, password resets, email verification, password changes, and the security log. Everything else can be added later by uncommenting a line. Every sign-in method is already in your service provider, every feature is in the configuration file, and every action is published, so each one works as soon as you enable it.

Next, add the `HasKeyring` trait to your `User` model, implement `MustVerifyEmail`, and keep Laravel's `hashed` cast on the `password` attribute. The interface is needed because registration leaves a new user signed out until they've verified their email address, so nobody can use the registration form to discover who has an account. The installer has already enabled email verification:

```php
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Keyring\Concerns\HasKeyring;

class User extends Authenticatable implements MustVerifyEmail
{
    use HasKeyring;
}
```

If the trait is missing, signing in will throw a `Keyring\Exceptions\MissingTrait` exception naming the model, rather than quietly working without the protection the trait adds.

A new user can't sign in until they've followed the verification link, so make sure your application can send mail. In a new Laravel application, the default `log` mailer writes each email, link included, to `storage/logs/laravel.log`.

## Your Pages

Keyring is headless, meaning it handles the requests while you build the pages. When using Inertia, Keyring renders `auth/{page}` components. Otherwise, it renders Blade views named `auth.{page}`. For a frontend that Laravel doesn't serve, such as a Nuxt app, see [Headless Frontends](headless.md).

If a view is missing, Keyring throws an error that names the file you need to create and the data it receives. The same is true of a missing Inertia component when Inertia's `pages.ensure_pages_exist` option is enabled.

Keyring renders ten pages, though you only need the ones for the features you've enabled:

| Page | When It's Needed |
|---|---|
| `login` | Always. |
| `challenge` | When you add a second sign-in method. This page asks for the user's next factor. |
| `confirm` | When you use step-up, which changing the password and adding sign-in methods both do. A user who signed in more than 15 minutes ago confirms it's them first. This is the challenge page for confirming, so it may render the same component. |
| `register` | With `Features::registration()`. It posts `name`, `email`, `password`, and `password_confirmation` to `/register`. The response sends the user to your `login` page with a status asking them to check their inbox. See [Registration](sign-in-flow.md#registration). |
| `forgot-password`, `reset-password` | With `Features::resetPasswords()`. |
| `verify-email` | With `Features::emailVerification()`, for a signed in user who hasn't verified their address yet. It asks them to click the link they were sent, with a button to send another. With the default registration flow, nobody is signed in before verifying, so you only need this page if you set `registration.reveal_taken`. |
| `email-verification` | With `Features::emailVerification()`. The emailed verification link lands here for a signed in user, on a page with a single button. With the default registration flow, the link sends a new user to sign in instead, and signing in verifies their address, so this page is also only needed with `registration.reveal_taken`. |
| `email-change` | With `Features::emailChanges()`. The emailed confirm and undo links land here, on a page with a single button. |
| `device-report` | With `Features::devices()`. The "this wasn't me" link lands here, on a page with a single button. |

A login page posts `email`, `password`, and an optional `remember` field to `/login`:

```blade
{{-- resources/views/auth/login.blade.php --}}
<form method="POST" action="{{ route('login.store') }}">
    @csrf
    <input name="email" type="email" value="{{ old('email') }}" autocomplete="username" required>
    <input name="password" type="password" autocomplete="current-password" required>
    @if ($status) <p>{{ $status }}</p> @endif
    @error('email') <p>{{ $message }}</p> @enderror
    <button>Sign in</button>
</form>
```

Once signed in, users are sent to the `home` path in your `config/keyring.php` configuration file, which is `/dashboard` by default. A new Laravel application doesn't have a `/dashboard` route, so you should either add one or point `home` somewhere that exists.

Every page and the data it receives is listed in the [Pages](sign-in-flow.md#pages) documentation, and the [example application](https://github.com/keyringphp/example) includes all of them in React.

## Your Settings Page

The page where users manage their sign-in methods belongs to your application too, and may live at whatever URL you like. Keyring doesn't register a route that renders it. Instead, your controller reads what to show, and the page calls Keyring's routes to make changes:

```php
use Illuminate\Http\Request;
use Inertia\Inertia;
use Keyring\Contracts\Enrollable;
use Keyring\Contracts\Factor;
use Keyring\Devices\DeviceManager;
use Keyring\Facades\Keyring;
use Keyring\Models\Authenticator;

class SecurityController
{
    public function edit(Request $request, DeviceManager $devices)
    {
        $user = $request->user();

        return Inertia::render('settings/security', [
            'authenticators' => $user->keyring->all()
                ->reject(fn (Authenticator $authenticator) => $authenticator->isVirtual())
                ->map(fn (Authenticator $authenticator) => [
                    ...$authenticator->factor()->present($authenticator),
                    'isDefault' => $authenticator->is_default,
                ])
                ->values(),
            'enrollable' => Keyring::registered()
                ->filter(fn (Factor $factor) => $factor instanceof Enrollable)
                ->keys(),
            'devices' => $devices->list($request, $user),
            'activity' => Keyring::activity($user, 15)->map(fn ($event) => [
                'type' => $event->type,
                'factor' => $event->factor,
                'ip' => $event->ip,
                'at' => $event->created_at->toIso8601String(),
            ]),
        ]);
    }
}
```

| Prop | Contents |
|---|---|
| `authenticators` | The sign-in methods the user has set up. The `present` method gives each one's `factor`, `id`, `name`, `createdAt`, and `lastUsedAt` (as ISO 8601 dates), along with a masked `hint` for email codes, and `remaining` and `replace` for recovery codes. The password is a virtual authenticator with no database row of its own, so it's left out. |
| `enrollable` | The keys of the factors a user may add, such as `totp` and `passkey`, for your "add" buttons. This includes `recovery`, which only works once the user has another second factor, so you should present it as "generate recovery codes" next to those rather than as a way to sign in. It includes `sso` when [single sign-on](sso.md#linking-and-unlinking) is registered, which you offer as a "link" button for each provider. |
| `devices` | Where the user is signed in, when `Features::devices()` is enabled. This is the same list returned by [`GET /user/devices`](devices-and-sessions.md#listing-and-revoking-devices). |
| `activity` | Recent [security log](security-log-and-emails.md#showing-recent-activity) entries, when `Features::securityLog()` is enabled. |

From there, the page uses Keyring's routes: [`/user/authenticators`](authenticators.md#routes) to add, rename, and remove sign-in methods, [`/user/devices`](devices-and-sessions.md#routes) to sign devices out, [`/user/sessions`](devices-and-sessions.md#listing-and-ending-sessions) to list sessions and end one, [`PUT /user/password`](protected-changes.md#changing-the-password), and [`POST /user/email`](protected-changes.md#changing-the-email-address). The [browser package](frontend.md#managing-authenticators) wraps the authenticator routes for you, including the passkey ceremony.

The routes that change something require a [fresh verification](step-up.md#fresh-verification), which lasts 15 minutes by default. The two that only list sessions and devices don't. You should place the same middleware on your settings page, after `auth`, so users confirm once when they open the page rather than halfway through adding a passkey:

```php
Route::get('/settings/security', [SecurityController::class, 'edit'])
    ->middleware(['auth', 'verified', 'keyring.fresh:15m']);
```

Signing in counts as a verification, so the page opens without asking right after a user signs in. If a user leaves the page open for longer than that, their next JSON request will receive a `423` response containing a `redirect` to the confirm page:

1. Catch the `423` response and send the browser to `redirect`.
2. The user confirms it's them on your `confirm` page.
3. Keyring sends them back to the page they were on, and they try again.

The [Handling Step-Up in JavaScript](frontend.md#handling-step-up-in-javascript) documentation contains the code for the first step.

## Testing

Keyring ships with an `InteractsWithKeyring` trait for your base test case. It provides the `withAssurance`, `verifiedWith`, `freshAt`, `totpCode`, and `sessionErrors` methods, and skips the timing delay on failed checks:

```php
use Keyring\Testing\InteractsWithKeyring;

abstract class TestCase extends BaseTestCase
{
    use InteractsWithKeyring;
}
```

You may also add `KeyringConformance` to a test class to verify that your setup keeps Keyring's guarantees. For more information, see the [Testing](testing.md) documentation.

## Adding Features

Features are enabled in your `config/keyring.php` configuration file. Each feature only registers its routes, and anything else it needs, once it's in the list. This is the list as the installer writes it:

```php
use Keyring\Features;

'features' => [
    Features::registration(),
    Features::resetPasswords(),
    Features::emailVerification(),
    Features::updatePasswords(),
    // Features::manageAuthenticators(),
    // Features::devices(),
    // Features::emailChanges(),
    Features::securityLog(),
    // Features::impersonation(),
],
```

| Feature | What It Adds | Documentation |
|---|---|---|
| `registration()` | `/register`, through your `CreateNewUser` action. Requires `emailVerification()` unless you set `registration.reveal_taken`. | [Registration](sign-in-flow.md#registration) |
| `resetPasswords()` | Forgot and reset password, through your `ResetUserPassword` action. | [Resetting the Password](protected-changes.md#resetting-the-password) |
| `emailVerification()` | Laravel's email verification routes, the `verify-email` page, and the `email-verification` page its link opens. | [Email Verification](protected-changes.md#email-verification) |
| `updatePasswords()` | `PUT /user/password`. Changing the password anywhere else will then throw an exception. | [Changing the Password](protected-changes.md#changing-the-password) |
| `manageAuthenticators()` | Adding, renaming, and removing sign-in methods. This is required for users to set any up. | [Managing Authenticators](authenticators.md) |
| `devices()` | A device cookie, "trust this device", a list of where users are signed in, and "this wasn't me" links. | [Devices & Sessions](devices-and-sessions.md) |
| `emailChanges()` | Email changes that are confirmed by the new address and may be undone from the old one. Changing the email anywhere else will then throw an exception. | [Protected Changes](protected-changes.md#changing-the-email-address) |
| `securityLog()` | A log of sign ins, failures, refusals, and changes in the `keyring_events` table, along with "was this you?" alerts. It's enabled unless you remove it, in which case the events are written to your application's log instead. | [Security Log & Emails](security-log-and-emails.md) |
| `impersonation()` | `POST /impersonate/{user}` and `/impersonate` to stop, for signing in as another user and coming back. Nobody may until you register `Keyring::allowImpersonationWhen()`. | [Impersonation](impersonation.md) |

A few more things live outside the features list:

- **[Security emails](security-log-and-emails.md#security-emails):** Keyring sends its own from the start, each one once its feature is enabled. You may call `Keyring::notifications([...])` in your `KeyringServiceProvider` to replace one with your own class or turn it off.
- **[Risk signals](risk.md):** These are listed in `Keyring::risk()->signals([...])` in your `KeyringServiceProvider`, where `keyring:install` wrote a starting set. When you enable devices, you should also uncomment `NewDevice` and `InactiveAccount`.
- **A [support contact](security-log-and-emails.md#a-support-contact):** The `support_contact` option in `config/keyring.php` sets who those emails tell users to contact.
- **[Requiring a second factor](policies.md#requiring-a-second-factor):** The `keyring.enrolled` middleware, with `enrollment_url` set to your page for adding one. The `keyring:install` command sets up both when you choose to require one. Step-up also sends users to this page when they don't have what a route needs.

## Adding Sign-In Methods

Every sign-in method lives in your `app/Providers/KeyringServiceProvider.php` file, and the ones you didn't pick during installation are commented out. Uncomment the ones you would like, along with recovery codes:

```php
use Keyring\Facades\Keyring;
use Keyring\Factors;
use Keyring\Login\Requirement;

Keyring::factors([
    Factors\Password::class,
    Factors\Totp::class,
    Factors\RecoveryCodes::class,
    Factors\WebAuthn::passkeys(),
    // Factors\WebAuthn::securityKeys(),
    // Factors\EmailCode::asExtraStep(),
]);

Keyring::require(Requirement::aal2()->ifEnrolled()->noDowngrade());
```

AAL stands for authenticator assurance level, NIST's scale for how strongly a session has been proved. AAL1 is a single factor, such as a password. AAL2 adds something the user has, such as an authenticator app, or comes from a passkey on its own. See [Assurance Levels](policies.md#assurance-levels).

Next:

1. Enable `Features::manageAuthenticators()` in your `config/keyring.php` file so users can set them up.
2. Build the `challenge` and `confirm` pages, and the part of [your settings page](#your-settings-page) that adds and removes sign-in methods.
3. If everyone should set one up, uncomment the `keyring.enrolled` line below them and set `enrollment_url` to that page. See [Requiring a Second Factor](policies.md#requiring-a-second-factor).

To let users sign in with Google, Microsoft, GitHub, or another identity provider, add `Factors\SingleSignOn::class` to the list and configure the providers. See [Single Sign-On](sso.md).

The `Requirement::aal2()->ifEnrolled()` policy asks for a second factor once a user has set one up. Adding `noDowngrade()` ensures a user with a passkey can't be talked into using something weaker, once they've had it for [7 days](authenticators.md#established-authenticators). To learn more, see the [Factors](factors.md) and [Policies](policies.md) documentation.

## What Keyring Does Without Being Asked

The following protections are part of the foundation. You don't need to set any of them up, but you're free to change them:

| Protection | Default | How to Change It |
|---|---|---|
| Rate limits on signing in | 5 a minute per account and 20 per IP address. After 100 failures in a row, an authenticator is refused until a password reset or `Keyring::unlock()` clears it, or until the second factor is removed and added again. | `limits` in [Configuration](configuration.md#pending-logins-timebox-and-rate-limits) |
| Failed checks take the same amount of time, as does every registration and refused password reset | 500ms | `timebox` |
| Registration gives the same response whether or not an address has an account | Enabled | [`registration.reveal_taken`](sign-in-flow.md#registration) |
| Password rules | 15 characters without a second factor, and 8 with one. Common passwords are refused, and so are ones made up only of the user's name or email, or the app's name or its `passwords.context` words, with digits and punctuation ignored. Breached passwords are refused in production, as well. | [Password Rules](protected-changes.md#password-rules) |
| A record of each session, with its IP address and browser, so Keyring can sign it out | Sessions end after two hours unused, and 30 days after signing in. "Remember me" brings a browser back for up to 14 days away, with nothing proved, and only to a session that hasn't ended. | `sessions` in [Configuration](configuration.md#sessions) |
| Assurance levels lapse, as NIST recommends | AAL2 after an hour idle or 24 hours, and AAL3 after 15 minutes idle or 12 hours. The session stays signed in at whatever level remains, unless `sessions.end_on_lapse` ends it. | `sessions.levels` |
| Browsers are told to clear their cache and storage on sign out | Enabled | A custom [`LogoutResponse`](sign-in-flow.md#responses) |
| Step-up middleware | `keyring:aal2` and `keyring.fresh:15m`, for your own routes | [Step-Up](step-up.md) |
