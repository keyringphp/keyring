# Configuration

- [Introduction](#introduction)
- [Durations](#durations)
- [Guard and Users](#guard-and-users)
- [Features](#features)
- [Registration](#registration)
- [Redirects](#redirects)
- [Routes](#routes)
- [Pages](#pages)
- [WebAuthn](#webauthn)
- [Single Sign-On](#single-sign-on)
- [Account Changes and Enrollment](#account-changes-and-enrollment)
- [Devices](#devices)
- [Sessions](#sessions)
- [Impersonation](#impersonation)
- [Protected Attributes and Email Changes](#protected-attributes-and-email-changes)
- [Passwords](#passwords)
- [Risk](#risk)
- [Security Log](#security-log)
- [Pending Logins, Timebox and Rate Limits](#pending-logins-timebox-and-rate-limits)
- [Messages and Translations](#messages-and-translations)
- [The Keyring Facade](#the-keyring-facade)

## Introduction

You configure Keyring in two places:

- Your `config/keyring.php` configuration file holds values: your features, timeouts, limits, and route options.
- Your `app/Providers/KeyringServiceProvider.php` file holds behaviour: which factors exist, the policy, risk responses, swapped responses, and pages. You put these calls in the provider's `boot()` method.

The `keyring:install` command publishes a short config file with the options most applications change: `guard`, `username`, `home`, `features`, `registration`, `enrollment_url`, and `support_contact`. Every other option on this page keeps its default until you copy it into that file. Keyring merges your file over its defaults key by key, so you only need to copy the part you change, such as `'sessions' => ['absolute' => '7d']`. Lists, like `features`, are replaced as a whole. If you'd rather have the full file, run `php artisan vendor:publish --tag=keyring-config`.

## Durations

Options that take a duration accept a number of seconds, or a string such as `"30s"`, `"15m"`, `"12h"`, or `"7d"`. Any other value throws an `InvalidArgumentException`. The two short ones, `timebox` and `webauthn.timeout`, also accept milliseconds, such as `"250ms"`. Those two always need a unit, so a bare number throws.

## Guard and Users

```php
'guard' => 'web',

'username' => 'email',

'email' => 'email',
```

`guard` is the stateful guard that users sign in with. Keyring stores pending logins, step-up state, and enrollments in the session, so it needs a guard that uses sessions.

`username` is the user attribute that users type at login. It's also the field name the login form posts. Keyring lowercases what users type before it looks them up, so store this attribute in lowercase.

`email` is the attribute that holds the user's address. The [email change flow](protected-changes.md#changing-the-email-address) changes and protects this attribute. It's also the field the password reset forms post, and it's where an email code's hint comes from. Leave it as it is unless your users sign in with something else, such as a handle. In that case, set `username` to that attribute, and keep `email` pointing at the address.

## Features

```php
use Keyring\Features;

'features' => [
    Features::registration(),
    Features::resetPasswords(),
    Features::emailVerification(),
    Features::updatePasswords(),
    Features::securityLog(),
    // Features::manageAuthenticators(),
    // Features::devices(),
    // Features::emailChanges(),
    // Features::impersonation(),
],
```

Signing in and out, challenges, and step-up are always on. Everything else is a feature. Each feature adds its routes, and anything else it needs, only once it's in this list. An unknown feature in `config/keyring.php` stops the application from booting, rather than quietly leaving that feature off. Without a config file, Keyring turns on registration, password resets, email verification, password changes, and the security log. Those are also the defaults `keyring:install` picks, unless you choose otherwise. Your list replaces that default list as a whole, so keep `Features::securityLog()` in it, unless you'd rather have those events in [your application's log](security-log-and-emails.md#without-the-table). For a description of what each feature adds, see [Adding Features](quick-start.md#adding-features).

You may check for a feature in your own code with `Features::enabled(Features::devices())`. The `Features::all` method lists all of them, which is handy in tests.

## Registration

```php
'registration' => [
    'reveal_taken' => false,
],
```

By default, registering gives the same answer whether or not the address already has an account. New users sign in once they've followed the link emailed to them. An address that already has an account is emailed to say that someone tried to register with it. This needs `Features::emailVerification()` and a `MustVerifyEmail` user model. The app doesn't boot with registration on and email verification off.

If you set `reveal_taken` to `true`, the form answers "has already been taken" and signs new users in straight away. That lets anyone check whether an address has an account. The [Registration](sign-in-flow.md#registration) section explains exactly what each choice reveals.

## Redirects

```php
'home' => '/dashboard',
```

`home` is where users go after they sign in or confirm, when there's no intended URL. Keyring also uses it after email verification, with `?verified=1` added, and after confirming an email change while signed in. It may be a full URL, such as a page on a [frontend of your own](headless.md#where-each-answer-goes).

Users who are signed out are sent to the route named `login`.

## Routes

```php
'routes' => true,

'prefix' => '',

'domain' => null,

'middleware' => ['web', AddSecurityHeaders::class],
```

Keyring registers its routes inside a group that uses this prefix, domain, and middleware. The `Keyring\Http\Middleware\AddSecurityHeaders` middleware sends `Cache-Control: no-store, private`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy: same-origin-allow-popups`, and `Referrer-Policy: same-origin` on every Keyring response. It sends `Referrer-Policy: no-referrer` on the pages that emailed links open. It leaves `X-Frame-Options` off a response that already says who may frame it, either with a header of its own or with a `frame-ancestors` directive. That means a middleware listed after it here can allow framing. See [Links and Headers](security.md#links-and-headers). If your application sets those headers itself, you may take this middleware out of the list. In that case, you still need to keep the URLs of emailed links out of `Referer` headers some other way, because they carry their token.

If you set `routes` to `false`, Keyring registers nothing. Instead, you call `Keyring::routes()` wherever you want them. For example, you may call it inside your own group:

```php
Route::prefix('account')->middleware('throttle:60,1')->group(fn () => Keyring::routes());
```

The `Keyring::routes` method adds the `middleware` option, but it doesn't add `prefix` or `domain`. Your group decides those. To change the routes themselves, copy `vendor/keyring/keyring/routes/keyring.php` into your application instead, and keep the route names. Keyring's controllers, emails, and middleware link to routes by name, such as `login`, `keyring.confirm.challenge`, and `keyring.devices.report`.

The browser package uses Keyring's default paths. If you change the prefix, tell the package with [`configureRoutes({ prefix })`](frontend.md#changing-routes).

## Pages

```php
'pages' => true,
```

Keyring renders its [pages](sign-in-flow.md#pages) as Inertia components or Blade views, and answers a JSON request for one with the page's name and props. Set `pages` to `false` when every page lives in a frontend that Laravel doesn't serve, such as a Nuxt app. Keyring then answers anything but a JSON request for a page with a `404`, and never throws a `MissingPage` exception. A page you render with a closure through `Keyring::page` still renders. See [Headless Frontends](headless.md).

## WebAuthn

```php
'webauthn' => [
    'relying_party' => [
        'id' => env('KEYRING_WEBAUTHN_RP_ID'),
    ],
    'origins' => [],
    'timeout' => '60s',
    'login_options_for' => '5m',
    'attestation_roots' => [],
    'algorithms' => ['ES256', 'EdDSA'],
    'minimum_rsa_bits' => 2048,
],
```

For more, see [Passkeys & Security Keys](passkeys.md#relying-party-and-origins). The `timeout` and `login_options_for` options are [durations](#durations). `login_options_for` sets how long the challenge of a [usernameless sign in](passkeys.md#signing-in-without-a-username) can be answered. It's never shorter than `timeout`.

The `attestation_roots` option lists the root certificates that a new key's attestation has to chain to. You may give them as PEM text or as paths to PEM files. Keyring only reads this list for a factor set up with [`requireAttestation()`](passkeys.md#requiring-attestation). That setup refuses every key while the list is empty.

The `algorithms` option lists the signature algorithms that keys may use, in order of preference: `ES256`, `EdDSA`, and `RS256`. `RS256` is off by default. When you turn it on, `minimum_rsa_bits` sets the shortest RSA key that Keyring accepts, which is never under 2048. See [Signature Algorithms](passkeys.md#signature-algorithms) for what turning it on gains you and what it costs.

## Single Sign-On

```php
'sso' => [
    'providers' => [],
    'request_for' => '10m',
    'cache_for' => '1h',
    'store' => null,
],
```

`providers` lists the identity providers users can sign in with, by name, once the `SingleSignOn` factor is registered. Keyring only registers its `/auth/{provider}` routes when this lists a provider as the app boots. Each one has a `driver` (`oidc`, `google`, `microsoft`, `github`, or one of your own), a `client_id`, and usually a `client_secret`. Its `freshness` (`reauthenticate`, `round_trip`, or `never`) says how much its sign ins and confirms count toward a [fresh verification](step-up.md#fresh-verification). It's `reauthenticate` for `oidc` and `microsoft` and `never` for `google` and `github`, see [Freshness](sso.md#freshness). `request_for` is how long a user sent to a provider has to come back. Providers' discovery documents and signing keys are cached in `store` (`null` for your default store) for `cache_for`. Both are [durations](#durations). See [Single Sign-On](sso.md#configuration) for every provider option.

## Account Changes and Enrollment

```php
'changes_middleware' => ['keyring.fresh:15m'],
```

This is extra middleware for adding, renaming, and removing authenticators, ending sessions, revoking devices, changing the password, and starting an email change. It's applied on top of `auth:{guard}`, which every signed-in Keyring route already has, so don't add `auth` here. By default, these routes need a verification from the last 15 minutes, as [Step-Up](step-up.md#fresh-verification) explains. Whatever this says, they also refuse a browser that's [impersonating](impersonation.md#whats-refused-while-impersonating) the user.

```php
'authenticator_changes' => [
    'established_after' => '7d',
    'skip_with_totp' => false,
],
```

The `established_after` option sets how long the account must have had an authenticator, or a set of recovery codes, before it's [established](authenticators.md#established-authenticators). Until then, a new passkey or security key doesn't make `noDowngrade()` ask for one. It also sets how long the account's sign-in methods stay [frozen](authenticators.md#frozen-sign-in-methods) after one is added, or after an established one or an established set of recovery codes is removed or replaced, and how long a second factor added to an account takes [the password](authenticators.md#the-password-for-a-first-second-factor) while the account has no older one. Setting it to `0` turns the first two off, so a stolen session that has just signed in could shut the owner out again. The password is then only asked for while the account has no second factor at all. It's separate from `email_changes.established_after`.

While the account is frozen, the owner can still make one change by proving, in the same request, a passkey or security key (or a phishing-resistant factor of your own) the account has had for `established_after` and since before the session signed in. See [Making a Change With an Established Key](authenticators.md#making-a-change-with-an-established-key). Set `skip_with_totp` to `true` to let an established authenticator app do it too. It's off because a six digit code can be phished as it's typed, and then the person phishing it could make the change.

```php
'enrollment_url' => null,
```

This is where the `keyring.enrolled` middleware sends users who still need a second factor. If the value is `null`, the middleware answers with a `403` instead. The `keyring:install` command sets it to `/settings/security` when you choose to require a second factor for everyone. See [Requiring a Second Factor](policies.md#requiring-a-second-factor).

```php
'enrollment_except' => [],
```

You may list more routes that those users can still reach in the meantime, by route name. Use `*` as a wildcard, such as `['billing.*', 'support']`. The enrollment page, Keyring's own routes, signing out, email verification, and changing the password are always let through.

```php
'authenticators_url' => null,
```

This is your page where users see and remove their sign-in methods. The `authenticator_added` and `recovery_codes_generated` emails link to it, so an owner can remove a method they didn't add. A path is put after `APP_URL`, or the root from `Keyring::linkRootUsing()`, never the request's host. A full URL is used as it is. If the value is `null`, the emails have no link. See [Email Types](security-log-and-emails.md#email-types).

```php
'password_change_url' => null,
```

This is where a user who must choose a new password is sent from every other page, until they've done so. If the value is `null`, Keyring answers with a `403`. See [Requiring a Password Change](protected-changes.md#requiring-a-password-change).

```php
'support_contact' => null,
```

This is where users can reach you about their account. Give a page's URL, such as `'https://example.com/support'`, or an email address, such as `'support@example.com'`. Every notification receives it as `$contact`. Keyring's security notices, the emailed code, and the email change notice end with "If this wasn't you and you need help, contact us" and a link to it. If you set it to `null`, that line is left out. See [Security Emails](security-log-and-emails.md#a-support-contact).

```php
'enrollments' => [
    'keep_for' => '15m',
],
```

This is how long a user has to finish adding a sign-in method, once they've started. See [Adding an Authenticator](authenticators.md#adding-an-authenticator).

## Devices

```php
'devices' => [
    'cookie' => null,
    'cookie_lifetime' => '400d',
    'limit' => 50,
    'trust_for' => '30d',
    'report_link_for' => '7d',
    'keep_revoked_for' => '30d',
    'keep_unseen_for' => '365d',
    'locator' => NullLocator::class,
],
```

The `cookie` option sets the name of the device cookie. When it's `null`, the name is `known_device`, with a prefix once your application is served over HTTPS: `__Host-`, or `__Secure-` when `session.domain` is set or `session.path` isn't `/` (see [Keyring's Cookies](devices-and-sessions.md#keyrings-cookies)). A name you set is used exactly as it is. The `cookie_lifetime` option sets how long the browser keeps the cookie. 400 days is the most browsers allow.

The `limit` option sets how many devices one account keeps. If a sign in from a new browser goes past that limit, the device seen longest ago is forgotten and signed out. Set it to `null` for no limit.

The `trust_for` option sets how long "don't ask again on this device" lasts. Set it to `null` to hide that option. The `report_link_for` option sets how long a ["this wasn't me" link](devices-and-sessions.md#the-this-wasnt-me-link) works.

The [`keyring:prune`](devices-and-sessions.md#pruning) command deletes a device `keep_revoked_for` after it was revoked, or `keep_unseen_for` after it was last seen.

The `locator` option is the class that works out a request's location. See [Devices & Sessions](devices-and-sessions.md) for more.

## Sessions

```php
'sessions' => [
    'driver' => env('KEYRING_SESSION_DRIVER', 'database'),
    'connection' => null,
    'table' => 'keyring_sessions',
    'store' => null,
    'max' => 100,
    'idle' => '2h',
    'remember_idle' => '14d',
    'absolute' => '30d',
    'levels' => [
        'aal2' => ['idle' => '1h', 'absolute' => '24h'],
        'aal3' => ['idle' => '15m', 'absolute' => '12h'],
    ],
    'end_on_lapse' => false,
    'middleware' => true,
    'remember_cookie' => null,
    'remember_grace' => '10s',
    'continue_as_guest' => [],
    'sweep_every' => null,
    'sweep_limit' => 1000,
],
```

| Key | Meaning |
|---|---|
| `driver` | `database`, `cache`, or the name of a driver you've added. |
| `connection`, `table` | Used by the `database` driver. |
| `store` | The cache store that the `cache` driver uses. `null` means your default store. Pick one that keeps its keys until they expire. A store that evicts keys under memory pressure can drop a user's list of sessions, and a sign-out everywhere then misses the sessions it listed. The `database` driver has no such store to depend on. |
| `max` | How many sessions one account can have at once. When a sign in goes past that number, the session that has gone unused the longest ends. Use `null` for no limit. See [How Many Sessions](devices-and-sessions.md#how-many-sessions). |
| `idle` | How long a session may sit inactive before it ends. `null` leaves that to Laravel's session lifetime. |
| `remember_idle` | The same setting, for a browser that ticked "remember me". It's how long the browser may stay away and still be signed back in, with nothing proved. `null` lets it stay away for the whole `absolute` limit. See [Inactivity and "Remember Me"](devices-and-sessions.md#inactivity-and-remember-me). |
| `absolute` | The longest a session can last, however active it is. |
| `levels` | How long each assurance level keeps counting, as `idle` and `absolute` limits. The keys are `aal1`, `aal2`, or `aal3`. By default, these follow NIST's limits: AAL2 is 1h and 24h, and AAL3 is 15m and 12h. |
| `end_on_lapse` | Whether a session ends when the level it signed in at runs out. Otherwise, the session carries on at a lower level. See [Ending a Session With Its Level](devices-and-sessions.md#ending-a-session-with-its-level). |
| `middleware` | Whether Keyring adds its session middleware to the `web` group for you. |
| `remember_cookie` | The name of the cookie that ties ["remember me"](devices-and-sessions.md#remember-me) to the session it was ticked for. `null` is `remembered_session`, prefixed over HTTPS like the device cookie, with `__Secure-` when `session.domain` is set or `session.path` isn't `/`. See [Keyring's Cookies](devices-and-sessions.md#keyrings-cookies). |
| `remember_grace` | How long after that cookie is used the browser's other requests, sent with it, still get in on the same session. Each cookie works once. After this grace period, [sending a used one again](devices-and-sessions.md#a-cookie-used-twice) ends the session. A `0` leaves no room at all, so requests that a browser sends together end the session too. |
| `continue_as_guest` | Route names, as `Request::routeIs()` takes them, where a page visit whose session has ended is asked for again as a guest instead of being sent to log in. The `signed-out` status is flashed for the page to show. JSON requests still get a `401`. A list with an entry that isn't a non-empty string is ignored. See [Pages That Also Serve Guests](devices-and-sessions.md#pages-that-also-serve-guests). |
| `sweep_every` | How often Keyring schedules [`keyring:sweep`](devices-and-sessions.md#sweeping-ended-sessions), such as `'5m'` or `'1h'`, on the `database` driver. It ends sessions that timed out with no request to end them, and announces again any ended session whose event was lost. A bare number counts seconds. It runs at least every 12 hours. `null` (the default) leaves the sweep off, and anything that isn't a duration does too, with a warning in your log. |
| `sweep_limit` | The most sessions one run of the sweep announces again, and the most it ends, each. Anything that isn't a positive number is taken as `1000`, and it's at most `10000`. |

See [Devices & Sessions](devices-and-sessions.md#the-session-registry).

## Impersonation

```php
'impersonation' => [
    'lifetime' => '1h',
    'show_in_sessions' => true,
    'show_in_activity' => true,
    'middleware' => ['keyring:aal2', 'keyring.fresh:15m'],
    'redirect_url' => null,
    'return_url' => null,
],
```

These only matter with `Features::impersonation()` on, and once [`Keyring::allowImpersonationWhen()`](impersonation.md#who-may-impersonate-whom) says who may.

| Key | Meaning |
|---|---|
| `lifetime` | How long an impersonation lasts before it ends by itself and goes back to the impersonator. It's never longer than `sessions.absolute`. `null` is an hour. With the feature on, one that isn't a duration, or is `0`, throws an `InvalidArgumentException` naming the option when the app boots. See [The Time Limit](impersonation.md#the-time-limit). |
| `show_in_sessions` | Whether the impersonated session is in the user's own [sessions list](impersonation.md#the-sessions-list), marked with who is in it, for the user to end. With `false` it's left out, except from the list the impersonated session itself asks for, but still ends with the rest of their sessions, and still counts in how many "sign out everywhere else" says it ended. |
| `show_in_activity` | Whether `impersonation_started` and `impersonation_ended` are in [`Keyring::activity`](security-log-and-emails.md#showing-recent-activity), on both accounts. With `false` they're in `Keyring::unlistedActivityTypes()`, so it leaves them out, but they're still written. This is the only way to leave out any of Keyring's own types: listed in `security_log.unlisted`, they're still shown. It doesn't keep an impersonation secret either: what was done while impersonating, such as signing out, is still in the user's activity. See [The Security Log and Events](impersonation.md#security-log-and-events). |
| `middleware` | What starting one takes, on top of being signed in and not impersonating already. By default, two factors proved in the last 15 minutes. An empty list asks for nothing more: any signed-in session the callback allows can start one, with no step-up. |
| `redirect_url` | Where starting goes. `null` is `home`. |
| `return_url` | Where stopping, or running out, goes. `null` is `home`. |

See [Impersonation](impersonation.md).

## Protected Attributes and Email Changes

```php
'protected' => [],

'email_changes' => [
    'confirmable_for' => '24h',
    'revertable_for' => '7d',
    'established_after' => '7d',
    'sign_out_others' => true,
    'keep_ended_for' => '30d',
],
```

The `confirmable_for` option sets how long the emailed confirmation link works. The `revertable_for` option sets how long the old address can undo the change afterwards. The `established_after` option sets how long the account must have had a second factor before proving it lets a change skip the old address's confirmation. It also sets how far back undoing a change removes sign-in methods. See [Confirming](protected-changes.md#confirming). It's separate from [`authenticator_changes.established_after`](#account-changes-and-enrollment), which decides when a new sign-in method counts for policies and can freeze the rest. When an email change applies, `sign_out_others` ends the account's other sessions. The `keep_ended_for` option sets how long a finished change is kept before `keyring:prune` deletes it.

The `Features::updatePasswords()` feature adds `password` to the protected attributes, and `Features::emailChanges()` adds the [`email` attribute](#guard-and-users). You may list any others in `protected`. See [Protected Changes](protected-changes.md).

## Passwords

```php
'passwords' => [
    'min_with_mfa' => 8,
    'min_without_mfa' => 15,
    'max' => 128,
    'uncompromised' => null,
    'refuse_unchecked' => false,
    'context' => [],
    'broker' => null,
],
```

For more, see [Password Rules](protected-changes.md#password-rules). The `broker` option sets the password broker used for resets. `null` means your default broker.

The `min_with_mfa` and `min_without_mfa` options are counted in characters. Neither can be set below 8, which is the shortest password that OWASP ASVS 5.0.0 (6.2.1) and NIST SP 800-63B-4 (Sec. 3.1.1.2) allow. If you set a lower value, Keyring throws a `LogicException` as the application boots, and again wherever the option is read. It won't quietly use 8 instead.

The `max` option is counted in characters, but how much of that you get depends on the hasher. Bcrypt, Laravel's default, only reads the first 72 bytes of a password. So with bcrypt, Keyring refuses anything longer, rather than ignoring the end of it. That makes the real limit 72 bytes, not 128 characters. In practice, that's 72 plain characters, but only 36 accented or Cyrillic ones, 24 Chinese, Japanese, or Korean ones, or 18 emoji. OWASP ASVS 5.0.0 (6.2.9) asks that passwords of at least 64 characters are allowed, which bcrypt can't promise. To accept every password up to `max`, use argon2id to hash passwords:

```ini
HASH_DRIVER=argon2id
# While some users still have bcrypt hashes. They're rehashed as they sign in.
HASH_VERIFY=false
```

Keyring doesn't hash a password before bcrypt to get around the limit. Those hashes would no longer be ones that Laravel's own hasher can check. The [conformance suite](testing.md#the-conformance-suite) fails on bcrypt until you switch hashers, or say that you're keeping bcrypt.

The `context` option is your list of words that a password mustn't be made up of. Include the names of your organisation, products, systems, projects, departments, and roles. It's the documented list that OWASP ASVS 5.0.0 (6.1.2) asks for. Keyring always adds your application's name and what it knows about the user, too. See [Context-Specific Words](protected-changes.md#context-specific-words) for how the words are compared.

The `uncompromised` option checks new passwords against Have I Been Pwned over the network. The default, `null`, runs the check only when the application is in production. That way, local development and tests make no network calls. Set it to `true` or `false` to choose for every environment.

The check is Laravel's own (`Password::uncompromised()`). It fails open. When Have I Been Pwned can't be reached, times out, or answers with an error, Laravel reports the exception and lets the password through. On those requests, only the [bundled list](protected-changes.md#password-rules) of common passwords stands between a user and a breached password.

If you would rather refuse those passwords, set `refuse_unchecked` to `true`. Keyring then makes the request itself, in the same way. Only the first five characters of the password's SHA-1 leave your server. A password that gets no answer is refused with `keyring::keyring.password_unchecked`, which asks the user to try again in a moment. The cost is that nobody can register, change a password, or reset one while the service is unreachable from your servers. This only applies where `uncompromised` runs. Keyring waits up to 10 seconds for an answer. It asks `api.pwnedpasswords.com` and nowhere else. A redirect isn't followed, and it counts as no answer.

Laravel's check goes through whatever `Illuminate\Contracts\Validation\UncompromisedVerifier` is bound in the container. That means you may bind one of your own, for example to check a copy of the breach data that you host yourself. `refuse_unchecked` doesn't use that binding, since a verifier can only answer yes or no. If you use your own verifier, leave the option off, and have the verifier answer `false` when it can't check.

## Risk

```php
'risk' => [
    'levels' => ['medium' => 30, 'high' => 60, 'critical' => 90],
    'recent_change' => '7d',
    'store' => null,
],
```

The `levels` option sets the score thresholds. The `recent_change` option sets how long after an email change the `RecentlyChangedRecovery` signal fires. The `store` option sets the cache store for risk locks. `null` means your default store. Use a database or Redis store, not Octane's `octane` store. See [Octane's Cache Store](security.md#octanes-cache-store). For more, see [Risk](risk.md).

## Security Log

```php
'security_log' => [
    'keep_for' => '180d',
    'channel' => env('KEYRING_LOG_CHANNEL'),
    'context_key' => 'trace_id',
    'refusals' => 20,
    'refusals_per' => '1h',
    'alerts' => ['second_factor_failed', 'device_reported', 'email_change_reverted', 'clone_suspected', 'remember_me_reused'],
    'unlisted' => [],
],

'prune_at' => '03:00',
```

The `keep_for` option sets how long entries are kept before the [`keyring:prune`](devices-and-sessions.md#pruning) command deletes them. The `alerts` option lists the entry types that are shown once, as ["was this you?" alerts](security-log-and-emails.md#was-this-you-alerts), at the next sign in. The `unlisted` option lists the entry types that `Keyring::activity` leaves out, for entries about a user that aren't something the user did. An entry that isn't a string is ignored, and so is one of Keyring's own entry types: to leave out the impersonation entries, set [`impersonation.show_in_activity`](#impersonation) to `false` instead. See [Showing Recent Activity](security-log-and-emails.md#showing-recent-activity).

The table is turned on by `Features::securityLog()`, which is on by default. Without it, the same events are written to the log `channel` instead. `null` means your default channel. Without the table, "was this you?" alerts and the `RepeatedFactorFailures`, `SuccessAfterFailures`, and `CredentialStuffing` risk signals don't work, since they read from the table. See [Without the Table](security-log-and-emails.md#without-the-table).

The `context_key` option is the key in Laravel's Context where your application keeps a request's ID, if it keeps one. Every entry that the request writes then carries that ID. If your application doesn't keep one, Keyring makes an ID of its own for each request. If you set it to `null`, the ID is left out. See [Request IDs](security-log-and-emails.md#request-ids).

The `refusals` option sets how many entries of one type are written about one account, or about one IP address when no account is known. It counts over each `refusals_per` period. This applies to things that were refused and can be asked for again without end. A `null` writes them all. See [Refusals That Repeat](security-log-and-emails.md#refusals-that-repeat).

The `prune_at` option is the time of day that Keyring schedules `keyring:prune` for. The command deletes everything that's past its time, not only log entries. If you set it to `null`, scheduling the command is up to you. See [Pruning](devices-and-sessions.md#pruning).

## Pending Logins, Timebox and Rate Limits

```php
'pending_logins' => [
    'keep_for' => '10m',
],

'timebox' => '500ms',

'limits' => [
    'per_account' => 5,
    'per_ip' => 20,
    'consecutive' => 100,
    'consecutive_elsewhere' => 80,
    'remember_names_for' => '30d',
    'longest_lock' => '24h',
    'longest_ip_lock' => '15m',
    'lock_after' => null,
    'codes' => 3,
    'codes_per' => '10m',
    'notices' => 5,
    'notices_per' => '1h',
],
```

The `pending_logins.keep_for` option sets how long a half-finished login or confirmation stays valid. It's a [duration](#durations). It's also the `expiresAt` value shown on the challenge page.

The `timebox` option sets the minimum time that a refused verification takes. That way, timing doesn't reveal whether an account exists, or whether a password that was refused for another reason was right. It covers every pipeline step. So a request refused by a rate limit or by validation waits too, and so do a registration and a refused password reset. Verifications that go through return straight away.

The timebox only hides work that's shorter than it. The slowest thing a refusal does is hash a password, and not every refusal hashes one at the same cost. An account's password is checked at the cost its stored hash was made with, which differs from today's cost while old hashes are being moved to a new one. A reset token is only checked for an address with a link outstanding. So keep `timebox` comfortably longer than one password hash takes on your servers. Bcrypt at 12 rounds takes around 200ms on current hardware, and more on a small instance. When a refusal takes longer than `timebox`, Keyring writes a warning to your application's log, at most once an hour. That warning is the check that sees your real hashing cost on your real servers. As an early guide, the [conformance suite](testing.md#the-conformance-suite) also times a hash where your tests run, and fails when the hash doesn't fit.

The `limits` option sets the default attempts per minute for each factor, per account and per IP address. It also has `consecutive`, which is the number of failures in a row that one of an account's authenticators allows before it's refused for that account. `null` means no cap, and 100 is the most that NIST SP 800-63B-4 allows (Sec. 3.2.2). Those failures are counted in the `keyring_failure_counts` table. Nothing brings a refused authenticator back by itself, as [At the Cap](security.md#at-the-cap) explains. The `consecutive_elsewhere` option sets how many of those failures may come from browsers that the account hasn't signed in from. The rest are kept for the owner's own sign-ins. It only applies with `Features::devices()` on, and `null` keeps nothing back. The `remember_names_for` option sets how long the cache keeps the failures in a row counted under each typed username. The sign-in form answers from those counts.

Keyring keeps the per-minute counts and their locks in the cache store that Laravel's rate limiter uses. That's `cache.limiter` in `config/cache.php`, or your default store. Point it at a database or Redis store. Octane's in-memory `octane` store fills up, isn't atomic across workers, and is emptied by a restart, as [Octane's Cache Store](security.md#octanes-cache-store) explains.

Each lockout lasts twice as long as the one before it, up to `longest_lock`. For a whole IP address, the limit is `longest_ip_lock`. Set `lock_after` to refuse an account as it would be at the cap, once it has been locked out of signing in that many times in a day. The account stays refused until its password is reset. See [Locking Until a Reset](security.md#locking-until-a-reset). An account can be sent `codes` codes for one factor every `codes_per` period. It can also receive `notices` security notices of one kind, or email change requests, every `notices_per` period. Registration also mails an address at that rate. See [Rate Limiting](security.md#rate-limiting).

Keyring's form routes use a named rate limiter called `keyring`. These routes include registration, password resets, enrollment confirmation, email changes, verification emails, and the buttons on the pages that emailed links open. The limiter allows 6 requests a minute per user, or per IP address for guests. To change it, define your own `keyring` limiter in the `boot()` method of a service provider:

```php
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Keyring\Support\TooManyAttempts;

RateLimiter::for('keyring', fn (Request $request) => Limit::perMinute(10)
    ->by($request->user()?->id ?: $request->ip())
    ->response(new TooManyAttempts('keyring')));
```

`GET /login/{factor}/options` uses its own limiter, `keyring-login-options`, which allows 60 requests a minute per IP address. Login pages fetch the options on every load for passkey autofill. When the limit is hit, autofill stops offering passkeys until the next minute. To change it, define the same limiter.

The pages that emailed links open (for confirming or undoing an email change, verifying an address, or reporting a device) only show a button. So they use a third limiter, `keyring-pages`, which allows 60 requests a minute per IP address. Pressing the button is held to the `keyring` limit. Opening both ends of an email change, or reloading a page, doesn't use up the attempts the buttons get. To change it, define the same limiter.

`TooManyAttempts` is the response that Keyring's own three limiters answer with. It sends Laravel's usual `429` after dispatching the `Keyring\Events\RateLimited` event, which the security log records as [`rate_limited`](security-log-and-emails.md#entry-types). Laravel has no event of its own for a refused request. So a limiter you define without that `response()` still limits requests, but it writes nothing to the log.

## Messages and Translations

Keyring's text lives in two translation files, under the `keyring::` namespace:

| File | What It Holds |
|---|---|
| `lang/en/keyring.php` | Validation and error messages, such as `keyring::keyring.invalid`. |
| `lang/en/status.php` | The message for each status slug, such as `keyring::status.password-updated`. See [Status Responses](sign-in-flow.md#status-responses). |

You may publish them to change the wording or to add languages. The wording of emails lives in [your notification classes](security-log-and-emails.md#security-emails) instead:

```bash
php artisan vendor:publish --tag=keyring-lang
```

## The Keyring Facade

The `Keyring\Facades\Keyring` facade is the entry point for everything you set in code:

| Method | What It Does |
|---|---|
| `Keyring::factors([...])` | Sets the factors users can use. See [Factors](factors.md). |
| `Keyring::extend($key, $resolver)` | Adds one more factor from a closure. Its `key()` must match `$key`. |
| `Keyring::require($requirement)` | Sets the policy. See [Policies](policies.md). |
| `Keyring::pipeline($callback)` | Changes the verification steps. See [The Pipeline](sign-in-flow.md#the-verification-pipeline). |
| `Keyring::respondWith($contract, $implementation)` | Swaps a response. See [Responses](sign-in-flow.md#responses). |
| `Keyring::page($name, $component)` | Changes the component a page renders. See [Pages](sign-in-flow.md#pages). |
| `Keyring::risk()->signals([...])->respond(...)` | Configures risk signals and actions. `Keyring::risk()->push(...)` adds to the signals already on. See [Risk](risk.md). |
| `Keyring::notifications([...])` | Swaps the notification that Keyring sends for a type with your own class, or uses `null` to send none. Types you leave out keep Keyring's own notification. Unknown types throw an `InvalidArgumentException`. See [Security Emails](security-log-and-emails.md#security-emails). |
| `Keyring::createUsersUsing($action)` | Sets the registration action. See [Registration](sign-in-flow.md#registration). |
| `Keyring::resetUserPasswordsUsing($action)` | Sets the password reset action. See [Resetting the Password](protected-changes.md#resetting-the-password). |
| `Keyring::updateUserPasswordsUsing($action)` | Sets the password change action. See [Changing the Password](protected-changes.md#changing-the-password). |
| `Keyring::validateEmailChangesUsing($action)` | Sets the email change validation action. See [Requesting a Change](protected-changes.md#requesting-a-change). |
| `Keyring::routes()` | Registers Keyring's routes yourself, when `routes` is `false`. See [Routes](#routes). |
| `Keyring::useAuthenticatorModel($model)` | Uses your own subclass of `Keyring\Models\Authenticator`. |
| `Keyring::useDeviceModel($model)` | Uses your own subclass of `Keyring\Models\Device`. See [Your Own Device Model](devices-and-sessions.md#your-own-device-model). |
| `Keyring::usePendingChangeModel($model)` | Uses your own subclass of `Keyring\Models\PendingChange`. |
| `Keyring::useSecurityEventModel($model)` | Uses your own subclass of `Keyring\Models\SecurityEvent`. |
| `Keyring::useFailureCountModel($model)` | Uses your own subclass of `Keyring\Models\FailureCount`. |
| `Keyring::attempt($request, $factor)` | Starts a sign in with a factor from a route of your own, through the same pipeline as the login form. See [Starting a Sign In Yourself](sign-in-flow.md#starting-a-sign-in-yourself). |
| `Keyring::requirePasswordChange($user, $reason = null)` | Holds a user until they choose a new password. `requiresPasswordChange($user)` asks whether they're held, and `cancelPasswordChange($user)` lets them go. See [Requiring a Password Change](protected-changes.md#requiring-a-password-change). |
| `Keyring::unlock($user)` | Lets a locked-out user try again without a password reset. It lifts their risk lock, and clears the limits, locks, and failures in a row on the factors that can start a sign in. `Keyring::unlock($user, 'totp')` clears one factor's instead, such as a second factor that was refused at the cap. See [At the Cap](security.md#at-the-cap). |
| `Keyring::allowSignInWhen($callback)` | Decides who may be signed in at all, such as accounts that aren't banned. See [Who May Sign In](sign-in-flow.md#who-may-sign-in). |
| `Keyring::allowEnrollmentWhen($callback)` | Decides who may add a sign-in method, in place of the verified email rule. See [Who May Enroll](authenticators.md#who-may-enroll). |
| `Keyring::allowImpersonationWhen($callback)` | Decides who may sign in as whom. Nobody may until it's called. See [Who May Impersonate Whom](impersonation.md#who-may-impersonate-whom). |
| `Keyring::impersonate($request, $user)` | Signs in as another user, from a controller of your own. `Keyring::stopImpersonating($request)` goes back. See [From Your Own Code](impersonation.md#from-your-own-code). |
| `Keyring::linkRootUsing($callback)` | Where emailed links start, in place of `APP_URL`. Identity providers' [callback URL](sso.md#the-callback-url) starts there too. See [Emailed Links](security.md#emailed-links). |
| `Keyring::sso()` | The identity providers in `sso.providers`. `extend($driver, $resolver)` registers a [driver of your own](sso.md#custom-drivers), and `start()` and `complete()` sign in with a provider [from your own routes](sso.md#signing-up-with-a-provider). |
| `Keyring::recordIpsUsing($callback)` | What Keyring stores as a request's IP address. See [What's Stored](security-log-and-emails.md#whats-stored). |
| `Keyring::describeDevicesUsing($callback)` | Names devices your own way, in place of "Firefox on Windows". See [Device Names](devices-and-sessions.md#device-names). |
| `Keyring::findUsersUsing($callback)` | Finds the user a typed username belongs to, in your own way, for a password sign in. See [Finding the User](sign-in-flow.md#finding-the-user). |
| `Keyring::normalizeUsernamesUsing($callback)` | Normalises usernames your own way. See [Finding the User](sign-in-flow.md#finding-the-user). |
| `Keyring::signInAfterRegistering($when)` | Whether registering signs the user in, where `registration.reveal_taken` lets it. See [Saying When an Address Is Taken](sign-in-flow.md#saying-when-an-address-is-taken). |
| `Keyring::findUser($request)` | The user a password sign in is for, for a primary factor of your own. |
| `Keyring::signsInAfterRegistering($user, $request)` | Whether registering signs this user in, for a registration flow of your own. |
| `Keyring::hidesRegisteredAddresses()` | Whether registration answers the same for a taken address, which it does unless `registration.reveal_taken` is on. |
| `Keyring::withoutProtection($callback, reason: ...)` | Changes protected attributes outside Keyring's flows. See [Protected Changes](protected-changes.md#bypassing-protection). |
| `Keyring::activity($user, $limit = 25)` | Recent security log entries, leaving out the types in `security_log.unlisted`, and the impersonation entries with `impersonation.show_in_activity` off. See [Showing Recent Activity](security-log-and-emails.md#showing-recent-activity). |
| `Keyring::unlistedActivityTypes()` | The entry types `Keyring::activity` leaves out, for an activity query of your own. See [Showing Recent Activity](security-log-and-emails.md#showing-recent-activity). |
| `Keyring::for($user)` | The user's keyring, the same as `$user->keyring`. |
| `Keyring::user()` | The user signed in to Keyring's guard. Throws an `AuthenticationException` when there isn't one. |
| `Keyring::fake()` | Passes or fails factors in tests. See [Testing](testing.md). |

The facade also answers questions about your setup. These are useful in your own controllers, factors, and steps:

| Method | Returns |
|---|---|
| `Keyring::registered()` | The registered factors, keyed by their key. |
| `Keyring::factor($key)` | One registered factor. `Keyring::hasFactor($key)` says whether there is one. |
| `Keyring::guard()` | Keyring's guard. `Keyring::provider()` is its user provider. |
| `Keyring::username()` | The username field, `email` by default. |
| `Keyring::normalizeUsername($username)` | A username as Keyring stores and looks it up. See [Finding the User](sign-in-flow.md#finding-the-user). |
| `Keyring::requirementFor($user, $attempt)` | What this user must prove to finish the attempt. See [Checking Requirements in Code](policies.md#checking-requirements-in-code). |
| `Keyring::statusMessage($status)` | The translated message for a status slug, or `null`. See [Flash Messages and Alerts](frontend.md#flash-messages-and-alerts). |
| `Keyring::render($name, $props)` | Renders one of Keyring's [pages](sign-in-flow.md#pages), as Inertia or Blade, for a route of your own. |
| `Keyring::result($key = null, $default = null)` | What the last status response flashed for the page, such as new recovery codes, or one key of it in dot notation. `$default` when nothing was flashed. See [Flash Messages and Alerts](frontend.md#flash-messages-and-alerts). |
| `Keyring::hasNotification($type)` | Whether a notification is sent for a [type](security-log-and-emails.md#email-types). |
| `Keyring::protectedAttributes($user = null)` | The attributes that only change through Keyring's flows. Pass a user whose model keeps its password under another name to get that name. See [Protected Attributes](protected-changes.md#protected-attributes). |
| `Keyring::response($contract, ...$with)` | Builds one of Keyring's [responses](sign-in-flow.md#responses), or yours when you swapped it, for a route of your own. |
| `Keyring::describeDevice($userAgent)` | A user agent as a name people recognise, or `null`. |
| `Keyring::linkRoot()` | Where emailed links start. |
| `Keyring::email()` | The attribute holding the user's address, `email` by default. |
| `Keyring::policy($user, $attempt)` | What the policy asks of this user, before considering what they've enrolled. |
| `Keyring::steps()` | The pipeline's steps, in order. `Keyring::dangerouslyChangedSteps()` lists the mandatory ones an application took out. |
| `Keyring::notification($type, $arguments)` | The notification for a type, Keyring's own or yours, or `null` when it's turned off. `Keyring::requiredNotification()` throws when it is. |
| `Keyring::belongsToGuard($user)` | Whether Keyring's guard would load this user back, so they can be signed in. |
| `Keyring::recordedIp($request)` | The request's IP address as Keyring stores it. |
| `Keyring::allowsSignIn($user)` | Whether the application lets this user be signed in. See [Who May Sign In](sign-in-flow.md#who-may-sign-in). |
| `Keyring::allowsEnrollment($user)` | Whether the user may add a sign-in method. See [Who May Enroll](authenticators.md#who-may-enroll). |
| `Keyring::allowsImpersonation($impersonator, $user)` | Whether one user may impersonate another, and `Keyring::impersonationRefusal()` why not. See [Who May Impersonate Whom](impersonation.md#who-may-impersonate-whom). |
| `Keyring::impersonating()` | Whether the session is impersonating someone. `Keyring::impersonator()` is who, and `Keyring::impersonation()` what a [banner](impersonation.md#showing-a-banner) needs. |
| `Keyring::authenticatorModel()` | The authenticator model's class. `deviceModel()`, `pendingChangeModel()`, `securityEventModel()`, and `failureCountModel()` do the same for theirs. |
