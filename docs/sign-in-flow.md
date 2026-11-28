# The Sign In Flow

- [Introduction](#introduction)
- [Routes](#routes)
- [Signing In With a Password](#signing-in-with-a-password)
    - [Finding the User](#finding-the-user)
    - [Who May Sign In](#who-may-sign-in)
- [Signing In With a Passkey](#signing-in-with-a-passkey)
- [Starting a Sign In Yourself](#starting-a-sign-in-yourself)
- [The Challenge Page](#the-challenge-page)
    - [Page Props](#page-props)
    - [Choosing an Authenticator](#choosing-an-authenticator)
    - [Verifying](#verifying)
    - [Sending Codes](#sending-codes)
- [Finishing the Login](#finishing-the-login)
- [Registration](#registration)
    - [Without Revealing Who Has an Account](#without-revealing-who-has-an-account)
    - [Saying When an Address Is Taken](#saying-when-an-address-is-taken)
- [Signing Out](#signing-out)
- [The Verification Pipeline](#the-verification-pipeline)
    - [Customising the Steps](#customising-the-steps)
    - [Mandatory Steps](#mandatory-steps)
    - [Writing a Step](#writing-a-step)
- [Responses](#responses)
    - [Status Responses](#status-responses)
- [Pages](#pages)
- [Events](#events)

## Introduction

Signing in follows a short sequence of steps:

1. The user proves a first factor, usually their password, by posting to `/login`. This identifies them.
2. Keyring asks the [policy](policies.md) what they need. If the policy is satisfied, they're signed in.
3. Otherwise, Keyring regenerates the session ID, saves a pending **attempt** in the session, and sends them to the challenge page, which asks for the next factor. They repeat this until the requirement is met.

The pending attempt is encrypted JSON in the session. It lasts `pending_logins.keep_for` (10 minutes by default). It ends early if the user's password or email address changes in the meantime, so a reset also stops someone who already got past the old password. It also ends if a sign-in method it has already proved is taken off the account, or if `keyring.guard` is no longer the guard it started under. After that, the user is sent back to the login page with `keyring::keyring.expired`.

[Step-up](step-up.md) uses the same challenge page and the same pipeline, with the purpose `confirm` instead of `login`.

## Routes

| Method | URI | Name | Purpose |
|---|---|---|---|
| `GET` | `/login` | `login` | The login page. |
| `POST` | `/login` | `login.store` | Sign in with a password. |
| `GET` | `/login/{factor}/options` | `keyring.login.options` | Options for signing in without a username (passkeys). |
| `POST` | `/login/{factor}` | `keyring.login.factor` | Sign in with another primary factor (passkeys). |
| `GET` | `/auth/{provider}/redirect` | `keyring.sso.redirect` | Send the user to an identity provider to sign in. Uses the `keyring-login-options` rate limiter. Only registered when `sso.providers` lists a provider, and only answers once the `SingleSignOn` factor is registered. See [Single Sign-On](sso.md). |
| `GET` | `/auth/{provider}/callback` | `keyring.sso.callback` | Where the identity provider sends the user back, to sign in, to link an account, or to confirm a step-up. For anyone: it takes the guest or signed-in middleware its purpose needs, and a guest's uses the `keyring-login-options` rate limiter. Registered with the redirect. |
| `GET` | `/confirm/sso/redirect` | `keyring.sso.confirm` | Send a signed-in user back to the provider of a link the confirm page offers, to confirm a [step-up](sso.md#step-up). Takes the link's ID as `authenticator`. Uses the `keyring-login-options` rate limiter. Registered with the redirect. |
| `GET` | `/login/challenge/{factor?}` | `keyring.login.challenge` | The challenge page. |
| `POST` | `/login/challenge/{factor}` | `keyring.login.verify` | Verify the next factor. |
| `POST` | `/login/challenge/{factor}/send` | `keyring.login.send` | Send a code (email codes). |
| `GET` | `/register` | `register` | The registration page. |
| `POST` | `/register` | `register.store` | Create an account. Uses the `keyring` rate limiter. See [Registration](#registration). |
| `POST` | `/logout` | `logout` | Sign out. |

The login and registration routes are for guests only, and the `/logout` route requires `auth:{guard}`. The registration routes exist only when the `registration` feature is on. By default, the `keyring` rate limiter allows six a minute. See [Rate Limits](configuration.md#pending-logins-timebox-and-rate-limits).

The routes that spend session state (`POST /login`, `POST /login/{factor}`, the challenge page, its verify and send routes, and the three single sign-on routes) take Laravel's session lock with `->block()`, so parallel requests in one session wait their turn instead of spending the same state twice.

> [!NOTE]
> Your cache store must support locks.

A factor key that isn't registered gives a `404` on `/login/{factor}`, its `options` route, the enrollment routes, and the verify and send routes once a sign in or step-up is under way. The challenge page's `GET` routes send an unknown key back to the page without it instead.

## Signing In With a Password

To sign in with a password, post the username and password to `/login`. The request takes these fields:

| Field | |
|---|---|
| `email` (or your `username` attribute) | Required. Trimmed and lowercased before the lookup. See [`normalizeUsernamesUsing`](#finding-the-user). |
| `password` | Required. |
| `remember` | Optional boolean, for Laravel's "remember me" cookie. |

A wrong password and an unknown account get the same error, shown on the username field with Laravel's `auth.failed` message. Both also take the same amount of time.

Send these fields in the request body, either as a form or as JSON. Keyring doesn't read the query string of a `POST` request for them, so `POST /login?password=...` fails as if no password was sent. See [Request Input](security.md#request-input).

### Finding the User

By default, Keyring looks the user up by the attribute named in the `username` configuration option, which is `email`. The value is trimmed and lowercased first. You may change either behaviour in your `KeyringServiceProvider`:

```php
use App\Models\User;
use Illuminate\Http\Request;

// Sign in with an email address or a username.
Keyring::findUsersUsing(fn (Request $request) => User::query()
    ->where('email', $request->email)
    ->orWhere('username', $request->email)
    ->first());

// Keep usernames' case (for lookups, rate limits, email changes and reservations).
Keyring::normalizeUsernamesUsing(fn (string $username) => trim($username));
```

Whether a lookup respects case also depends on your database. MySQL's default collations ignore case, while PostgreSQL and SQLite don't.

The finder only tells Keyring whose username was typed, and only the password form asks it. A passkey finds its account without one. To keep an account out, use `allowSignInWhen`.

Failed attempts count against the user your finder returns, however the username was typed. That gives an account one limit, whether someone guesses its email address or its username. Keyring calls the finder once to count the attempt and again to check it, so keep the finder to a simple lookup.

`findUsersUsing` only finds the user. Keyring still checks the password, and a `null` result gets the same answer as a wrong password, in the same time. The answer is also the same for a user that Keyring's guard wouldn't load back through its provider, such as a user of another model. The username field's validation still applies. If you need to change it, do so with a [pipeline step](#writing-a-step).

### Who May Sign In

To keep some accounts out altogether, such as banned ones, tell Keyring who may sign in:

```php
use App\Models\User;

Keyring::allowSignInWhen(fn (User $user) => ! $user->banned);
```

Keyring checks this wherever a session starts or continues:

- Every way of starting a sign in, including the password, a passkey, and any factor of your own.
- A sign in that's waiting for its second factor.
- A "remember me" cookie. Keyring ends the session it would have continued, so the same cookies can't sign the account back in once it's allowed again.
- Each request in a session that's already signed in. That session is signed out, with a `session_ended` entry whose reason is `not_allowed`. The first refused request also ends every other session the account has, along with its "remember me" cookies, trusted devices, and any pending email change (a `sessions_revoked` entry). That way, a session that stayed away doesn't work again once the account is let back in.
- Registration that [signs new users in](#saying-when-an-address-is-taken), which leaves this one signed out.

An account that's turned away gets the same answer as one that doesn't exist. The same goes for an account whose address isn't verified yet, when registration [doesn't reveal who has an account](#without-revealing-who-has-an-account). Anything that doesn't sign anyone in still works for that account, such as a password reset, and the emailed links that confirm or undo an email change or report a device.

The callback runs on every signed-in request, so answer from the user it receives instead of running a query.

> [!WARNING]
> Keyring only finds out that an account is kept out when one of its sessions makes a request. Until then, those sessions are still in the registry, and they would work again if the account were let back in before any of them made a request.

To end them as you set your flag, sign the account out yourself:

```php
use Keyring\Sessions\Sessions;

$user->forceFill(['banned' => true])->save();

app(Sessions::class)->signOutEverywhere($user);
```

That is also what OWASP ASVS 5.0.0 (7.4.2) asks for: a disabled account's sessions end when it's disabled, not when they're next used.

> [!WARNING]
> Use `allowSignInWhen` rather than a global scope on the user model to keep an account out. A scope makes the account look missing to Keyring, which ends nothing. Its sessions, "remember me" cookies, trusted devices, and any pending email change all remain when the scope shows the account again, and no event fires to clear them.

## Signing In With a Passkey

Passkeys can sign a user in without a username. The browser requests options, runs the WebAuthn ceremony, and posts the result in two steps:

1. `GET /login/passkey/options` returns WebAuthn request options as JSON, under `options`, with an empty `allowCredentials`. Keyring keeps the challenge in the session.
2. `POST /login/passkey` with a `credential` field, which holds the browser's response as JSON, and optionally `remember`.

The options come back in this shape:

```json
{ "options": { "challenge": "...", "timeout": 60000, "rpId": "example.com", "allowCredentials": [], "userVerification": "required" } }
```

The same options also work for autofill ("conditional UI"), where the browser offers passkeys in the email field. The browser package's `usePasskeyLogin` handles all of this for you. See [Frontend](frontend.md#signing-in-with-a-passkey). The two requests are the same ones Laravel's `@laravel/passkeys` client makes, so [it can sign in here too](passkeys.md#laravels-passkeys-client).

A passkey sign in still goes through the policy, so a policy such as `Requirement::factors(3)` would still ask for more.

Only factors that implement `PrimaryFactor` and return `true` from `startsLogin` can start a sign in. Only `DiscoverableFactor`s serve options, and any other factor key returns a 404. Security keys share the passkey driver, but their `startsLogin` returns `false`, so `/login/security-key` and its options route return a 404 too.

## Starting a Sign In Yourself

`POST /login/{factor}` starts a sign in with any factor that supports it. When the proof arrives somewhere else, such as a callback from a service of your own, you may start the sign in from your own route with `Keyring::attempt`:

```php
use Illuminate\Http\Request;
use Keyring\Facades\Keyring;

Route::get('/partner/callback', fn (Request $request) => Keyring::attempt($request, 'partner'))
    ->middleware('guest')
    ->block();
```

It runs the same [pipeline](#the-verification-pipeline) as the login form, so rate limits, the policy, and risk checks all apply. A user with a second factor is sent to the challenge page. It answers with the same [responses](#responses). For a failure, that's a `ValidationException`, which you may want to catch and turn into a redirect to your login page. A factor that can't start a login answers with `404`.

Keyring's own [single sign-on](sso.md) callback signs in this way, and [Signing Up With a Provider](sso.md#signing-up-with-a-provider) has a complete example of a route that does. Keep your own routes away from `/auth/{provider}/redirect` and `/auth/{provider}/callback`, which are Keyring's.

## The Challenge Page

`GET /login/challenge` shows the next factor to verify. `GET /login/challenge/{factor}` shows that factor instead, as long as it would bring the user closer to the requirement. If there's no pending attempt, the user goes back to the login page.

### Page Props

The page (`challenge` for sign ins, `confirm` for step-up) receives:

```json
{
  "purpose": "login",
  "factor": "security-key",
  "authenticator": { "factor": "security-key", "id": "01JC3...", "name": "Work key" },
  "challenge": { "options": { "challenge": "...", "rpId": "example.com", "allowCredentials": [{ "type": "public-key", "id": "AbC...", "transports": ["usb"] }] } },
  "alternatives": [
    { "factor": "totp", "id": "01JC4...", "name": "Authenticator app" },
    { "factor": "recovery", "id": "01JC5...", "name": "Recovery codes", "remaining": 7, "replace": false }
  ],
  "canTrustDevice": true,
  "expiresAt": "2026-11-08T14:05:00+00:00"
}
```

| Prop | |
|---|---|
| `purpose` | `login` or `confirm`. |
| `factor` | The key of the factor to verify now. |
| `authenticator` | How the factor presents this authenticator. It leaves out the dates a [settings page](authenticators.md#adding-an-authenticator) gets, so someone who has only the password isn't told when its owner last signed in. It always includes `factor`, `id`, and `name`, and `id` is `null` for the password. Email codes add `hint`, a masked address such as `t•••@example.com`. Recovery codes add `remaining` and `replace`. `replace` says whether a code has been used, so the user should [make a new set](authenticators.md#recovery-codes). |
| `challenge` | Props specific to the factor. See below. |
| `alternatives` | The user's other authenticators that would help, for a "try another way" link. These have the same shape as `authenticator`. |
| `canTrustDevice` | Whether to show a "don't ask again on this device" option. This is `true` for sign ins when `Features::devices()` is on, `devices.trust_for` isn't `null`, and verifying this authenticator would bring the sign in to AAL2. |
| `expiresAt` | When the pending attempt expires, as an ISO 8601 date. |

The `challenge` prop holds these values for the built-in factors:

| Factor | Challenge |
|---|---|
| `password`, `totp`, `recovery` | `[]` |
| `email-code` | `length` (the number of digits), `sent` (whether a code has been sent), and `expiresAt` (the code's expiry, or `null`). |
| `passkey`, `security-key` | `options`, the WebAuthn request options for the browser. |
| `sso` (confirm page only) | `provider`, its `label`, and `url`, which sends the user to the provider to sign in again. See [Single Sign-On](sso.md#step-up). |

Alternatives only include authenticators that bring the user closer to the requirement. For example, after a password, another password isn't offered. With [no downgrade](policies.md#no-downgrade) turned on, a user who has an established passkey or security key is only offered their other keys, plus recovery codes unless the policy refuses those too.

### Choosing an Authenticator

If the URL has no factor, the page shows the user's default authenticator when it would help. Otherwise, it shows the first useful one by priority. To pick one authenticator of a factor, add `?authenticator={id}` to the URL:

```
GET /login/challenge/security-key?authenticator=01JC3...
```

Keyring remembers which authenticator the page showed for each factor.

### Verifying

Post the proof to `POST /login/challenge/{factor}`, using these fields:

| Field | Used By |
|---|---|
| `password` | `password` |
| `code` | `totp`, `email-code`, `recovery`, and most custom factors. |
| `credential` | `passkey` and `security-key`. The browser's WebAuthn response, either as an object or a JSON string. |
| `authenticator` | Optional. The authenticator ID. It defaults to the one the page showed, or to the only authenticator of that factor. |
| `trust` | Optional boolean. When true, this device is trusted for `devices.trust_for`, once this login has reached AAL2. |

For WebAuthn, the browser may answer with any of the user's keys for that factor, not only the one shown. Keyring accepts it.

A wrong proof fails with `keyring::keyring.invalid`, shown on the factor's field (`password`, `code`, or `credential`). A wrong code keeps its guess count, so neither reloading the page nor sending a new code resets it.

Once a pending attempt reaches a factor's limit (five guesses by default), nothing can finish it. Verifying then fails with `keyring::keyring.too_many_codes`. Opening the challenge page or sending a code ends the attempt and sends the user back to the start (`/login`, or `/confirm` for a step-up) with that message. An attempt that has timed out does the same, with `keyring::keyring.expired`. On `/login`, the message appears on the username field. On `/confirm`, it appears on the field of the factor the page asks for next, such as `password` or `code`. The account's limits keep counting these failures. A JSON request isn't redirected. It gets the message as a `422` validation error, with the page to start again on as `page` (see [Responses](#responses)).

### Sending Codes

Factors that send codes only send one when asked. To send a code, post to this route:

```
POST /login/challenge/email-code/send
```

Viewing the page, or prefetching it, never sends anything. Each account can be sent three codes per factor every 10 minutes ([`limits.codes` and `limits.codes_per`](configuration.md#pending-logins-timebox-and-rate-limits)). These codes are counted across sign ins, step-ups, and enrollments, so starting over doesn't buy more. A fourth request gets a `429` with Laravel's `auth.throttle` message on `code`. A new code replaces the previous one, and a code only verifies the authenticator it was sent to. The response is a [status response](#status-responses) with `code-sent`.

## Finishing the Login

When the requirement is met, Keyring:

1. signs the user into the guard, with "remember me" if it was ticked,
2. regenerates the session ID, destroying the old one,
3. records what they proved, for [step-up](step-up.md),
4. recognises or registers the [device](devices-and-sessions.md), and registers the session,
5. dispatches `Keyring\Events\Authenticated`,
6. flashes `keyring.alerts` for anything suspicious since their last sign in (see ["Was This You?" Alerts](security-log-and-emails.md#was-this-you-alerts)),
7. dispatches `NewDeviceSignedIn` if the device is new,
8. redirects to the intended URL, or `home`.

## Registration

`POST /register` passes the whole request to your `CreatesNewUsers` action. The action is published to `app/Actions/Keyring/CreateNewUser.php` and registered with `Keyring::createUsersUsing`. It has two methods:

- `validate(array $input): array` checks the form and returns what `create()` needs. The published version validates `name`, `email`, `password`, and `password_confirmation`, using `PasswordRules::for`. See [Password Rules](protected-changes.md#password-rules).
- `create(array $input)` saves the user, using what `validate` returned.

You may change both to fit your application, but leave out any check that the address is free. Keyring makes that check itself, after `validate` has passed and before `create` is called. An address counts as taken when an account has it, including a soft deleted account or one that a global scope of yours hides. It also counts as taken when the address is [held for its previous owner](protected-changes.md#the-old-address-is-reserved) while their email change can still be undone. What Keyring does with a taken address is controlled by the `registration.reveal_taken` option.

### Without Revealing Who Has an Account

By default (`registration.reveal_taken` is `false`), nobody can use the form to find out whether an address has an account. This is what OWASP ASVS 5.0.0 (6.3.8) asks of registration.

- The answer is always the same. The user is redirected to the login page with the `registration-received` status ("Thanks for registering. We've emailed that address with what to do next."), or gets that status as JSON. Nobody is signed in.
- Validation errors from your action are shown as usual. They're the same for every address, because your action never checks whether an address is taken.
- After your action's `validate` method runs, Keyring refuses any password the hasher can't handle, whatever your rules say. With bcrypt, that means one longer than 72 bytes, or one with a NUL byte. The refusal is the same for every address, and it happens before Keyring checks whether the address is taken.
- **If `create` throws an exception**, Keyring passes it to `report`, and the answer is the usual one. Nothing is created or sent. That means the visitor is told to check an inbox that receives nothing. A `create` that keeps failing shows up in your error tracker, rather than as failed requests. A `ValidationException` thrown there is shown like any other validation error, since it's your action refusing the form on purpose.
- **A free address** gets its account, and Laravel's `Registered` event is dispatched once the response has been sent, which emails the verification link.
- **A taken address** gets nothing created or changed. Once the response has been sent, Keyring emails the address your `already_registered` [notification](security-log-and-emails.md#emails-a-flow-needs). The email says someone tried to register. It links to the login page and, with `Features::resetPasswords()`, to the forgot password page. If the account there was never verified, the address is sent another verification link instead, since the first may be lost or expired.
- Registration mails any one address five times an hour at most (`limits.notices` every `limits.notices_per`), and verification links count toward that. This keeps the form from being used to fill someone's inbox. Past that limit, the answer stays the same and nothing is sent.
- Every registration request takes at least `timebox` (500ms), whether the form was refused, an account was created, or the address was taken. Both of the last two hash one password. No email is sent before the response.
- Registration keeps the `keyring` rate limiter: six a minute per IP address.

A new user can't sign in until their address is verified. If they could, anyone could register an address with a password of their own and then try to sign in with it. Success would reveal that the address was free. So until verification, a correct password gets the same answer as a wrong one, in the same time.

Verifying takes the emailed link and the password together:

1. The user follows the link. Their browser isn't signed in, so Keyring remembers the link in the session and sends them to the login page with the `sign-in-to-verify` status. It gives the session a new ID first, so only the browser that followed the link holds the remembered link, even if someone else knew the old session ID. The new session also comes with a new CSRF token, so a login page already open in another tab of that browser needs reloading before it can post. Opening the link changes nothing by itself, so a mail scanner that fetches it verifies nothing.
2. They sign in. From the browser that followed the link, the account may sign in, and doing so verifies the address. Laravel's `Verified` event fires. They're then sent back to the link, which has nothing left to do, and it sends them on to `home`.

From then on, they can sign in anywhere, like anyone else. A link works until it expires (`auth.verification.expire`, 60 minutes). Registering again with the same address sends a new link. A finished [password reset](protected-changes.md#resetting-the-password) verifies the address too, since its link went to the same inbox. A password reset is the way in for the owner of an address that someone else registered first. That owner can't verify an account whose password they don't know, and whoever registered it never sees the link.

This needs email verification. Keyring tells you when it's missing, rather than letting the gap through quietly:

- With registration on and `Features::emailVerification()` off, the app won't boot. It throws `Keyring\Exceptions\EmailVerificationRequired`.
- If the user model doesn't implement `MustVerifyEmail`, or there's no `already_registered` notification, `POST /register` throws before anything is saved.

This also means an unverified account can't sign in at all, however it got that way. A session whose user loses `email_verified_at` is signed out on its next request. Mark accounts that you create yourself, through an import, a seeder, or a social login, as verified.

A few things are still yours to keep quiet:

- A username of your own that must be unique, such as a handle, will say when it's taken, because your action checks it.
- The same goes for a `ValidationException` that your `create` throws for a free address only.
- Anything your action's `create` does that takes noticeably longer than the timebox will show. Your `Registered` listeners run after the response, so they can't slow down one answer and not the other.
- Your mail provider's bounce and delivery reports are outside the request altogether.

### Saying When an Address Is Taken

Many applications would rather tell someone straight away that they already have an account. To do that, set the option, and registration works the way it does in Laravel's starter kits:

```php
// config/keyring.php
'registration' => [
    'reveal_taken' => true,
],
```

- A taken address gets Laravel's "has already been taken" error on the email field, alongside any other validation errors. Nothing is emailed.
- A new user is signed in straight away. The password they chose counts as proved, and `Registered` is dispatched during the request. The policy isn't consulted, since they have no other factors yet. The answer comes from `RegisterResponse`, which by default behaves like `AuthenticatedResponse`. You may swap it to send new users somewhere else, such as an onboarding page. See [Responses](#responses).
- Users can sign in before verifying their address, and email verification is optional.
- An exception your action's `create` throws isn't caught. There's nothing left to hide, so it fails like any other request.

> [!WARNING]
> This tells anyone who asks whether an address has an account. The error says so, and so does being signed in. It's the trade most consumer apps make, and it doesn't meet ASVS 6.3.8.

To leave new users signed out in this mode, for example until an admin approves them, pass `false` or a callback to `signInAfterRegistering`. They're sent to the login page with the `registered` status:

```php
Keyring::signInAfterRegistering(false);
Keyring::signInAfterRegistering(fn (User $user, Request $request) => ! $user->needs_approval);
```

## Signing Out

`POST /logout` revokes the registered session, signs the user out, forgets what they proved, and invalidates the session. JSON clients get a `204 No Content` response. Everyone else is redirected to `/`.

The response also sends `Clear-Site-Data: "cache", "storage"`. It leaves cookies alone, so the device cookie survives and the next sign in isn't treated as a new device.

Signing out while [impersonating](impersonation.md#signing-out-while-impersonating) signs the browser out of the impersonator's own session too, and leaves the user's "remember me" token alone.

To sign the current user out the same way from your own code, use the `out` method on `Keyring\Login\SignIn`. It returns the user who was signed out, or `null`. Keep in mind that it doesn't dispatch `LoggedOut`. For example:

```php
use Keyring\Login\SignIn;

app(SignIn::class)->out($request);
```

Your own `Auth::logout()` or `Auth::logoutCurrentDevice()`, on Keyring's guard in a request with a session, ends the registered session too, with its "remember me" cookie and what the session proved, so a sign-out route you already have keeps working. Invalidate the session after it as Laravel's docs do, or before it on any route Keyring's [session middleware](devices-and-sessions.md#the-session-middleware) runs on; `SignIn::out()` does that part for you. It dispatches no `LoggedOut`, so nothing reaches the security log. Dispatch `Keyring\Events\LoggedOut` yourself if you want it there.

## The Verification Pipeline

Every verification, at login or step-up, goes through one pipeline of steps:

| Step | Does |
|---|---|
| `EnsureNotThrottled` | Checks the factor's rate limits, counts the attempt, and locks out repeated failures. See [Rate Limiting](security.md#rate-limiting). |
| `VerifyFactor` | Validates the request, identifies the user for primary factors, and checks the proof. If the check fails, it stops the pipeline. |
| `ResolveDevice` | Notes the device this attempt comes from, along with the `trust` checkbox. |
| `EnsureNotRiskLocked` | Refuses a user who is under a [risk lock](risk.md#actions), with the usual generic error. Skipped for step-up. |
| `AssessRisk` | Runs the [risk signals](risk.md) once per login and acts on them. Skipped for step-up. |
| `DetermineRequirement` | Asks the policy what the user needs to prove. |
| `CompleteAttempt` | Signs the user in, or confirms them, when the requirement is met. Otherwise, it regenerates the session ID and saves the attempt for the challenge page. |

You'll find the steps in `Keyring\Pipeline\Steps\`.

### Customising the Steps

You may change the pipeline with `Keyring::pipeline`. For example, this code adds a step after `ResolveDevice` and replaces `AssessRisk`:

```php
use App\Keyring\BlockSanctionedCountries;
use App\Keyring\MyRiskStep;
use Keyring\Facades\Keyring;
use Keyring\Pipeline\Steps;
use Keyring\Pipeline\Steps\AssessRisk;
use Keyring\Pipeline\Steps\ResolveDevice;

Keyring::pipeline(fn (Steps $steps) => $steps
    ->after(ResolveDevice::class, BlockSanctionedCountries::class)
    ->replace(AssessRisk::class, MyRiskStep::class));
```

The `Steps` class has `before`, `after`, `replace`, and `remove` methods. `before` and `after` take any number of steps. Each method throws an `InvalidArgumentException` if the step you name isn't in the pipeline. You may call `Keyring::pipeline` more than once. The callbacks run in order, and each one runs as soon as you call it, so a mistake shows up at boot.

### Mandatory Steps

The steps `EnsureNotThrottled`, `VerifyFactor`, `EnsureNotRiskLocked`, `DetermineRequirement`, and `CompleteAttempt` enforce Keyring's guarantees. That's why `replace` and `remove` throw an `InvalidArgumentException` if you name one of them. `ResolveDevice` and `AssessRisk` are yours to replace or remove.

If you really mean to take a mandatory step out, say so:

```php
Keyring::pipeline(fn (Steps $steps) => $steps
    ->dangerouslyReplace(EnsureNotThrottled::class, MyRateLimiter::class));
```

> [!WARNING]
> `dangerouslyReplace` and `dangerouslyRemove` log a warning when `Keyring::pipeline` is called, and the [conformance suite](testing.md#the-conformance-suite) fails until you acknowledge the step. Whatever that step checked is then up to you.

Before it signs anyone in, `CompleteAttempt` also confirms that the request was throttled, verified, and checked for a risk lock, and that the requirement is met. If any of those didn't happen, it logs an error, dispatches `VerificationRefused` (recorded as a `verification_refused` entry in the [security log](security-log-and-emails.md#entry-types)), and refuses with the usual generic error. It doesn't ask for those checks from a step you took out with `dangerouslyReplace` or `dangerouslyRemove`, but the requirement must always be met.

### Writing a Step

A step is a class with a `handle()` method that receives a `Keyring\Pipeline\Context` and the next step. Steps are resolved from the container, so you may inject dependencies:

```php
namespace App\Keyring;

use Closure;
use Keyring\Devices\Location;
use Keyring\Enums\Purpose;
use Keyring\Pipeline\Context;

class BlockSanctionedCountries
{
    public function handle(Context $context, Closure $next): Context
    {
        $country = Location::of($context->request)['country'] ?? null;

        if ($context->purpose === Purpose::Login && in_array($country, config('app.blocked_countries'), true)) {
            return $context->fail();
        }

        return $next($context);
    }
}
```

The context holds:

| | |
|---|---|
| `$context->request` | The request. |
| `$context->purpose` | `Purpose::Login` or `Purpose::Confirm`. |
| `$context->factor` | The factor being verified. |
| `$context->attempt` | The pending `Attempt`. |
| `$context->authenticator` | The authenticator being verified. |
| `$context->verification` | The `Verification`, once `VerifyFactor` has passed. |
| `$context->identifying` | Whether this request also identifies the user (the first factor of a sign in). |
| `$context->outcome` | The `Keyring\Pipeline\Outcome`, set by `CompleteAttempt` or by a failure. |

`Location::of($request)` asks the configured [locator](devices-and-sessions.md#locations) once per request and remembers the answer, so steps, signals, and device tracking share a single lookup.

To refuse with the same generic error as a wrong password, return `$context->fail()`. To answer as rate limited, return `$context->lockout($seconds)`. A failure counts toward the rate limits, the same as a wrong password.

Where you put a step matters. Before `VerifyFactor`, the first factor of a sign in has no attempt or authenticator yet, so `$context->attempt` is `null`. After `VerifyFactor`, steps only run when the proof was right, and the attempt is always set.

## Responses

Each outcome is answered by a response class, bound to a contract in `Keyring\Contracts\Responses`:

| Contract | When | Default |
|---|---|---|
| `AuthenticatedResponse` | The login or confirmation is complete. | Redirect to the intended URL or `home`. JSON: `{"status": "authenticated", "redirect": "..."}`. |
| `ChallengeResponse` | Another factor is needed. | Redirect to the challenge page. JSON: `202` with `{"status": "challenge", "page": "challenge", "redirect": "..."}`, where `page` is `confirm` for step-up. |
| `FailedResponse` | The proof was wrong or the user wasn't found. | A validation error: `auth.failed` on the username field when starting a login with a password (a passkey has no username field, so it goes on `credential`), otherwise `keyring::keyring.invalid` on the factor's field. |
| `LockoutResponse` | Too many attempts. When an account's own limit refuses a typed username, the answer is `FailedResponse` instead (see [Rate Limiting](security.md#rate-limiting)). | A `429` validation error with Laravel's `auth.throttle` message, or `keyring::keyring.locked` when a password reset is the way back in, or `keyring::keyring.factor_locked` for a second factor that has to be set up again. |
| `LogoutResponse` | The user signed out. | Redirect to `/`. JSON: `204`. Both send `Clear-Site-Data`. |
| `RegisterResponse` | A new user registered and was signed in, with [`registration.reveal_taken`](#saying-when-an-address-is-taken). | The same as `AuthenticatedResponse`. |
| `StatusResponse` | Every other action: a code sent, a password changed, a device signed out... | See [Status Responses](#status-responses). |
| `SignedOutResponse` | A session was ended for the user: revoked, timed out, or signed out by a risk response, or an [impersonation](impersonation.md#security-log-and-events) ended with nothing to go back to. Built with the `reason`. | Redirect to the login page with the `signed-out` status, which brings them back afterwards. JSON: `401` with `"page": "login"` and `redirect`. Both send `Clear-Site-Data`. Not used for page visits to [routes that also serve guests](devices-and-sessions.md#pages-that-also-serve-guests). |
| `ConfirmationRequiredResponse` | A route needs [step-up](step-up.md) first. | Redirect to the confirm page, which brings them back afterwards. JSON: `423` with `"page": "confirm"` and `redirect`. |
| `EnrollmentRequiredResponse` | A route needs a sign-in method the user hasn't set up. | Redirect to `enrollment_url` with the `enroll-first` status, or `403` without one. JSON: `403`. |
| `PasswordChangeRequiredResponse` | The user has to [choose a new password](protected-changes.md#requiring-a-password-change) before going on. | Redirect to `password_change_url` with the `change-password` status, or `403` without one. JSON: `403`. |
| `VerifiedResponse` | The user's email address is verified. Built with `justNow`, which is true when the link they followed did the verifying. | Redirect to the intended URL or `home`, with `?verified=1` when `justNow`. JSON: `{"status": "email-verified", "message": "...", "justNow": true, "redirect": "..."}`. |

In this table, "JSON" means the request expects JSON and isn't an Inertia request. Inertia visits get redirects, like normal page visits. Whenever a JSON answer sends the browser to one of Keyring's [pages](#pages), it names the page as `page` beside the `redirect`, so a [frontend of your own](headless.md) can go to its page of that name without reading the URL.

A sign in or step-up that ran out, or that used up its code guesses, sends a page visit back to the login or confirm page with the reason as a validation error. A JSON request gets that error as a `422`, in Laravel's validation shape, with `page` and `redirect` added:

```json
{
  "message": "Your sign in timed out. Please start again.",
  "errors": { "email": ["Your sign in timed out. Please start again."] },
  "page": "login",
  "redirect": "https://example.com/login"
}
```

You may swap any response with `Keyring::respondWith`:

```php
use App\Http\Responses\WelcomeBack;
use Keyring\Contracts\Responses\AuthenticatedResponse;

Keyring::respondWith(AuthenticatedResponse::class, WelcomeBack::class);
```

Your class must implement the contract. Keyring builds it through the container and passes what it knows by constructor parameter name. A contract that takes any lists those names in a `BUILT_WITH` constant: `status`, `data`, and `redirect` for a `StatusResponse`, `reason` for a `SignedOutResponse`, and `justNow` for a `VerifiedResponse`. A contract without the constant, such as `LogoutResponse`, passes nothing. Take only the ones you need, and type-hint anything else for the container to inject. A required parameter that Keyring can't fill is refused when you call `respondWith`, so the problem shows up at boot, not at someone's first sign in.

After a verification, Keyring builds responses with the pipeline's `context`, so you may accept it in the constructor:

```php
use Keyring\Contracts\Responses\AuthenticatedResponse;
use Keyring\Enums\Purpose;
use Keyring\Pipeline\Context;

class WelcomeBack implements AuthenticatedResponse
{
    public function __construct(protected ?Context $context = null) {}

    public function toResponse($request)
    {
        return $this->context?->purpose === Purpose::Confirm
            ? redirect()->intended(config('keyring.home'))
            : redirect()->intended('/welcome-back');
    }
}
```

`LogoutResponse` and `RegisterResponse` are never given a context.

`respondWith` also accepts a closure. It's bound in the container like any other binding, and it receives what Keyring passes as its second argument. To answer with one of these responses from a route of your own, build it the same way with `Keyring::response`:

```php
return Keyring::response(StatusResponse::class, status: 'device-revoked', redirect: route('login'));
```

### Status Responses

Every action that isn't a sign in or confirmation answers through `StatusResponse`. It's built with three arguments:

| Argument | |
|---|---|
| `status` | A slug such as `password-updated` or `device-revoked`. |
| `data` | Extra data, such as the new authenticator. Often empty. |
| `redirect` | Where to go instead of back, or `null`. |

JSON clients get the slug, its translated message, the redirect (when there is one), and the data, all side by side. When the redirect is one of Keyring's pages, such as the login page after a password reset, `page` names it:

```json
{
  "status": "authenticator-updated",
  "message": "Sign-in method updated.",
  "authenticator": { "factor": "totp", "id": "01JC4...", "name": "Work phone" }
}
```

Other requests are redirected, either back or to `redirect`. The slug is flashed as `status`, along with any data for the next request. That data is encrypted with `APP_KEY`, since it can hold a secret being set up or new recovery codes. Read it with `Keyring::result`, or read one key of it using dot notation, for example `Keyring::result('recoveryCodes')`. It's `null` when nothing was flashed. `session('keyring.result')` holds only the ciphertext.

Two statuses can say where the user was going when Keyring sent them away. That happens when they were sent to [add a sign-in method](policies.md#carrying-on-afterwards) or [held to choose a new password](protected-changes.md#carrying-on-afterwards):

- `authenticator-added` carries it as `continue` in its data. It's data rather than a redirect, so a page showing new recovery codes stays up until the user has saved them. The key is left out when there's nowhere to carry on to, and when the account still can't meet what sent the user to enroll, such as after adding an email code where a second factor is asked for. The page is kept for the sign-in method that does.
- `password-updated` uses it as `redirect`, but only when the user was held for a new password. A password change the user chose goes back, as before.

```json
{
  "status": "authenticator-added",
  "message": "Sign-in method added.",
  "authenticator": { "factor": "totp", "id": "01JC4...", "name": "Authenticator app" },
  "recoveryCodes": ["..."],
  "continue": "https://example.com/invoices/42"
}
```

The messages live in `lang/en/status.php`, as `keyring::status.{slug}`. The pages Keyring renders that show a status (`login`, `forgot-password`, and `verify-email`) receive the translated message as their `status` prop, not the slug. The slugs are:

`authenticator-added`, `authenticator-removed`, `authenticator-updated`, `change-password`, `code-sent`, `device-reported`, `device-revoked`, `email-change-cancelled`, `email-change-confirmed`, `email-change-invalid`, `email-change-requested`, `email-change-reverted`, `email-changed`, `email-verified`, `enroll-first`, `enrollment-started`, `impersonating`, `impersonation-ended`, `impersonation-refused`, `impersonation-started`, `not-impersonating`, `password-reset`, `password-updated`, `registered`, `registration-received`, `reset-link-sent`, `session-revoked`, `sessions-revoked`, `sign-in-to-verify`, `signed-out`, `sso-cancelled` and `verification-link-sent`.

You can swap it the same way as the others. Your class receives the same named arguments:

```php
use Keyring\Contracts\Responses\StatusResponse;

Keyring::respondWith(StatusResponse::class, MyStatusResponse::class);
```

## Pages

Keyring renders these pages:

| Name | Props |
|---|---|
| `login` | `canResetPassword`, `canRegister`, `status` (a translated message), `providers` (the identity providers to offer, each with `name`, `label` and `url`, once the `SingleSignOn` factor is registered; otherwise empty) |
| `challenge` | See [Page Props](#page-props). Used for sign ins. |
| `confirm` | The same props, with `purpose: "confirm"`. Used for step-up. |
| `register` | None. The published action expects `name`, `email`, `password`, and `password_confirmation`. Afterwards, the user lands on the login page with the `registration-received` status, unless [registration signs them in](#saying-when-an-address-is-taken). |
| `forgot-password` | `status` (a translated message) |
| `reset-password` | `token`, `email` |
| `verify-email` | `status` (a translated message) |
| `email-verification` | `email` (the address being verified), `url` (where its button posts), and `expires` and `signature` (posted in the body). See [Email Verification](protected-changes.md#email-verification). |
| `email-change` | `action` (`confirm` or `revert`), `url` (where its button posts), and `token` (posted in the body). See [Protected Changes](protected-changes.md#the-emailed-links). |
| `device-report` | `device` (a description), `url` (where its button posts), and `expires` and `signature` (posted in the body). See [The "This Wasn't Me" Link](devices-and-sessions.md#the-this-wasnt-me-link). |

With Inertia installed, each page renders the component `auth/{name}`, such as `auth/login`. Without Inertia, Keyring renders the Blade view `auth.{name}`, such as `resources/views/auth/login.blade.php`, and passes the props as view data. Keyring doesn't ship Blade views, so you'll need to write them. Until you do, the page throws a `Keyring\Exceptions\MissingPage` exception that names the view to create and the data it receives.

Inertia only notices a missing component in the browser, unless you turn on `pages.ensure_pages_exist` in `config/inertia.php`. With that option on, Keyring throws the same exception, naming the component.

A request for a page that expects JSON, and isn't an Inertia visit, gets the page's name and props instead, with the status and headers the page would have had. Laravel counts an XHR (`X-Requested-With: XMLHttpRequest`) that accepts anything as expecting JSON too, the way jQuery's `$.get()` sends it:

```json
{
  "page": "reset-password",
  "props": { "token": "...", "email": "taylor@example.com" }
}
```

That's for a frontend Laravel doesn't serve, such as a Nuxt app, which builds each page itself. A JSON request never throws `MissingPage`, and isn't noted as the page to go back to. If every page lives in such a frontend, set [`pages`](configuration.md#pages) to `false`, and anything but JSON is answered with a `404`. See [Headless Frontends](headless.md).

If a form on one of these pages fails validation, the user comes back to that page. Keyring notes each page it renders as the one to return to, for browsers that send no `Referer` at all, since Laravel doesn't remember an Inertia visit as the last page seen. You don't need Inertia's `store_previous_url` option for Keyring's pages.

To change the component for a page, use `Keyring::page`:

```php
Keyring::page('challenge', 'Auth/TwoFactor');
```

Or you may pass a closure that receives the props and returns a response:

```php
Keyring::page('login', fn (array $props) => response()->view('marketing.login', $props));
```

A closure can return anything a route can return, such as a response, a view, or a string. It answers JSON requests for the page too, and still renders with `pages` set to `false`, so a closure is also how you change what a JSON client gets.

`challenge` and `confirm` are separate pages, so overriding `challenge` with `Keyring::page` doesn't change step-up. Override `confirm` too. A `confirm` page can render your `challenge` page with its props.

## Events

Every event here lives in the `Keyring\Events` namespace:

| Event | When | Properties |
|---|---|---|
| `Attempting` | A verification starts. | `request`, `factor` (key), `purpose` |
| `FactorChallenged` | The challenge page shows a factor. | `attempt`, `authenticator` |
| `FactorVerified` | A factor's proof was right. | `attempt`, `authenticator`, `verification` |
| `ProviderIdentityAccepted` | An [identity provider](sso.md#hearing-about-accepted-identities)'s account was accepted as the user's link, for a sign in, a confirm, or a link. For a sign in or a confirm it fires before the rest of the pipeline, so a second factor may still be asked for. | `user`, `authenticator`, `identity` (`Keyring\Sso\Identity`), `purpose` (`login`, `confirm`, or `link`) |
| `FactorFailed` | A factor's proof was wrong, or the user wasn't found. | `attempt` (nullable), `authenticator` (nullable), `factor`, `request` |
| `Lockout` | A rate limit was hit. It's dispatched for each request the limit refuses. | `request`, `factor`, `retryAfter` (`null` when waiting won't help) |
| `VerificationRefused` | The final gate refused because a [mandatory step](#mandatory-steps) hadn't run. | `attempt`, `factor`, `skipped` |
| `AccountLocked` | A factor that can start a sign in is refused for the account until a password reset. This happens when it reached the cap on failures in a row, or when `limits.lock_after` held it. | `user`, `factor` |
| `Authenticated` | A login completed. | `user`, `attempt`, `device` |
| `Confirmed` | A step-up completed. | `user`, `attempt` |
| `LoggedOut` | The user signed out. | `user` |
| `SessionEnded` | Keyring signed a session out on its own: revoked, timed out, or ended by a risk response. | `user`, `reason` |

Laravel's own `Login`, `Logout`, and `Registered` events still fire, because Keyring signs users in and out through the guard. Keyring also dispatches Laravel's other auth events alongside its own, so listeners and packages built for them keep working:

| Laravel Event | Dispatched With |
|---|---|
| `Illuminate\Auth\Events\Failed` | `FactorFailed`. Its credentials hold only the username field, never the password or code. That's the user's own when one was found. Otherwise it's what was typed, for a factor that asks for a username, such as the password, and `null` for one that doesn't, such as an identity provider's callback. |
| `Illuminate\Auth\Events\Lockout` | `Lockout`, so once for every refused request. |
| `Illuminate\Auth\Events\PasswordReset` | Keyring's `PasswordReset`. |
