# Events

- [Introduction](#introduction)
- [Signing In and Confirming](#signing-in-and-confirming)
- [Sessions and Devices](#sessions-and-devices)
    - [Why a Registered Session Ended](#why-a-registered-session-ended)
- [Authenticators](#authenticators)
- [Account Changes](#account-changes)
- [Risk](#risk)
- [Refusals](#refusals)
- [Laravel's Auth Events](#laravels-auth-events)

## Introduction

Every event lives in the `Keyring\Events` namespace, and its data is stored in public readonly properties. To listen for them, use the same approach you would for any Laravel event. For example, this listener saves the time of each sign in:

```php
use Illuminate\Support\Facades\Event;
use Keyring\Events\Authenticated;

Event::listen(function (Authenticated $event) {
    $event->user->update(['last_signed_in_at' => now()]);
});
```

The `user` property is always an instance of your user model. Keyring fires events whether or not a feature that reacts to them is turned on. The [security log](security-log-and-emails.md) and the [security emails](security-log-and-emails.md#security-emails) are listeners for these same events, so your own listeners don't need either one.

No event has a password, code, or token among its properties, apart from the registry ID in the `session` of `SessionResumed` and `RememberMeReused`, and the spent state, nonce, and code verifier in `ProviderIdentityAccepted`'s `identity->request`, which a listener in the request sees and a queued one doesn't (see below). `Attempting`, `FactorFailed`, and `Lockout` carry the request as it arrived, including whatever the user typed. Don't log or serialise that request in full, and don't queue a listener for those three events. Laravel's `Failed`, which Keyring dispatches with `FactorFailed`, carries your user model as it is, so don't queue a listener for it either.

Keyring's other events don't put a password hash, a secret, or a "remember me" value on your queue. A queued listener gets the `user` back from the database by its ID, as with any Laravel event that uses `SerializesModels`. An `attempt` is queued as its plain data and looks its user up again when you call `user()`. If the user has been deleted by then, `attempt->user()` and `attempt->keyring()` throw `AttemptExpired`. That happens in your listener, after the job has been restored, so `deleteWhenMissingModels` doesn't cover it: catch it, or let the job fail. `AuthenticatorRemoved` queues the deleted authenticator without its `secret`. `FactorChallenged` and `FactorVerified` queue a stored `authenticator` by its ID, so a queued listener gets it fresh from the database. An unsaved authenticator, such as the password's, has nothing stored to look up, so it's queued as it is, without a `secret` or the user loaded with it. `authenticator->user()` looks the user up again, and throws a `LogicException` if they have been deleted.

`ProviderIdentityAccepted` carries the provider's `Identity`, whose `request` holds the state, nonce, and PKCE code verifier of a sign in that's over and can't be used again. A listener in the request sees them, and a queued listener gets the request with all three blank, and the claims without the ID token's `nonce`, `at_hash`, and `c_hash`. Only serialising the event leaves them out: Telescope's event watcher, or a `dump()` or `json_encode()` of the event, still sees them. Its `identity->claims` are everything the provider sent about the user, so log them with the care you'd give the user's profile. The same goes for the `providerAcr` and `providerAmr` the provider sent: escape them where you print them.

`SessionResumed` and `RememberMeReused` carry a `RegisteredSession` whose `id` is the ["remember me" cookie](devices-and-sessions.md#remember-me)'s value. A listener in the request sees it, but a queued listener gets the record without any of its registry IDs: a blank `id`, and a null `replacedBy` and `origin`. Both events always carry the session's `handle` as well, worked out from the full record when the event is made. It's the same one the [sessions list](devices-and-sessions.md#listing-and-ending-sessions) shows, so use that to tell sessions apart. `Sessions::find($user, $event->handle)` turns it back into the session while it's still active. Don't call `Sessions::handle()` on the queued record: with its IDs gone it has no handle, and it throws a `LogicException`. Only serialising the event leaves the IDs out. Anything that reads the event's properties directly, such as Telescope's event watcher or a `dump()` or `json_encode()` of the event, still sees it.

## Signing In and Confirming

| Event | When | Properties |
|---|---|---|
| `Attempting` | A factor is about to be checked. | `request`, `factor` (its key), `purpose` |
| `FactorChallenged` | The challenge page showed a factor. | `attempt`, `authenticator` |
| `FactorVerified` | A factor's proof was right. | `attempt`, `authenticator`, `verification` |
| `ProviderIdentityAccepted` | An [identity provider](sso.md#hearing-about-accepted-identities)'s account was accepted as the user's link, for a sign in, a confirm, or a link. For a sign in or a confirm it fires before the rest of the pipeline, so a second factor may still be asked for. | `user`, `authenticator`, `identity` (`Keyring\Sso\Identity`), `purpose` (`login`, `confirm`, or `link`) |
| `FactorFailed` | A factor's proof was wrong, or the user wasn't found. It also fires for a wrong proof sent to [make a change while sign-in methods are frozen](authenticators.md#making-a-change-with-an-established-key), a wrong [password for a first second factor](authenticators.md#the-password-for-a-first-second-factor), and a wrong password for [removing the last one](authenticators.md#removing-authenticators), with a `Confirm` attempt. | `attempt` (null when the user wasn't found), `authenticator` (nullable), `factor`, `request` |
| `Lockout` | A rate limit was hit. This includes an account's own limit refusing a sign in, which is answered like a wrong password. It's dispatched for every request the limit refuses, a password or proof checked inside a change to sign-in methods included. The [security log](security-log-and-emails.md#refusals-that-repeat) notes it once per lock. | `request`, `factor`, `retryAfter` (in seconds, or `null` when waiting won't help, meaning the factor stays refused until its failures in a row are cleared) |
| `AccountLocked` | Failed attempts have caused a factor that can start a sign in to be refused for the account until a password reset or `Keyring::unlock()`. This happens when the factor used up its failures in a row, or when `limits.lock_after` held it. Browsers the account has signed in from may still get in. | `user`, `factor` |
| `Authenticated` | A login completed, and the user was signed in. | `user`, `attempt`, `device` (null without `Features::devices()`) |
| `Confirmed` | A [step-up](step-up.md) completed. | `user`, `attempt` |
| `LoggedOut` | The user signed out. | `user` |

`purpose` is the `Keyring\Enums\Purpose` enum, either `Login` or `Confirm`. `FactorChallenged`, `FactorVerified`, and `FactorFailed` fire for both purposes, so check `$event->attempt?->purpose` when a listener should only react to sign ins. On `FactorFailed`, `attempt` is null when the user wasn't found. Its `afterFirstFactor()` says whether a later step failed once the login's first step had passed, `afterPassword()` whether that first step was the password, as opposed to an [identity provider](sso.md), and `firstFactor()` gives that first step's `Verification`. See [The Sign In Flow](sign-in-flow.md#events).

## Sessions and Devices

| Event | When | Properties |
|---|---|---|
| `NewDeviceSignedIn` | Someone signed in from a device the account hasn't used before. | `user`, `device`, and `revokeUrl($days = null)`. The link is valid for `devices.report_link_for` unless you pass a number of days. It's the ["this wasn't me" link](devices-and-sessions.md#the-this-wasnt-me-link). |
| `DeviceRevoked` | A device was signed out. | `user`, `device`, `reported` (true when it came from the "this wasn't me" link) |
| `SessionsRevoked` | Sessions were signed out. This happens with "sign out everywhere else", when one session is ended from the sessions list, when an administrator runs `keyring:sign-out` for the user, or on the first request refused for an account [the application keeps out](sign-in-flow.md#who-may-sign-in). | `user`, `count` |
| `SessionEnded` | Keyring signed a session out on its own. | `user`, `reason`: `revoked`, `expired`, `idle`, `other_user`, `reused`, `risk`, or `not_allowed` |
| `RegisteredSessionEnded` | A registered session ended, whoever ended it and wherever. There's one for each record the registry revoked. | `handle`, `handles`, `userId`, `userType`, `guard`, `deviceId`, `endedAt`, `reason` (see [below](#why-a-registered-session-ended)) |
| `EveryoneSignedOut` | Every user's sessions ended at once, with `keyring:sign-out --all` or the registry's `revokeEveryone()`. | `at` (every session that signed in up to this Unix timestamp ended). It's a cut-off on sign-in time, and the event may come late, from the sweep: see [Hearing About Ended Sessions](devices-and-sessions.md#hearing-about-ended-sessions). |
| `SessionResumed` | ["Remember me"](devices-and-sessions.md#remember-me) signed a browser back in after its session had gone unused. Nothing was proved. | `user`, `session` (the `RegisteredSession` it carries on as), `handle` (the session's handle) |
| `ImpersonationStarted` | Someone signed in as another user. The user's own `Login` and `Authenticated` don't fire. See [Impersonation](impersonation.md#security-log-and-events). | `impersonator`, `user`, `handle` (the impersonated session's handle) |
| `ImpersonationEnded` | An impersonation ended, in the request of the browser that was impersonating: it stopped, ran out, or found it had ended. Once, however many of its requests find it over at once. | `impersonator` (null once deleted), `user` (the user who was impersonated, null once they can no longer be loaded), `reason` (a `Keyring\Enums\ImpersonationEndReason`: `stopped`, `expired`, `revoked`, `impersonator_session_ended`, `lost`, or `signed_out`, never `failed`, which is only logged), `returned` (whether the browser went back to the impersonator's session), `handle` (the impersonated session's handle, as `ImpersonationStarted` gave it, or `null` when nothing says which session it was) |
| `RememberMeReused` | A ["remember me" cookie was used twice](devices-and-sessions.md#a-cookie-used-twice). This means two browsers held the same cookies, so the session was ended for both. | `user`, `session` (the `RegisteredSession` that was ended. Its device, IP address, and user agent belong to whoever used the cookie first.), `handle` (the session's handle) |

A user who signs out on purpose triggers `LoggedOut`, not `SessionEnded`. The request that brought a used cookie also gets a `SessionEnded` with `reused`. `RememberMeReused` fires once, when there was still a session to end, or when the session it was carried on to has timed out since. See [Devices & Sessions](devices-and-sessions.md#events).

### Why a Registered Session Ended

`SessionEnded` only fires in the request of the browser that was signed out. `RegisteredSessionEnded` fires for every registered session that ends, in that request or any other, so code that has to hear about each one listens for it. It's how a single sign-on provider built on Keyring knows to log the user out of its client applications. See [Hearing About Ended Sessions](devices-and-sessions.md#hearing-about-ended-sessions) for when it fires and what it promises.

Its properties are plain values, so it's safe to queue a listener for it:

| Property | Holds |
|---|---|
| `handle` | The session's [handle](devices-and-sessions.md#listing-and-ending-sessions) under the current `APP_KEY`. It's the same handle the session had before it moved to a new record. |
| `handles` | The handle under the current key and then under each key in `APP_PREVIOUS_KEYS`, so a handle you stored before a key rotation still matches one of them. |
| `userId` | The user's ID, as a string. |
| `userType` | The connection and table the ID is unique in, such as `mysql:users`. It's not a class name. Compare it with `RegisteredSession::typeOf($user)`. |
| `guard` | The guard the session signed in on. |
| `deviceId` | The ID of the session's device, or `null`. |
| `endedAt` | When it was revoked, as a Unix timestamp. |
| `reason` | A `Keyring\Enums\SessionEndReason`. |

It never carries the session's registry ID. That ID is what the browser's "remember me" cookie holds.

Laravel stops calling an event's listeners at the first that throws or returns `false`, so a listener registered before yours can stop yours hearing it. A handle also stops matching when the app key is rotated without `APP_PREVIOUS_KEYS`. Don't rely on this event alone to end sessions elsewhere: see [Hearing About Ended Sessions](devices-and-sessions.md#hearing-about-ended-sessions).

The reasons, and what gives each one:

| Reason | Given When |
|---|---|
| `logged_out` | The user signed out, with `POST /logout` or by ending the current session from the sessions list. Also a sign-out your app does itself with `Auth::logout()` or `Auth::logoutCurrentDevice()` on Keyring's guard, such as a Breeze, Jetstream or Filament logout route, unless you end it inside `app(Sessions::class)->because(...)` with a reason of your own. Laravel's `auth.session` middleware signs a browser out with `logoutCurrentDevice()` when the user's password changed elsewhere, so a session it ends is announced as `logged_out` too. |
| `signed_out_everywhere` | "Sign out everywhere else" from the sessions or devices page, or after adding or removing a sign-in method with `sign_out_others`. An administrator's `keyring:sign-out` for one user gives it too. |
| `revoked` | One session was ended from the sessions list. A sign in that's refused at the last step ends the session it had just registered with this reason too: when the password, email address, or sign-in methods changed while it was being checked, and when something failed as the session was being set up. It's also the reason for any revocation Keyring didn't name, such as your own call to `Sessions::signOutEverywhere()` or to the registry, and for a reason of your own that a subclass of the session middleware signs out for. Your app's own `Auth::logout()` is `logged_out`, not this. |
| `signed_in_again` | The browser signed in again while it was signed in, and left the session it was on. |
| `device_revoked` | The session's device was signed out from the devices list. |
| `device_reported` | The session's device was reported with the ["this wasn't me" link](devices-and-sessions.md#the-this-wasnt-me-link). |
| `device_limit` | Its device was forgotten to keep the account to [`devices.limit`](devices-and-sessions.md#devices). |
| `session_limit` | A new sign in took the account past [`sessions.max`](devices-and-sessions.md#how-many-sessions), and this session had gone unused longest. |
| `account_deleted` | The user was deleted, soft deleted or for good. |
| `password_changed` | The user changed their password, and their other sessions were signed out. |
| `password_reset` | The password was reset from a reset link. |
| `email_changed` | The email address changed, and the other sessions were signed out (`email_changes.sign_out_others`). |
| `email_change_undone` | The old address undid an email change. |
| `risk` | A [risk response](risk.md#actions) ended the session, or every session of the account. |
| `idle` | The session middleware found the session had gone unused for too long, or [`keyring:sweep`](devices-and-sessions.md#sweeping-ended-sessions) ended it for that. |
| `expired` | The session middleware found the session past its absolute limit, or the sweep ended it for that. With `sessions.end_on_lapse`, a "remember me" cookie that can't carry the session on gives it too. |
| `other_user` | The session middleware found the session's record belongs to another user. The event names the record's user. |
| `reused` | The session's ["remember me" cookie was used twice](devices-and-sessions.md#a-cookie-used-twice). |
| `not_allowed` | The application stopped letting the user sign in ([`Keyring::allowSignInWhen`](sign-in-flow.md#who-may-sign-in)). |
| `impersonation_ended` | An [impersonation](impersonation.md) ended: the session someone was signed in to as the user, and the impersonator's own parked session when the browser was signed out rather than going back to it. |

The event is at least once. With [the sweep](devices-and-sessions.md#sweeping-ended-sessions) on, a session whose event was lost is announced again, and one a listener failed for is tried again, so the same handle can come more than once. A session announced again has the reason it ended for, or `revoked` when that wasn't kept. Make listeners idempotent by handle.

When one action ends sessions for several reasons at once, the session gets the one closest to the code that ended it. For example, a risk response that signs out everywhere gives `risk`, not `revoked`.

## Authenticators

| Event | When | Properties |
|---|---|---|
| `AuthenticatorAdded` | The user added a sign-in method. | `user`, `authenticator` |
| `AuthenticatorRemoved` | The user removed one. | `user`, `authenticator` |
| `RecoveryCodesGenerated` | New recovery codes were made, and the old ones stopped working. | `user`, `authenticator` |
| `RecoveryCodeUsed` | A recovery code was used. | `authenticator`, `remaining` |
| `CloneSuspected` | A passkey or security key's counter went backwards, so the sign in was refused. | `authenticator` |

Confirming the `recovery` factor dispatches `RecoveryCodesGenerated` instead of `AuthenticatorAdded`. When an event has no `user` property, the owner is `$event->authenticator->user()`. See [Managing Authenticators](authenticators.md#events) and [Counters and Cloned Keys](passkeys.md#counters-and-cloned-keys).

## Account Changes

| Event | When | Properties |
|---|---|---|
| `EmailChangeRequested` | An email change was requested, and its links were sent. | `user`, `change` |
| `EmailChanged` | The email address changed. The old address can still revert the change for a while. | `user`, `change` |
| `EmailChangeReverted` | The old address undid a change. Every session was signed out. | `user`, `change` |
| `PasswordChanged` | The user changed their password. | `user` |
| `PasswordReset` | The password was reset from a reset link. Every session was signed out. | `user` |
| `PasswordChangeRequired` | A user was [held until they choose a new password](protected-changes.md#requiring-a-password-change). | `user`, `reason` (nullable) |
| `ProtectionBypassed` | Protected attributes were changed with [`Keyring::withoutProtection`](protected-changes.md#bypassing-protection). | `reason` (nullable) |

The `change` property is a `Keyring\Models\PendingChange`. Its tokens and addresses are hidden when it's serialised. See [Protected Changes](protected-changes.md#events).

## Risk

| Event | When | Properties |
|---|---|---|
| `RiskAssessed` | Keyring assessed the risk, and the action did something. | `user`, `risk`, `action`, `checkpoint` (`Checkpoint::Login` or `Checkpoint::Request`) |

An assessment that ends in `Action::allow` dispatches nothing. See [Risk](risk.md#events-and-logging).

## Refusals

| Event | When | Properties |
|---|---|---|
| `AccessRefused` | A signed-in user asked for an authenticator, device, or session that isn't theirs, or that doesn't exist. Both cases get the same 404, so the event doesn't tell them apart. The event also fires when someone opens an email verification link made for another account. | `user`, `resource` (`authenticator`, `device`, `session`, or `email_verification`), `id` (what was asked for, as it was sent. For a session, this is its handle.) |
| `RateLimited` | The form limiter refused a request to one of Keyring's routes, outside the sign-in limits. This covers registration, a reset, a change, an emailed link or the page it opens, and passkey options. | `user` (whoever is signed in, otherwise null), `limiter` (`keyring`, `keyring-pages`, or `keyring-login-options`), `route` (its name, or `null` for a route without one), `retryAfter` (in seconds) |
| `EnrollmentRefused` | A sign-in method wasn't added. | `user`, `factor`, `reason`: `invalid` (the factor turned the confirmation down, such as with a wrong code, a key it won't take, or an identity provider's account that's linked to someone else), `not_allowed` (the account may not add one yet), `frozen` (it would have replaced recovery codes or a sign-in method while they're [frozen](authenticators.md#frozen-sign-in-methods)), or `password` (it needed [the password](authenticators.md#the-password-for-a-first-second-factor) and didn't have the right one) |
| `AuthenticatorRemovalRefused` | A sign-in method was kept, because removing it would have left the user unable to sign in the way their policy requires, or because the account's sign-in methods are [frozen](authenticators.md#frozen-sign-in-methods). | `user`, `authenticator`, `reason` (`last_factor` or `frozen`) |
| `LinkRefused` | An emailed link was refused. This happens for a change that doesn't exist, a wrong or ended token, or a signature that didn't match or had expired. | `link`, `reason` (see [Refused Links](security-log-and-emails.md#refused-links)), `user` (whose email change it was, otherwise null) |
| `VerificationRefused` | A sign in or step-up met its requirement but was still refused, because a [mandatory step](sign-in-flow.md#mandatory-steps) hadn't run for the request. | `attempt`, `factor`, `skipped` (the steps' class names) |

None of these changes what the refused person sees. Each one fires every time, however often it's repeated. Only the [security log](security-log-and-emails.md#refusals-that-repeat) limits how many it writes down. A form that fails ordinary validation dispatches nothing.

That makes these events the right place to count from. Keyring keeps no metrics of its own, so if you watch for credential stuffing, you may feed your counters from a listener. To act on it at sign in instead, turn on the [`CredentialStuffing`](risk.md#built-in-signals) risk signal, which flags a sign in from an address where many other accounts have failed:

```php
use Illuminate\Support\Facades\Event;
use Keyring\Events\FactorFailed;
use Keyring\Events\Lockout;
use Keyring\Events\RateLimited;

Event::listen(fn (FactorFailed $event) => Metrics::increment('auth.failed', ['factor' => $event->factor]));
Event::listen(fn (Lockout $event) => Metrics::increment('auth.locked_out', ['factor' => $event->factor]));
Event::listen(fn (RateLimited $event) => Metrics::increment('auth.rate_limited', ['route' => $event->route ?? 'unnamed']));
```

`Metrics` stands for whatever your application reports to.

## Laravel's Auth Events

Keyring signs users in and out through the guard, so Laravel's `Login`, `Logout`, `Registered`, and `Verified` events fire as usual. `Registered` is dispatched once the response has been sent, unless [`registration.reveal_taken`](sign-in-flow.md#registration) is on. That way, the verification email it sends doesn't show up in how long a new address takes to get an answer. Keyring also dispatches these events alongside its own, so listeners and packages built for them keep working:

| Laravel Event | Dispatched With |
|---|---|
| `Illuminate\Auth\Events\Failed` | `FactorFailed`. Its credentials hold only the username field, never the password or code. That's the user's own when one was found. Otherwise it's what was typed, for a factor that asks for a username, such as the password, and `null` for one that doesn't, such as an identity provider's callback. |
| `Illuminate\Auth\Events\Lockout` | `Lockout`, so once for every refused request. |
| `Illuminate\Auth\Events\PasswordReset` | Keyring's `PasswordReset`. |
