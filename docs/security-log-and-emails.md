# Security Log & Emails

- [Introduction](#introduction)
- [The Security Log](#the-security-log)
    - [Without the Table](#without-the-table)
    - [Entry Types](#entry-types)
    - [Severity](#severity)
    - [Request IDs](#request-ids)
    - [Times](#times)
    - [Refusals That Repeat](#refusals-that-repeat)
    - [Refused Links](#refused-links)
    - [Showing Recent Activity](#showing-recent-activity)
    - [Pruning](#pruning)
    - [What's Stored](#whats-stored)
- ["Was This You?" Alerts](#was-this-you-alerts)
- [Security Emails](#security-emails)
    - [Email Types](#email-types)
    - [A Support Contact](#a-support-contact)
    - [Emails a Flow Needs](#emails-a-flow-needs)
    - [Your Own Templates](#your-own-templates)
    - [Slack, SMS and Other Channels](#slack-sms-and-other-channels)
    - [Sending Something Else Entirely](#sending-something-else-entirely)
- [Laravel's Auth Events](#laravels-auth-events)

## Introduction

Keyring keeps a record of what happens to your users' accounts, and it sends emails when something important changes. This page explains the security log, the "was this you?" alerts that the log can trigger, and the security emails Keyring sends to your users. It also covers the emails that a sign in or account change needs in order to work, and how to customise any of them.

## The Security Log

Keyring records sign ins, failures, lockouts, refusals, changes, and automatic actions in the `keyring_events` table, as `Keyring\Models\SecurityEvent` rows. Each entry has a `type`, a `severity`, the user (when it's known), the `factor`, the `device_id`, the IP address, the user agent, a `request_id`, `meta`, `created_at`, and `seen_at`. Keyring sets `seen_at` when it returns an alert to the user, so the same alert isn't returned again.

The log never holds passwords, codes, tokens, signatures, session IDs, or anything else from the request body.

While someone is [impersonating](impersonation.md#security-log-and-events) a user, the requests are the impersonator's. So any entry written on the user's account in those requests has no IP address or user agent, and neither do the `impersonation_started` and `impersonation_ended` entries on the user's account. The impersonator's own entries keep them.

The security log is turned on by default. The `Features::securityLog()` feature is part of Keyring's default features, and the `keyring:install` command includes it in your list unless you leave it out. You can configure the log with these options:

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
```

The log never gets in the way of a sign in. If a write fails, Keyring passes the error to `report`, writes the entry to [your application's log](#without-the-table) instead, and carries on, so the sign in, refusal, or email still goes ahead. If the log can't be read, there are no alerts, and the `RepeatedFactorFailures`, `SuccessAfterFailures`, and `CredentialStuffing` risk signals find nothing.

There is one exception. If the `protection_bypassed` entry can't be written, [`Keyring::withoutProtection()`](protected-changes.md#bypassing-protection) throws an exception before it runs your callback. So a bypass never happens without being logged.

### Without the Table

If you remove `Features::securityLog()` from your features, nothing is written to the `keyring_events` table. The events are still recorded, though. Each one becomes a line in your application's log, so there's never a moment when nothing is recorded. Each line is written as `Keyring: {type}` at the entry's [severity](#severity). It includes `at` (the time, [with its offset](#times)), the user (as `{morph class}:{id}`), `factor`, `device_id`, `ip`, `user_agent`, `request_id`, and `meta` as its context. The `channel` option names the log channel to use, and `null` selects your default channel:

```php
// config/logging.php
'security' => ['driver' => 'daily', 'path' => storage_path('logs/security.log'), 'days' => 180],
```

```ini
KEYRING_LOG_CHANNEL=security
```

How long those lines are kept, and who can read them, is up to that channel. The ["was this you?" alerts](#was-this-you-alerts), the [`Keyring::activity`](#showing-recent-activity) method, and the `RepeatedFactorFailures`, `SuccessAfterFailures`, and `CredentialStuffing` risk signals all read from the table, so they require the feature to be turned on.

### Entry Types

| Type | Severity | When | `meta` |
|---|---|---|---|
| `signed_in` | info | A login completed. | `factors` |
| `confirmed` | info | A step-up completed. | `factors` |
| `factor_failed` | warning | A factor failed. | |
| `second_factor_failed` | warning | A factor failed during a login, after a correct password or another first step of the same kind, such as a sign in with an [identity provider](sso.md). | |
| `locked_out` | warning | A rate limit started refusing an IP address for a factor. This happens whether the answer said so or was that of a wrong password. The entry is [logged once](#refusals-that-repeat), not for each request that's refused. It isn't linked to a user. | `retry_after` |
| `rate_limited` | warning | The [form limiter](configuration.md#pending-logins-timebox-and-rate-limits) started refusing requests to one of Keyring's other routes: registration, a reset, a change, an emailed link or the page it opens, or passkey options. It's [logged once](#refusals-that-repeat) for each wait, per route. It's linked to the signed-in user when there is one. | `limiter` (`keyring`, `keyring-pages` or `keyring-login-options`), `route` (its name), `retry_after` |
| `account_locked` | warning | Failed attempts got the password or a passkey refused until a password reset. This happens when the cap on failures in a row is reached, or when `limits.lock_after` is reached. | |
| `signed_out` | info | The user signed out. | |
| `authenticator_added`, `authenticator_removed` | notice | | `name` |
| `recovery_codes_generated` | info | | |
| `recovery_code_used` | notice | | `remaining` |
| `new_device` | notice | A sign in from a new device. | `device` |
| `device_revoked` | info | A device was signed out. | `device` |
| `device_reported` | warning | A device was signed out from the "this wasn't me" link. | `device` |
| `sessions_revoked` | info | "Sign out everywhere else" was used, one session was ended from the sessions list, an administrator ran `keyring:sign-out` for the user, or the first request was refused for an account [the application keeps out](sign-in-flow.md#who-may-sign-in). | `count` |
| `session_ended` | info | Keyring signed a session out on its own. | `reason`: `revoked`, `expired`, `idle`, `other_user`, `reused`, `risk` or `not_allowed` |
| `session_resumed` | info | ["Remember me"](devices-and-sessions.md#remember-me) signed a browser back in after its session had gone unused. Nothing was proved, which is why this isn't a `signed_in` entry. | |
| `remember_me_reused` | warning | A ["remember me" cookie was used twice](devices-and-sessions.md#a-cookie-used-twice), and the session ended for both browsers. The entry's address and user agent come from the request that brought the used cookie. `device_id` is the device the ended session was on. | `device` |
| `email_change_requested` | info | | |
| `email_changed` | notice | | |
| `email_change_reverted` | warning | | |
| `password_changed` | notice | | |
| `password_reset` | notice | A reset completed, and cleared the account's [sign-in lockouts](security.md#rate-limiting). | `sign_in_locks_cleared` |
| `protection_bypassed` | warning | `Keyring::withoutProtection` was used. It's linked to the signed-in user who did it. | `reason` |
| `clone_suspected` | critical | A passkey or security key's counter went backwards. | `name` |
| `risk_step_up`, `risk_reauthenticate`, `risk_notified`, `risk_password_change` | notice | A risk action did something. `risk_password_change` means the user is being [held until they choose a new password](protected-changes.md#requiring-a-password-change). | `checkpoint`, `score`, `reasons` |
| `risk_denied`, `risk_locked`, `risk_revoked_sessions` | warning | A risk action refused, locked, or signed out. | `checkpoint`, `score`, `reasons` |
| `access_refused` | warning | A signed-in user asked for an authenticator, device, or session that isn't theirs, or that doesn't exist. Either way the response is a 404. The entry is also written when the user opens an email verification link made for another account, which gets a 403. | `resource` (`authenticator`, `device`, `session` or `email_verification`), `id` (what was asked for, cut to 64 characters; for a session, its [handle](devices-and-sessions.md#listing-and-ending-sessions), never its registry ID) |
| `enrollment_refused` | warning | A sign-in method wasn't added. | `reason`: `invalid` (the factor turned the confirmation down, for example a wrong code or a key it won't accept), `not_allowed` (the account [may not add one yet](authenticators.md#who-may-enroll)), `frozen` (it would have replaced recovery codes or a sign-in method while they're [frozen](authenticators.md#frozen-sign-in-methods)), or `password` (it needed [the password](authenticators.md#the-password-for-a-first-second-factor) and didn't have the right one) |
| `authenticator_removal_refused` | warning | A sign-in method was kept, because removing it would have left the user unable to sign in the way their policy requires, or because the account's sign-in methods are [frozen](authenticators.md#frozen-sign-in-methods). | `name`, `reason` (`last_factor` or `frozen`) |
| `link_refused` | warning | An emailed link was refused. It's linked to the user whose email change it was, when there is one. | `link` and `reason`, [below](#refused-links) |
| `verification_refused` | critical | A sign in or step-up was refused at the end, because a [mandatory step](sign-in-flow.md#mandatory-steps) hadn't run for the request. | `skipped`, the steps |
| `refusals_limited` | warning | The entries above this one stopped being written for a while. See [Refusals That Repeat](#refusals-that-repeat). | `type`, the entry type that was left out |
| `impersonation_started` | notice | Someone signed in as another user. It's logged on both accounts, with no IP address or user agent on the user's. See [Impersonation](impersonation.md#security-log-and-events). | `impersonator` and `user` (the two accounts' IDs), `role` (`impersonator` or `impersonated`, for the entry's account) |
| `impersonation_ended` | info | An impersonation ended. It's logged on both accounts, or on the other's alone once one of them has been deleted, with no IP address or user agent on the user's. | `impersonator`, `user`, `role`, `reason` (`stopped`, `expired`, `revoked`, `impersonator_session_ended`, `lost`, `signed_out` or `failed`), `returned` (whether the browser went back to the impersonator's session, or stayed theirs for `failed`) |
| `impersonation_refused` | warning | A start of an [impersonation](impersonation.md#security-log-and-events) was refused. It's logged on the impersonator's account. | `reason` (an [`ImpersonationRefusal`](impersonation.md#from-your-own-code) value: `disabled`, `no_callback`, `self`, `not_allowed`, `impersonating`, `unregistered`, or `not_found` for an ID nobody has, which gets the same `403` as `not_allowed`), `user` (the ID asked for, cut to 64 characters) |

A wrong password for an unknown account is logged as `factor_failed`, with no user.

Form validation errors aren't logged. A missing field or a malformed address is an ordinary mistake, not an attempt on anything.

### Severity

Every entry has one of four severities. They're stored in the entry's `severity` column, as the `Keyring\Enums\Severity` enum. The severities are PSR-3 log levels, so an entry written to a [log channel](#without-the-table) goes out at its own level, and a channel's `level` setting filters them the same way it filters anything else:

| Severity | Means |
|---|---|
| `info` | Someone did what they were allowed to do. |
| `notice` | How the account signs in has changed, or something is worth a look if it wasn't expected. |
| `warning` | Something failed or was refused, or looks like someone else at work. |
| `critical` | A sign-in method or a safeguard can't be relied on. Examples are a cloned key, or a pipeline that let a request past a mandatory step. |

The `Severity::of` method gives you the severity of a type. An entry type of your own is `info`, unless you say otherwise:

```php
use Keyring\Activity\SecurityLog;
use Keyring\Enums\Severity;

app(SecurityLog::class)->record('exported_data', $user, severity: Severity::Notice);
```

To be told about the most serious entries as they happen, you may query for them, or send the log to a channel that raises alerts:

```php
SecurityEvent::query()->where('severity', Severity::Critical)->where('created_at', '>', now()->subDay())->get();
```

### Request IDs

Every entry a request writes has the same `request_id`. A failed second factor, the lockout it caused, and the email it sent can then all be read together:

```php
SecurityEvent::query()->where('request_id', $event->request_id)->oldest('id')->get();
```

The ID comes from Laravel's [Context](https://laravel.com/docs/context) feature. If your application already names its requests there, as Laravel's own documentation does with `trace_id`, Keyring uses your ID and never creates a second one:

```php
// A middleware of yours
Context::add('trace_id', (string) Str::uuid());
```

Set `security_log.context_key` to the key you use, whether or not it's hidden. Then your own log lines for the request carry the same ID as its entries, and so does any queued job the request dispatched. When no ID is present, Keyring creates a UUID for the request and keeps it in the hidden context, so it adds nothing to your log lines. An ID longer than 64 characters is cut to fit. Set the key to `null` to leave `request_id` empty.

### Times

An entry's `created_at` is a plain timestamp in your application's timezone (`app.timezone`), the same as every Laravel timestamp. The column doesn't store an offset. This means that an application set to a local timezone logs local times that can't be told apart from UTC by looking at the table alone. Leave `app.timezone` set to `UTC`. That's Laravel's default, and it's what OWASP ASVS 5.0.0 (16.2.2) recommends for a log. Convert the times when you display them. If your timezone isn't UTC, say so wherever the table is read or copied.

An entry written to [your application's log](#without-the-table) carries its time with its offset, stored as `at`, such as `2026-11-08T14:05:09+00:00`. Laravel stamps a log line without an offset, which is why this matters. Keeping your servers' clocks in step is up to you.

### Refusals That Repeat

Anyone who is refused can ask again as often as they like, and entries are kept for months. To keep a refusal from filling the table one request at a time, Keyring limits how often refusals are written:

- **A lock is logged when it starts.** `locked_out` is written once per factor and IP address, and not again until the wait that the lock imposed is over. Every request it refuses in the meantime still dispatches the `Lockout` event (and Laravel's own `Lockout` event), so your listeners see each one. `rate_limited` works the same way for the form limiter. It's written once per route, for the account or IP address being refused, until that limiter has room again. The `RateLimited` event is dispatched for every refused request.
- **Refusals are counted.** `locked_out`, `rate_limited`, `access_refused`, `enrollment_refused`, `authenticator_removal_refused`, `link_refused`, `verification_refused`, `impersonation_refused`, and `factor_failed` for a name nobody has are each written at most `security_log.refusals` times every `refusals_per` period, which is 20 an hour by default. These counts are kept for the account the entry is linked to, or for the IP address when the entry isn't linked to anyone.
- **The log says where it stopped.** The first entry left out is replaced by one `refusals_limited` entry that names its type, so a gap in the log is never silent.

A failed factor for a real account isn't counted this way. The account's own [rate limits](security.md#rate-limiting) already bound how often it can fail, and the `RepeatedFactorFailures` and `SuccessAfterFailures` risk signals count those entries. The `CredentialStuffing` signal also reads `factor_failed` for names nobody has. This limit counts by the request's real IP address, while the signal matches the address Keyring records, and `refusals => null` removes the limit. Either way, the signal counts all of those entries as one account, so the limit changes little for it. To write every refusal, set `refusals` to `null`. The counts are stored in the rate limiter's cache store, the same as the limits themselves.

### Refused Links

The `link_refused` entry covers every emailed link that Keyring checks:

| `link` | `reason` |
|---|---|
| `email_change_confirm`, `email_change_revert` | `token` when the token was wrong. `ended` when the token was right but the change is over (expired, cancelled, already used, or already undone). `unknown` when there's no such change, either because the link was made up or because its change was pruned long ago. Only pressing the page's button is logged, not opening the link. |
| `password_reset` | `token`: the token wasn't one sent to that address, or it has expired. The entry holds neither the token nor the address. |
| A signed route's name, such as `keyring.devices.report.store` or `verification.verify` | `signature` when the signature didn't match. `expired` when it matched but the link is out of date. |

Signed links are checked by the `keyring.signed` middleware. It works like Laravel's `signed` middleware, with the log entry added. It refuses the same links with the same 403 response. To have refusals on a signed route of your own logged too, add the middleware to that route:

```php
Route::get('/invitations/{invitation}', AcceptInvitation::class)->middleware('keyring.signed:relative')->name('invitations.accept');
```

### Showing Recent Activity

The `Keyring::activity` method returns a user's most recent entries, newest first. You may use it on a settings page. It accepts an optional limit, which defaults to `25`:

```php
use Keyring\Facades\Keyring;

return Inertia::render('settings/security', [
    'activity' => Keyring::activity($request->user())->map(fn ($event) => [
        'type' => $event->type,
        'factor' => $event->factor,
        'ip' => $event->ip,
        'at' => $event->created_at->toIso8601String(),
    ]),
]);
```

Some entries are about a user without being something the user did. For example, a package that issues tokens to another app's server might log each one with the user it was issued for. On the user's activity page, those entries would look like activity they don't recognise, from a server's address. List their types in `security_log.unlisted`, and `Keyring::activity` leaves them out:

```php
'security_log' => [
    // ...
    'unlisted' => ['acme.token_issued'],
],
```

A package can add its own types when it boots, so the apps that install it don't need to know them. It should start each type with its own name, as in `acme.token_issued`, so its types can't clash with Keyring's or your app's:

```php
config()->push('keyring.security_log.unlisted', 'acme.token_issued');
```

Your app may add types from a service provider of its own too. Push them the same way: setting the option there replaces what packages have already pushed, since their providers boot first. In `config/keyring.php`, keep the option a list even for one type. A string there leaves nothing out, and the first package to push to it throws an error.

Keyring's own [entry types](#entry-types) are never left out, even when they're listed, and that includes any spelling your database takes for one: on MySQL, Laravel's default collation takes `Signed_Out` or `signed_out ` for `signed_out`. A package adds its types where your app doesn't see them, and one of Keyring's there would hide the user's real sign ins or sign outs. The one exception is the impersonation entries, `impersonation_started` and `impersonation_ended`, which your app can leave out by setting [`impersonation.show_in_activity`](configuration.md#impersonation) to `false`, but not by listing them here.

Unlisted entries are still the user's. They're deleted when the user is force deleted, and kept for `keep_for` like any other entry. Only `Keyring::activity` leaves them out:

- ["Was this you?" alerts](#was-this-you-alerts) come from the `alerts` list alone. An unlisted type isn't an alert unless you add it there too.
- A line written to [your application's log](#without-the-table) still names the user.
- Your own queries on `SecurityEvent` still find them. If you build the activity page from a query of your own, add `->whereNotIn('type', Keyring::unlistedActivityTypes())` to it. That's the same list `Keyring::activity` uses, without Keyring's own types or anything that isn't a string, and with the impersonation types when `impersonation.show_in_activity` is `false`. A `null` read straight from the config would hide every entry.

### Pruning

The `SecurityEvent` model is mass prunable. The `keyring:prune` command deletes entries older than `security_log.keep_for`, which defaults to 180 days, along with Keyring's other old records. Keyring [schedules this command to run daily](devices-and-sessions.md#pruning) for you, so there's nothing for you to add.

When a user is force deleted, their entries are deleted with them, without waiting for `keep_for` to pass. A soft deleted user keeps theirs.

### What's Stored

Each entry keeps the request's IP address and user agent, as devices and sessions do. Security notices also pass the address along. To store less, tell Keyring what to keep. Rate limits always use the real address:

```php
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\IpUtils;

// The network, not the machine. Or return null to keep none.
Keyring::recordIpsUsing(fn (Request $request) => IpUtils::anonymize((string) $request->ip()));
```

For a complete list of everything Keyring keeps, how it's protected, and for how long, see [What Keyring Keeps](security.md#what-keyring-keeps).

## "Was This You?" Alerts

After a successful sign in, Keyring flashes `keyring.alerts` to the session. This is a list of log entries worth asking the user about, which they haven't seen yet. Each alert is shown only once. When `Features::devices()` is on, a browser only receives alerts for entries logged after the account first used that browser. A browser that hasn't signed in to the account before receives none. A browser first used after an alert was logged doesn't receive that alert either, since it could belong to whoever caused the event. Those alerts wait for a browser the account already had.

```json
[
  { "type": "second_factor_failed", "factor": "totp", "at": "2026-11-08T09:12:00+00:00", "ip": "198.51.100.4" }
]
```

The types that become alerts are listed in `security_log.alerts`. By default, they are `second_factor_failed`, `device_reported`, `email_change_reverted`, `clone_suspected`, and `remember_me_reused`. Any [entry type](#entry-types) can be added to that list. A `second_factor_failed` alert is the classic sign that someone else knows the password, or, after a sign in with an identity provider, that someone else can sign in to the account linked there.

To read the alerts yourself, call `Keyring\Activity\SecurityLog::pullAlerts` with the user. It returns the unseen alert entries, newest first, and marks them as seen, so each one comes back only once. Pass a time as `since:` to receive only the entries logged after that time.

To show a banner, share the alerts through your Inertia middleware:

```php
// app/Http/Middleware/HandleInertiaRequests.php
public function share(Request $request): array
{
    return [
        ...parent::share($request),
        'keyringAlerts' => fn () => $request->session()->get('keyring.alerts', []),
    ];
}
```

## Security Emails

Keyring sends its own emails. Each one is an ordinary Laravel notification in the `Keyring\Notifications` namespace, sent through your application's mailer using Laravel's mail template. There's nothing to publish or register. To change one, give Keyring your own class for its type in your `KeyringServiceProvider`, or pass `null` to turn that email off:

```php
use Keyring\Notifications\CloneSuspected;

Keyring::notifications([
    'new_device' => \App\Notifications\NewDevice::class,   // yours instead of Keyring's
    'recovery_code_used' => null,                            // not sent
    'clone_suspected' => CloneSuspected::class,              // the one notice that starts off
]);
```

Types you leave out keep Keyring's own notification. Every security notice is turned on from the start, except `clone_suspected`, which is sent once you list it as shown above. A notice is sent when its event happens, so a notice that depends on a feature you haven't turned on is never sent:

- `new_device` needs `Features::devices()`.
- `second_factor_failed` needs a sign-in method besides the password.
- `email_changed` and `email_change_reverted` need `Features::emailChanges()`.

NIST SP 800-63B-4 requires a notice when an authenticator is bound to an account (Sec. 4.1.2.1: `authenticator_added`, and `password_changed` for a new password). It also requires one when an account is recovered (Sec. 4.2.3: `password_changed` after a reset, and `recovery_code_used`), and when recovery codes are replaced (Sec. 4.2.1.1: `recovery_codes_generated`). NIST recommends a notice when an authenticator is removed (Sec. 4.5: `authenticator_removed`).

OWASP ASVS 5.0.0 asks for two kinds of notice. Requirement 6.3.7 covers a notice after a change to how someone signs in: `password_changed`, `authenticator_added`, `authenticator_removed`, `recovery_codes_generated`, `email_changed`, and `email_change_reverted`. Requirement 6.3.5 covers a notice of a suspicious attempt: `new_device`, `second_factor_failed`, `account_locked`, and `suspicious_activity` for what the [risk signals](risk.md#built-in-signals) find. Keyring's own emails cover both requirements, as far as your features go. A sign in after a long quiet period, or after several failures, is announced by [Keyring's own risk response](risk.md#telling-the-user). So is one from an address where many other accounts have failed, when the `CredentialStuffing` signal is on. A responder of yours has to do the same. The [OWASP ASVS](owasp-asvs.md) page has the whole list for each level.

Calling `Keyring::notifications` again adds to the notifications you gave it before. An unknown type throws an `InvalidArgumentException`, so a typo doesn't quietly leave an email as it was.

An account can receive each kind of notice five times an hour at most, as set by `limits.notices` every `limits.notices_per`. This means nobody can make your application mail one person without end, such as by signing in from a new browser over and over. The [security log](#the-security-log) records every event either way. A `MustVerifyEmail` user gets no security emails until their address is verified, because until then the address is only what someone typed when registering. There is one exception: `password_changed` after a password reset. The reset link went to that address, so whoever finished the reset can read its mailbox.

To reword an email, translate its strings. Every one goes through the `__` helper, so a line in your `lang/en.json` file replaces it. To restyle all of them, publish Laravel's mail template with `php artisan vendor:publish --tag=laravel-mail`. Every `MailMessage` in your application uses that template. For anything more, see [Your Own Templates](#your-own-templates). Keyring builds each notification through the container and passes what it has to say as named constructor arguments. That means a class of your own only needs to take the arguments it wants.

### Email Types

The security notices, each sent to the user:

| Type | Sent When | Passes |
|---|---|---|
| `new_device` | A sign in from a new device. | `url`, the ["this wasn't me" link](devices-and-sessions.md#the-this-wasnt-me-link) |
| `password_changed` | The password was changed or reset. | |
| `authenticator_added` | A sign-in method was added. | `name`, and `url`, your page for sign-in methods ([`authenticators_url`](configuration.md#account-changes-and-enrollment)), when you set one |
| `authenticator_removed` | A sign-in method was removed. | `name` |
| `second_factor_failed` | Someone got the password right, or signed in with a linked [identity provider](sso.md), but failed the next factor. | `name`, the sign-in method the first step used, such as "Google (taylor@example.com)", when it wasn't the password. Keyring's email then says that method was used rather than the password, so a class of your own should check it too. |
| `recovery_code_used` | A recovery code was used. | `remaining`, how many are left |
| `recovery_codes_generated` | A new set of recovery codes was made, and any earlier set stopped working. This is also sent for the set that comes with a user's first extra sign-in method. | `url`, your page for sign-in methods, when you set one |
| `account_locked` | Failed attempts got the password or a passkey refused until the password is reset. This happens when the account reaches [the cap on failures in a row](security.md#at-the-cap), or when [`limits.lock_after`](security.md#locking-until-a-reset) holds it. Browsers the account has signed in from may still get in. | `url`, the password reset form (the `password.request` route), when the application has one. `device` and `ip` are those of the attempt that locked the account. |
| `suspicious_activity` | A [risk action](risk.md#actions) with `notify()` ran. | `reasons` |
| `clone_suspected` | A passkey or security key looked cloned. | `name` |
| `email_changed` | An email change was applied. Sent to both the old and the new address. | |
| `email_change_reverted` | An email change was undone. Sent to the current address, and to the new one when the change had been applied. | |

Every notice is also passed `when` (the time as text, in the application's timezone), `at` (the same moment as a date, to format for the user's own timezone or language), the `device` and `ip` of the request that caused it, and `contact`, which is [your support contact](#a-support-contact). The copy of `email_change_reverted` sent to the new address leaves out the `device` and `ip`, since that address may belong to whoever took over the account.

Most notices end by telling a user who didn't do it to change their password and check their sign-in methods. `authenticator_added` and `recovery_codes_generated` say more, since someone else may be signed in. The first says to remove the new method, sign out everywhere and change the password. The second says to sign out everywhere, change the password and remove any method they don't recognise. With [`authenticators_url`](configuration.md#account-changes-and-enrollment) set, both have a "Review your sign-in methods" button to that page. The owner can always remove a method that was added recently, even while the account's others are [frozen](authenticators.md#frozen-sign-in-methods). The link is built from `APP_URL`, never the request's host, like every [emailed link](security.md#emailed-links). It carries no token, and nothing happens until the owner is signed in on that page.

Renaming a sign-in method, or choosing another one as the default, sends nothing. Neither change affects what can sign in to the account.

The `name`, `device`, and `reasons` values can contain what a user or browser sent. For example, a key's name is whatever was typed. Keyring cuts each value to one line of at most 500 characters. It's still text that you need to escape wherever you show it. Keyring's classes pass it through `Keyring\Support\MailText::plain`, because Laravel reads mail lines as Markdown. Without that step, a name could add a link to a genuine security email.

Keyring's notices share an abstract `Keyring\Notifications\SecurityNotice` class, which holds the constructor and the `via` and `toMail` methods. Each notice only defines its `subject`, its `intro`, and, when it has a button, its `action`. A notice may also override `ifNotYou`, the line that says what to do if it wasn't the user. Notices are queued once any open database transaction commits, so a change that's rolled back is never announced.

### A Support Contact

NIST SP 800-63B-4 (Sec. 4.6) asks that a notice give clear instructions, including contact information, for a recipient who says the event wasn't theirs. Keyring can't know where your support team is, so you need to tell it:

```php
// config/keyring.php
'support_contact' => 'https://example.com/support',   // or 'support@example.com'
```

Every notification Keyring builds then receives this value as `contact`, whether it's a security notice or an email a flow needs. Keyring's security notices, `VerificationCode`, and `EmailChangeNotice` end with "If this wasn't you and you need help, contact us", followed by the contact. The contact appears as a link when it's a URL or an email address. The `Keyring\Support\MailText::contact` method writes that line. The three emails that say nothing happened and can be ignored (`ConfirmEmailChange`, `EmailAddressInUse`, and `AlreadyRegistered`) don't show it. The default is `null`, which means no email includes the line. Set a contact before you claim that your notices follow NIST.

The same section (Sec. 4.6) has notices go to every address an account has, and asks for at least two. Keyring knows about one, the `email` attribute, and it sends mail to your user model in the same way Laravel does. To send every notice to more than one address, return them from your model's `routeNotificationForMail` method:

```php
// app/Models/User.php
public function routeNotificationForMail(): array
{
    return array_filter([$this->email, $this->backup_email]);
}
```

This also changes where Laravel's own mail notifications go, which is usually what you want. Keeping a second address, and verifying it before it's used, is something your application has to build. See [Known Limitations](security.md#known-limitations). A notice's `via` method is yours to define too, so a notice can also go to another channel, such as SMS or a push message.

### Emails a Flow Needs

Five emails are part of a flow rather than a notice. The flow can't work without them. If you set one of them to `null`, the flow throws a `Keyring\Exceptions\MissingNotification` exception that names the type:

| Type | Sent To | Passes |
|---|---|---|
| `verification_code` | The user, with an [email code](factors.md#email-codes). | `code`, the `minutes` until it expires, and `enrolling`, which is true when the code confirms a new email code sign-in method |
| `confirm_email_change` | The new address, during an email change. | `url` and `expiresAt` |
| `email_change_notice` | The current address, during an email change. | `email` (the new address, with most of its name hidden), `revertUrl`, and `confirmUrl` when this address must confirm too |
| `email_address_in_use` | An address someone tried to change their email to, when that address already has an account. | |
| `already_registered` | An address someone tried to [register](sign-in-flow.md#without-revealing-who-has-an-account) with, when that address already has an account. | `loginUrl`, and `resetUrl` when password resets are on |

The `verification_code` email is sent straight away. The three email change emails and `already_registered` are sent after the response, so the timing doesn't reveal whether an address has an account. An email change is refused before anything is saved if one of its three emails is turned off. A registration is refused in the same way without `already_registered`, unless `registration.reveal_taken` is on.

The email change emails, `already_registered`, and the copies of `email_changed` and `email_change_reverted` that go to an address the account no longer has are sent to a bare address. Their `$notifiable` is an `AnonymousNotifiable` routed to mail, not your user. In your own classes for those types, keep `via` and `toMail` from reading user attributes.

Password resets and email verification use Laravel's own `ResetPassword` and `VerifyEmail` notifications, with links that Keyring builds from `APP_URL`. You change them the usual Laravel way, for example by overriding the `sendPasswordResetNotification` method on your user model. The reset email is also sent after the response, and so is a new user's verification email, unless `registration.reveal_taken` is on.

### Your Own Templates

To write the email for every security notice from your own views, such as templates built with Maizzle, give `SecurityNotice` a callback in your `KeyringServiceProvider`. The callback receives the notice and the person it's for:

```php
use Illuminate\Notifications\Messages\MailMessage;
use Keyring\Notifications\SecurityNotice;

SecurityNotice::toMailUsing(fn (SecurityNotice $notice, object $notifiable) => (new MailMessage)
    ->subject($notice->subject())
    ->view('emails.keyring.notice', [
        'intro' => $notice->intro(),
        'when' => $notice->when,
        'device' => $notice->device,
        'ip' => $notice->ip,
        'actionText' => $notice->action(),
        'actionUrl' => $notice->action() === null ? null : $notice->url,
        'contact' => $notice->contact,
    ]));
```

Blade's `{{ }}` escapes those values for HTML. The callback may return a `Mailable` instead. [Emails With Maizzle](recipes.md#emails-with-maizzle) walks through this approach. The [example application](https://github.com/keyringphp/example#emails) builds every email this way, using Maizzle templates compiled to Blade views. One shared view serves every notice, and a local page lets you preview them.

For a single notice, or for one of the [emails a flow needs](#emails-a-flow-needs), extend Keyring's class and register your own:

```php
namespace App\Notifications;

use Illuminate\Notifications\Messages\MailMessage;
use Keyring\Notifications\PasswordChanged as KeyringPasswordChanged;

class PasswordChanged extends KeyringPasswordChanged
{
    public function toMail(object $notifiable): MailMessage
    {
        return (new MailMessage)
            ->subject($this->subject())
            ->view('emails.password-changed', ['when' => $this->when, 'device' => $this->device, 'ip' => $this->ip]);
    }
}
```

```php
Keyring::notifications(['password_changed' => \App\Notifications\PasswordChanged::class]);
```

A notification doesn't have to extend Keyring's class. Any class whose constructor takes the arguments it wants will do.

### Slack, SMS and Other Channels

Notifications can be sent to any channel Laravel supports. Choose the channels in the `via` method, per user if you like, and add the matching method for each one:

```php
namespace App\Notifications;

use Illuminate\Notifications\Slack\SlackMessage;
use Keyring\Notifications\NewDevice as KeyringNewDevice;

class NewDevice extends KeyringNewDevice
{
    public function via(object $notifiable): array
    {
        return $notifiable->slack_webhook ? ['mail', 'slack'] : ['mail'];
    }

    public function toSlack(object $notifiable): SlackMessage
    {
        // Slack reads <...> as a link, and a user agent is whatever the browser sent.
        return (new SlackMessage)->text(htmlspecialchars($this->subject().': '.$this->device, ENT_NOQUOTES));
    }
}
```

Register it with `Keyring::notifications(['new_device' => \App\Notifications\NewDevice::class])`.

Slack requires Laravel's `laravel/slack-notification-channel` package. See [Laravel's notification documentation](https://laravel.com/docs/notifications#slack-notifications) for it and the other channels. For the `database` or `broadcast` channels, add a `toArray` method.

### Sending Something Else Entirely

Keyring dispatches an [event](events.md) for everything it sends a notice about, whether or not that notice is turned on. To do something other than notify the user, set the type to `null` in `Keyring::notifications` and listen for the event.

## Laravel's Auth Events

Keyring dispatches Laravel's `Illuminate\Auth\Events\Failed`, `Lockout`, and `PasswordReset` events alongside its own events, so your existing listeners keep working. See [Events](sign-in-flow.md#events).
