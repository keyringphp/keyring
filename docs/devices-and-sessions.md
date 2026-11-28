# Devices & Sessions

- [Introduction](#introduction)
- [Routes](#routes)
- [Devices](#devices)
    - [Trusted Devices](#trusted-devices)
    - [New Device Sign Ins](#new-device-sign-ins)
    - [The "This Wasn't Me" Link](#the-this-wasnt-me-link)
    - [Locations](#locations)
    - [Device Names](#device-names)
    - [Your Own Device Model](#your-own-device-model)
- [Listing and Revoking Devices](#listing-and-revoking-devices)
- [Listing and Ending Sessions](#listing-and-ending-sessions)
    - [Is It Still Signed In?](#is-it-still-signed-in)
    - [Hearing About Ended Sessions](#hearing-about-ended-sessions)
    - [Sweeping Ended Sessions](#sweeping-ended-sessions)
- [The Session Registry](#the-session-registry)
    - [Drivers](#drivers)
    - [Writing a Driver](#writing-a-driver)
    - [How Many Sessions](#how-many-sessions)
    - [The Session Middleware](#the-session-middleware)
    - [Pages That Also Serve Guests](#pages-that-also-serve-guests)
    - ["Remember Me"](#remember-me)
    - [A Cookie Used Twice](#a-cookie-used-twice)
- [Keyring's Cookies](#keyrings-cookies)
- [For Administrators](#for-administrators)
- [Timeouts](#timeouts)
    - [Inactivity and "Remember Me"](#inactivity-and-remember-me)
    - [Ending a Session With Its Level](#ending-a-session-with-its-level)
- [Pruning](#pruning)
- [Events](#events)

## Introduction

Keyring keeps track of two things:

- **Devices**: browsers the user has signed in from, recognised by a cookie. A device is an input to your policy and to risk signals, but it's never a factor. Devices are a feature, enabled with `Features::devices()`.
- **Sessions**: each signed-in session, kept in Keyring's own registry. This means they can be listed and revoked, whichever session driver Laravel uses (database, file, cookie, or cache). Sessions are always on. They're how Keyring signs other sessions out after a password change, ends idle ones, and lapses assurance levels.

```php
'features' => [
    Features::devices(),
],
```

Because sessions are always kept, the routes that [list and end them](#listing-and-ending-sessions) are always registered. No feature turns them on or off.

When devices are on, Keyring sets its cookie at sign in, offers "don't ask again on this device," lists where the user is signed in, and adds "this wasn't me" links. Without devices, no cookie is set and no device is recorded. The `NewDevice`, `NewCountry`, `ImpossibleTravel`, and `InactiveAccount` [risk signals](risk.md) need devices. Devices also let Keyring keep some of an account's allowed failures for browsers it has signed in from ([`limits.consecutive_elsewhere`](security.md#at-the-cap)), so someone else's failed guesses can't lock the owner out of their own device.

## Routes

| Method | URI | Name | Middleware | Does |
|---|---|---|---|---|
| `GET` | `/user/sessions` | `keyring.sessions.index` | `auth:{guard}` | Lists the user's sessions as JSON. |
| `DELETE` | `/user/sessions/{session}` | `keyring.sessions.destroy` | `auth:{guard}`, `changes_middleware` | Ends one session. |
| `DELETE` | `/user/sessions` | `keyring.sessions.destroy-others` | `auth:{guard}`, `changes_middleware` | Signs out every other session. |
| `GET` | `/user/devices` | `keyring.devices.index` | `auth:{guard}` | Lists the user's devices as JSON. |
| `DELETE` | `/user/devices/{device}` | `keyring.devices.destroy` | `auth:{guard}`, `changes_middleware` | Signs one device out. |
| `DELETE` | `/user/devices` | `keyring.devices.destroy-others` | `auth:{guard}`, `changes_middleware` | Signs out every other session. |
| `GET` | `/devices/{device}/report` | `keyring.devices.report` | signed, `keyring-pages` limiter | The "this wasn't me" link: a page with a button. |
| `POST` | `/devices/{device}/report` | `keyring.devices.report.store` | signature in the body, `keyring` limiter | Signs the device out. |

The three session routes are always registered, but the device routes need `Features::devices()`. Looking at a list needs only a signed-in user. Ending a session or a device also needs `changes_middleware`, which is a [fresh verification](step-up.md#fresh-verification) by default.

## Devices

With `Features::devices()` on, Keyring looks for its device cookie on every sign in. If the cookie is missing or unknown, Keyring creates a device with a new random token and sets the cookie. The cookie is httpOnly, `SameSite=Lax`, and lasts 400 days. Only a SHA-256 hash of the token is stored. See [Keyring's Cookies](#keyrings-cookies) for its name and for when it's `Secure`.

An account keeps its 50 most recently seen devices (`devices.limit`). When a sign in comes from another new browser, the device seen longest ago is forgotten and signed out, so it counts as a new device if it comes back. Without a limit, one account could fill the table, and its own devices page, by signing in from browsers that send no cookie.

Each device records a readable name built from the user agent (the browser and the operating system, as in ":browser on :platform"), the last IP address and location, and when it was first and last seen. The user agent is never a factor. It's only a weak risk signal. `SessionFingerprintChanged` notices when a session's browser or platform changes.

A browser shared by several accounts has one cookie and a device for each account that signed in on it. An account's device never takes a cookie value the browser sent. A value might be there because two accounts share the browser, or because someone planted the value of another person's device. Keyring can't tell these apart, and accepting a planted value would make that person's browser count as one of this account's devices. So an account signing in on a browser for the first time gives it a new cookie, and the accounts already on that browser move to the new one with it. Every login that reaches AAL2 gives the browser a new cookie too, so the previous one stops working.

### Trusted Devices

When `devices.trust_for` isn't `null`, the challenge page offers "don't ask again on this device" (`canTrustDevice`). Posting `trust: true` during the login marks the device as trusted for that long (30 days by default), counted from the moment trust is granted. It only counts when that login reached AAL2, for example with a password and an authenticator app's code. If `Features::emailVerification()` is on, the email address must also be verified.

An [emailed code](factors.md#email-codes) doesn't count as a second factor. So a login that used one beside the password isn't offered trust (`canTrustDevice` is false), and it can't earn it. Sending `trust` with the password is kept, and trust is granted once a second factor passes in that login. A login that only used the password doesn't earn it. Granting trust gives the browser a new cookie, so trust never rests on a cookie that was planted or copied before the login. Other accounts on the same browser move to the new cookie too.

Trust on its own changes nothing. Your [policy](policies.md#deciding-per-user-and-attempt) is what makes use of it:

```php
Keyring::require(fn (User $user, Attempt $attempt) => $attempt->device()?->isTrusted()
    ? Requirement::aal1()
    : Requirement::aal2()->ifEnrolled());
```

Revoking a device stops trusting it, and signing out everywhere else stops trusting every other device. Every device stops being trusted when:

- the password changes or is reset,
- an authenticator is removed, or a factor that allows only one per user is replaced (new recovery codes don't count),
- an email change is applied or reverted,
- a signed-in request places a [risk lock](risk.md#responding-to-risk), or a signed-in session meets a critical risk.

Risk detected at login leaves the owner's sessions and trusted devices alone, whether it refuses the attempt or locks the account.

### New Device Sign Ins

A sign in from a new device dispatches `Keyring\Events\NewDeviceSignedIn`. The `new_device` [security email](security-log-and-emails.md#security-emails) tells the user about it. Keyring sends it by default, unless the app sets `new_device` to `null` in `Keyring::notifications()`. `keyring:install` only turns on the `NewDevice` risk signal when devices are on. Alternatively, you may write your own listener to send a message:

```php
use Illuminate\Support\Facades\Event;
use Keyring\Events\NewDeviceSignedIn;

Event::listen(function (NewDeviceSignedIn $event) {
    $event->user->notify(new NewSignIn($event->device->description(), $event->revokeUrl()));
});
```

When the location is known, `$device->description()` adds it, as in ":browser on :platform near :city".

### The "This Wasn't Me" Link

`$event->revokeUrl()` (or `$device->revokeUrl($days)`) returns a signed link to `GET /devices/{device}/report`. It's valid for 7 days by default (`devices.report_link_for`). Opening it shows the `device-report` page. Its props are `device` (a description such as "Chrome on macOS"), `url`, `expires`, and `signature`. Its button posts `expires` and `signature` in the body to `url`, which is the link's path without its query string.

That revokes the device without the user needing to sign in. Its sessions end, it stops being trusted, and every "remember me" cookie for the user stops working. The user lands on the login page, with a message recommending a password change. The event is logged as `device_reported`, which shows as a ["was this you?" alert](security-log-and-emails.md#was-this-you-alerts) at their next sign in.

The link is built from `APP_URL`. Its signature covers only the path and query, so a forged `Host` header can't point it at another site. Like the email change links, opening it changes nothing, so mail scanners that follow links can't sign anyone out.

The link itself has to carry its signature in the URL. The request that acts posts the signature instead, so it isn't written to access logs and proxies a second time. Keyring checks the posted fields the same way it checked the link: the same signature, over the same path, with the same expiry. A signature left in the URL of the `POST` request is refused with a `403`.

```html
<form method="POST" action="{{ $url }}">
    @csrf
    <input type="hidden" name="expires" value="{{ $expires }}">
    <input type="hidden" name="signature" value="{{ $signature }}">
    <button>Sign {{ $device }} out</button>
</form>
```

### Locations

Keyring asks a locator class for the rough location of each request. The default, `Keyring\Devices\NullLocator`, knows nothing. As a result, locations are empty, and the location [risk signals](risk.md) stay quiet.

To turn locations on, set `devices.locator` to a class that implements `Keyring\Contracts\LocatesIps`. [Recipes](recipes.md#locations-with-stevebaumanlocation) has one for `stevebauman/location`:

```php
use Illuminate\Http\Request;
use Keyring\Contracts\LocatesIps;

class IpLocator implements LocatesIps
{
    public function locate(Request $request): ?array
    {
        $record = app(IpDatabase::class)->lookup($request->ip());

        return $record === null ? null : [
            'country' => $record->countryCode,
            'city' => $record->city,
            'latitude' => $record->latitude,
            'longitude' => $record->longitude,
        ];
    }
}
```

The array may contain `country`, `region`, `city`, `latitude`, and `longitude`. Impossible travel needs the coordinates.

Keyring asks the locator at most once per request, however many signals and steps need the location. You can read it the same way in your own code with `Keyring\Devices\Location::of($request)`.

If the locator throws an exception (say, because its database file is missing), the location is treated as unknown for that request, and the exception goes to `report()`. Sign in carries on, and the location risk signals stay quiet.

`Keyring\Devices\HeaderLocator` reads the location headers that a proxy or CDN adds. By default, it reads Cloudflare's: `CF-IPCountry`, `CF-Region`, `CF-IPCity`, `CF-IPLatitude`, and `CF-IPLongitude`. For another proxy, set `devices.locator` to `HeaderLocator::class`, and bind it with your own map of location fields to header names:

```php
use Keyring\Devices\HeaderLocator;

$this->app->bind(HeaderLocator::class, fn () => new HeaderLocator([
    'country' => 'X-Country-Code',
    'city' => 'X-City',
]));
```

> [!WARNING]
> Only use `HeaderLocator` when requests can't reach your application without passing through that proxy. Anyone can send those headers.

### Device Names

Keyring's own user agent parsing only knows the common browsers and platforms. To use a real parser, pass a closure that receives the user agent string and returns a name, or `null`. You do this in a service provider's `boot()` method:

```php
use Keyring\Facades\Keyring;

Keyring::describeDevicesUsing(fn (string $userAgent) => app(UserAgentParser::class)->parse($userAgent)->summary());
```

`UserAgent::from($request)` returns the request's user agent, trimmed to 500 characters, as Keyring stores it.

### Your Own Device Model

To add relationships or methods to devices, extend `Keyring\Models\Device` and tell Keyring about your model:

```php
use App\Models\Device;

Keyring::useDeviceModel(Device::class);
```

`$user->devices()`, the risk signals, `keyring:prune`, and the device routes all use this model. The model has two query scopes, `ownedBy` and `active`. The `active` scope leaves out revoked devices:

```php
Keyring::deviceModel()::query()->ownedBy($user)->active()->get();
```

## Listing and Revoking Devices

With `Features::devices()` on, `GET /user/devices` returns the user's devices that haven't been revoked, most recently seen first. A device is a browser, with however many sessions it has (counted in `sessions`). For the sessions themselves, see [Listing and Ending Sessions](#listing-and-ending-sessions).

```json
{
  "devices": [
    {
      "id": "01JC6...",
      "name": "<browser> on <platform>",
      "description": "<browser> on <platform> near Leeds",
      "ip": "203.0.113.7",
      "location": { "country": "GB", "city": "Leeds" },
      "lastActiveAt": "2026-11-08T13:55:00+00:00",
      "trusted": false,
      "current": true,
      "sessions": 1
    }
  ]
}
```

`DELETE /user/devices/{device}` revokes one device. Its sessions end, it stops being trusted, and the user's "remember me" token is changed. The response is a [status response](sign-in-flow.md#status-responses) with `device-revoked`. Revoking the current device also signs this session out, and the response redirects to the login page. JSON clients get that redirect as `redirect`.

`DELETE /user/devices` and [`DELETE /user/sessions`](#listing-and-ending-sessions) do the same thing under two names. The second is registered whether or not `Features::devices()` is on, so "sign out everywhere else" is always available to offer. Either one signs out every session except the current one, changes the "remember me" token, stops trusting every other device, cancels any pending email change, and gives the current session a new ID. That last part means someone who copied its cookie is signed out too. The response is `sessions-revoked`.

You may do the same from your own code with `Keyring\Sessions\Sessions::signOutOthers()`. It returns how many sessions it revoked, and it dispatches `SessionsRevoked`. Internally, it runs `signOutEverywhere` with the current session left out, followed by `rotate`, which gives the current session its new ID:

```php
use Keyring\Sessions\Sessions;

app(Sessions::class)->signOutOthers($request, $user);

// Or step by step.
app(Sessions::class)->signOutEverywhere($user, except: app(Sessions::class)->current($request)?->id);

app(Sessions::class)->rotate($request);
```

A user can also ask for this [along with adding or removing a sign-in method](authenticators.md#signing-out-other-sessions). A [password change](protected-changes.md#changing-the-password) does it too, unless you tell it not to.

`rotate` regenerates the session, which destroys the old one on the server. Laravel's `cookie` session driver has nothing on the server to destroy. With that driver, `rotate` also moves the session to a new registry record and revokes the old one. Keyring calls it after every step-up as well. A browser that signs in while it's already signed in has the session it was on revoked. So on any driver, a copy of the session from before is signed out on its next request.

Laravel keeps one "remember me" token per user. Changing it signs out every remembered browser at once, including the current one the next time its session ends. Signing out on purpose changes the token, as it does in any Laravel application. A session that ends on its own (through an idle or absolute timeout, a risk response, or a revoked record) leaves the token alone, so other remembered browsers stay signed in. That browser's cookies stop working because its record has ended. See ["Remember Me"](#remember-me).

## Listing and Ending Sessions

`GET /user/sessions` returns every session the user could still carry on, most recently active first. It reads the registry, so the list is complete. It includes a session with no device, such as one your own `Auth::login()` started in a browser Keyring hadn't seen. It also includes each of two sessions on the same device.

```json
{
  "sessions": [
    {
      "id": "9f2c41d0...",
      "name": "<browser> on <platform>",
      "ip": "203.0.113.7",
      "device": "01JC6...",
      "remembered": false,
      "signedInAt": "2026-11-08T09:12:00+00:00",
      "lastActiveAt": "2026-11-08T13:55:00+00:00",
      "expiresAt": "2026-12-08T09:12:00+00:00",
      "current": true,
      "impersonated": false,
      "impersonator": null
    }
  ]
}
```

`impersonated` is `true` for a session someone else is signed in to as the user, through [impersonation](impersonation.md#the-sessions-list), and `impersonator` is who that is, as `{"name": "..."}` with no ID, or `null` once they've been deleted. Its `name`, `ip`, and `device` are always `null`, since they'd be the impersonator's: where they are and what they use. The user can end it like any other. With `impersonation.show_in_sessions` off, it's left out of the list, unless it's the session asking.

`device` is the ID of the session's [device](#listing-and-revoking-devices). It's `null` when the session has no device or when devices are off, so a page can show sessions under their devices. `lastActiveAt` is kept to the minute. A session that has been revoked, has expired, has [idled out](#timeouts), or has moved to another record isn't listed.

`id` is a handle, not the session's registry ID. The registry ID is what the ["remember me" cookie](#remember-me) carries, so it never leaves the server by any other route. A page that could read it could hand someone the session. The handle is an HMAC-SHA256, under your `APP_KEY`, of the ID of the record the session started on. It can't be turned back into an ID, and it's the wrong length to be mistaken for one. The only things that accept it are the route below and the methods that look for it among the user's own sessions. A session keeps its handle when it [moves to a new record](#the-session-registry), so a handle you kept still names the same session after "remember me" carries it on or a step-up gives it a new record. Changing `APP_KEY` changes every handle the list gives. A handle given under a key you've moved to `APP_PREVIOUS_KEYS` still works, until you take that key out of the list.

`DELETE /user/sessions/{session}` ends the session with that handle. Its record is revoked, so that browser is signed out on its next request, and its "remember me" cookie brings nothing back. The response is a [status response](sign-in-flow.md#status-responses) with `session-revoked`. `SessionsRevoked` is dispatched with a count of one. The user's "remember me" token is left alone, so their other remembered browsers stay signed in.

A handle that isn't one of the user's own sessions, someone else's included, gets a `404` and is logged as `access_refused`. Anything that isn't shaped like a handle, a registry ID included, doesn't match the route at all.

Ending the current session is the same as signing out. Keyring does everything `POST /logout` does, including changing the "remember me" token and dispatching `LoggedOut`. It answers with the same [`LogoutResponse`](sign-in-flow.md#signing-out). A JSON client gets a `204`, so send the user to your login page when `current` was `true`.

`DELETE /user/sessions` signs out every session except this one. See [Listing and Revoking Devices](#listing-and-revoking-devices) for everything it ends.

From your own code:

```php
use Keyring\Sessions\Sessions;

$sessions = app(Sessions::class);

$sessions->list($request, $user);            // what the route returns
$sessions->active($user);                    // the same sessions as RegisteredSession objects

$session = $sessions->find($user, $handle);  // null unless it's one of the user's own
$sessions->revoke($user, $session);
```

### Is It Still Signed In?

Other code sometimes knows a session by its handle and needs to know whether it still counts. A single sign-on provider that signed a client in on the session is one example. Ask `stillSignedIn`:

```php
use Keyring\Sessions\Sessions;

if (! app(Sessions::class)->stillSignedIn($user, $handle)) {
    // The user has signed out of that session, or it has ended.
}
```

It's `true` only when your application still lets the user sign in ([`Keyring::allowSignInWhen`](sign-in-flow.md#who-may-sign-in)), and the handle is one of the user's own sessions on Keyring's guard that can still be carried on. A session that was revoked, has expired, or has [idled out](#timeouts) gives `false`. So does anything that isn't one of the user's handles. A session that has moved to a new record keeps its handle, so the answer doesn't change when it moves.

Asking changes nothing. It doesn't count as activity, so it never keeps a session from idling out, and it doesn't sign anyone out. The session middleware still does that on the session's next request.

Some things are only judged on the browser's own requests, so `stillSignedIn` doesn't check them:

- [`sessions.end_on_lapse`](#ending-a-session-with-its-level), [risk locks](risk.md#actions), and the risk signals that run on each request. A session that one of these ends stays `true` until its browser's next request.
- The session's [assurance level](policies.md#assurance-levels). `true` says the user is signed in, not how strongly.

It can't see Laravel's own session either, because no request comes back to say it has ended. A session that isn't remembered is over once Laravel's session is (past `session.lifetime`, or on `expire_on_close`), but its record stays good until it [idles out](#timeouts), so `stillSignedIn` keeps answering `true` until then. With `sessions.idle` at `null`, that's when it hits `absolute`, 30 days by default. Keep `idle` no longer than `session.lifetime` if the answer shouldn't outlast Laravel's session. Even then, with `expire_on_close` or a browser that drops its cookies, it can answer `true` for up to `idle` after the browser has gone.

It needs an Eloquent user, and returns `false` for any other. And where registration hides who has an account, a user who hasn't verified their email address can only be signed in from the browser that followed the verification link. Asked from any other request, such as a server-to-server call, `stillSignedIn` answers `false` for them.

Keep the handle, not the registry ID. The ID is what the "remember me" cookie carries, so it must never leave the server.

### Hearing About Ended Sessions

To be told when a session ends, rather than asking, listen for `Keyring\Events\RegisteredSessionEnded`. There's one for every registered session that ends, whoever ended it and wherever: signing out, your app's own `Auth::logout()` or `Auth::logoutCurrentDevice()` on Keyring's guard, signing out everywhere, ending one session or a device, the device and session limits, a deleted user, a risk response, a password change or reset, an email change or its undo, and the session middleware finding a session idle, expired, used twice, or kept out. See [Events](events.md#why-a-registered-session-ended) for its properties and every reason.

```php
use Illuminate\Support\Facades\Event;
use Keyring\Events\RegisteredSessionEnded;

Event::listen(function (RegisteredSessionEnded $event) {
    // Every handle the session goes by, so one stored before a key rotation matches.
    ClientSession::whereIn('keyring_handle', $event->handles)->each->logOut();
});
```

`ClientSession` stands for whatever your application stores against a handle. Match on `handles`, not only `handle`. `handle` is the session's handle under the current `APP_KEY`. `handles` adds the handle under each key in `APP_PREVIOUS_KEYS`, so a handle you stored before rotating the key still finds its session. Store the handle you got from the sessions list, from `Sessions::handle()`, or from a `RegisteredSessionEnded`. A session keeps its handle when it moves to a new record, so you only need to store it once.

A handle you stored stops matching when `APP_KEY` is rotated without the old key in `APP_PREVIOUS_KEYS`, when a key is taken out of `APP_PREVIOUS_KEYS`, when a server still on old code moves a session during a rolling deploy, or when a [driver of your own](#writing-a-driver) loses `origin`. An event for that session then names a handle you don't have, and nothing tells you. [`stillSignedIn`](#is-it-still-signed-in) answers `false` for such a handle, so it fails safe where the event fails open. Code that keeps someone signed in elsewhere on the strength of a Keyring session should also ask `stillSignedIn` now and then, such as when it refreshes a token, rather than rely on events alone.

When every user is signed out at once, with `keyring:sign-out --all` or the registry's `revokeEveryone()`, Keyring can't list each session. It dispatches one `Keyring\Events\EveryoneSignedOut` instead. Its `at` says that every session that signed in up to then has ended. On the `database` driver its sessions count as announced once it has gone out. If it didn't, because a listener threw or the process stopped, the sweep dispatches it again, never an event for each session. That one can come up to a day late, and its `at` may be a few seconds earlier than the first one's would have been: when the sign-out started, where the first is taken when it finished. Of several lost ones, only the latest is sent, and it settles the rest. So treat `at` as a cut-off on when sessions signed in: end what your app holds for sessions that signed in up to `at`, never "everything, now". A session that signed in since is still good.

What is announced:

- One event per record the registry revoked. A record that was already revoked gives none, so two requests ending the same session at once announce it once between them.
- Nothing when a session moves to a new record. It carries on, under the same handle.
- Nothing when `keyring:prune` deletes records. A record it deletes was announced when it was revoked. With the sweep off, it may also have [timed out](#timeouts) with no request to end it (see below).

When it goes out depends on the [driver](#drivers):

- **`database`**: the event is tied to the transaction on the registry's connection. Outside a transaction, it goes out as soon as the record is revoked. Inside one, such as the user's row that Keyring holds while it signs out everywhere, it goes out once that transaction commits. If the transaction is rolled back, so is the revocation, and nothing is announced. A transaction on any other connection doesn't change when it goes out. A connection with separate `read` and `write` hosts is still one connection, with its transactions on the write host, so the event follows the write host's transaction.
- **`cache`**: the event goes out as soon as the record is revoked. The cache has no transactions, so a rollback elsewhere doesn't take the revocation back, and the event goes out anyway. This is best effort. A cache that's cleared, or that evicts records to make room, ends those sessions with no event at all. When the store fails part way through signing out everywhere, the sessions it had already revoked are still announced, and then the failure is thrown. A synchronous listener runs inside Keyring's row-lock transaction on the user's connection, which commits before that failure is thrown. So what the listener wrote there is kept when Keyring's row lock is the outermost transaction. Inside a transaction of your own, the failure still rolls that transaction back, what the listener wrote included, unless you catch it. A database failure (a `PDOException` anywhere in its chain, which includes deadlocks and lost connections) is thrown from inside the row lock instead, so what the listener wrote is rolled back with it. A listener's own failed query is reported and not thrown, and on PostgreSQL it can still leave the row lock's transaction aborted, so its commit quietly rolls back what the other listeners wrote. With `sessions.max`, a sign in whose limit fails to end a session is refused, and its new record is revoked again without an event before the lock is let go, and the sweep doesn't announce it later. Signing out everywhere still cycles the remember token, stops trusting devices and cancels a pending email change before the failure is thrown, signing out a device still cycles the remember token, and signing out everywhere else still gives this session a new ID. These hold on the `database` driver too. There, with the registry on the user's connection, the same failures roll back everything the row lock held, so nothing is revoked or announced, and the sign in's new record isn't kept. With the registry on a `sessions.connection` of its own, the row lock's transaction isn't the registry's, so it behaves as the cache driver does here. A revocation whose copy into the record fails is kept and announced, and the failure is reported. Revoking a session and moving it with "remember me" take turns under a lock, so a sign-out that lands mid-move is announced. On a store without locks they can't, and such a sign-out can end the session with no event. A revocation that waits more than five seconds for the lock goes ahead without it, with the same risk.
- **A driver of your own** is announced straight away, as the cache driver is, unless it extends `DatabaseSessionRegistry`. See [Writing a Driver](#writing-a-driver).

Two kinds of ending need [the sweep](#sweeping-ended-sessions) to be announced:

- A session that times out with no request arriving. Nothing ends its record until the browser comes back and the session middleware finds it idle or expired. If it never comes back, only the sweep ends it.
- A revocation whose event was lost after its commit: the process stopped before the event went out, another after-commit callback in the same commit threw first (Laravel stops at the first that throws, so an after-commit job whose push to the queue fails stops Keyring's), or the commit reached the database but its answer was lost, which Laravel takes for a rollback.

Without the sweep, these sessions end with no event. With it, on the `database` driver, each one is announced at least once. The `cache` driver can't be swept, so none of this happens there. A session that times out on the cache driver is only announced when its browser comes back, and a cache that's cleared or evicts records ends sessions with no event at all.

Because an ended session can be announced again, the event is at least once: the same handle may come more than once. Make your listener idempotent by handle. Logging a client out twice should do nothing the second time.

The event is dispatched in the request or command that ended the session. Signing out everywhere can end many sessions at once, so queue your listener (`ShouldQueue`) if it does anything slow, like calling another application. The event's properties are plain values, so it's safe on a queue.

Queue it without waiting for a commit. Keyring already dispatches the event after the right commit. A listener with `ShouldQueueAfterCommit`, or a queue connection with `after_commit` turned on, waits again, for whichever transaction was opened last on any connection. If that one is rolled back, the job is dropped, though the sessions stay revoked. This matters when the registry is on a connection of its own, or on the `cache` driver, while some other transaction is open.

A listener that throws doesn't stop the sign-out. The exception is reported with `report()`, the remaining sessions are still announced, and the rest of what was signing out still happens: the browser is signed out, the "remember me" token changes, the devices stop being trusted, and so on. So a failure in your listener can't leave someone signed in to your Keyring app.

It can leave someone signed in elsewhere, though. Laravel calls an event's listeners in turn, and stops at the first that throws or returns `false`. Another listener registered before yours, one of your app's own or a package's, can stop yours hearing the event at all, and all that's left of it is a report. So queue your listener, keep anything else listening for this event from returning `false`, and don't rely on the event alone (see below).

### Sweeping Ended Sessions

`php artisan keyring:sweep` does two things on the `database` driver:

- It announces again each session that was revoked but whose event never went out. It waits five minutes after the revocation first, so an event still on its way isn't doubled. The event has the reason the session ended for, or `revoked` when that wasn't kept. It gives up on a revocation a day old.
- It ends each session that has timed out with no request to end it, those that timed out longest ago first, and announces it with the reason `idle` or `expired`. It ends what the session middleware would end for timing out on the session's next request: one past its `absolute` limit, or unused for longer than `idle` (`remember_idle` for a remembered one). It never ends a session by a level's limits or by [`end_on_lapse`](#ending-a-session-with-its-level). Those depend on what the browser's session proved, which the registry doesn't hold, so they still end on the browser's next request. Nor does it end the sessions of an account your application no longer lets sign in ([`Keyring::allowSignInWhen`](sign-in-flow.md#who-may-sign-in)). Call `signOutEverywhere` when you shut an account out, as [For Administrators](#for-administrators) says.

The limits are the ones in the config of the process that runs the sweep, with its clock. An application that changes `sessions.idle` at runtime, per tenant say, has its sessions swept by the configured value.

To turn it on, set how often it runs. Keyring then adds it to Laravel's scheduler, ahead of `keyring:prune`:

```php
'sessions' => [
    'sweep_every' => '5m',
    'sweep_limit' => 1000,
],
```

`sweep_every` takes minutes or hours, such as `'1m'`, `'5m'`, or `'1h'`. Pick a step that divides an hour or a day. A step that doesn't, such as `'45m'`, runs at the steps that fit in each hour. Over an hour, the hours are rounded down, so `'90m'` runs hourly. A bare number counts seconds, and anything under a minute runs every minute, and zero turns the sweep off, with a warning in your log. The longest it runs apart is 12 hours: a longer setting runs every 12 hours, with a warning in your log. Something that isn't a duration, such as `'5 min'`, leaves the sweep off, with a warning in your log, and `keyring:sweep` prints the problem when you run it. It never stops the rest of your schedule.

The scheduled sweep runs on one server at a time, and never overlaps itself. Both need a cache store shared by your servers that supports locks, such as Redis, Memcached, or the database store. With one that doesn't, each server may run its own sweep. That's safe but wasted work: two sweeps lock the sessions they end and wait for each other, though both may announce the same lost revocation again, which listeners already have to allow for. The lock that says a sweep is running lasts twice the interval, at least ten minutes and at most six hours. So a server that dies mid-sweep holds the sweep up for that long, not for a day. It needs the [scheduler running](installation.md#after-installing).

If no sweep runs for a day, the revocations of that day whose events were lost are given up on, and pruning forgets them.

One run announces again at most `sweep_limit` sessions, then ends at most `sweep_limit` more. Each half has its own allowance, so a backlog of timeouts can't hold up a lost announcement. That keeps the first run, after an upgrade or after you turn the sweep on, from announcing thousands of sessions in one go. The command says how many it ended and announced, and whether it left some for the next run. It never loops until none are left. `sweep_limit` is at most 10000.

A request beats the sweep. The sweep finds what has timed out, locks those rows by their IDs, and decides again from the locked rows. A request that used a session a moment ago keeps it. A browser that comes back after the sweep ended its session is signed out as `idle` or `expired`, in `SessionEnded` and the security log, as it would be had nothing swept it first: pruning keeps its record until a day after it expired, as it would an unended one. A session revoked after it had timed out, by `signOutEverywhere` say, is told the same until pruning removes its record, once its end is announced.

A listener that throws is reported, and the event is tried again later: five minutes after the first try, then ten, then twenty, and so on, doubling, until the day is out. That's about nine tries in all, so an outage of a few hours loses nothing, and a listener that always fails costs a handful of tries, not one every sweep. Laravel stops at the first listener that throws, so the ones behind a broken listener don't hear the event until it's tried again. Put a listener that may fail last, or queue it.

The grace period runs from the revocation, not the commit. A transaction that stays open longer than five minutes around a revocation can see its session announced twice.

The sweep needs four columns that a migration adds to `keyring_sessions`: `announced_at`, `end_reason`, `announce_attempts`, and `announce_after`. Until it has run, sessions end and are announced as before. Keyring logs a warning, once a day, that the migration is missing. The first process that needs to know asks the database, and keeps the answer, yes or no, in the cache for five minutes. Every process takes the cache's word, so a request that ends a session makes no schema query. `keyring:sweep` refuses to run. The [conformance suite](testing.md#the-conformance-suite) checks for the columns. Once the migration has run, noting starts within those five minutes, long-lived processes such as Octane and queue workers included, and at once wherever `keyring:sweep` or `keyring:prune` runs, since they ask the database themselves. A session that ends in those minutes isn't noted, so the sweep announces it a second time. If you roll the migration back, it can take up to five minutes to be noticed under FPM, and Octane and queue workers that found the columns don't notice until they restart. Until then a sign-out that finds the columns gone is made again without them, so signing out keeps working. Sessions revoked before the migration count as announced, so the first sweep doesn't announce them again.

Once the migration has run, `keyring:prune` keeps what a sweep still has to do, whether or not a sweep is scheduled: a session that timed out but hasn't been ended, until a day after it expired, and one that was revoked but not yet announced, until the sweep gives up on it. A session the sweep ended for timing out stays as long as it would have unended, until a day after it expired, so its browser is still told why. A record "remember me" moved a session to also stays until it expires, ended or not: a used cookie is followed to it, so turning up again still raises the [alarm](#a-cookie-used-twice) after the sweep ended the session. It deletes the rest as before. Before the migration, pruning works as it always has.

Running `keyring:sweep` on the `cache` driver, or on a driver of your own that doesn't extend `DatabaseSessionRegistry`, says so and does nothing.

## The Session Registry

Every signed-in session gets a record in Keyring's registry. Each record has its own random ID, along with the user, the device, the assurance level, the IP address, the user agent, whether "remember me" was ticked, and its timestamps. Laravel's session ID is never stored. The registry ID lives inside the session.

A session can move to a new record. This happens when ["remember me"](#remember-me) carries it on, when a [risk response](risk.md#actions) asks it to verify again, and with `rotate` on the `cookie` session driver, which includes every step-up. The old record then names the new one (`replacedBy`, `replacedAt`) and stops being a session. It isn't listed, counted, or revoked with the user's sessions. Every record a session moves to also names the record it started on (`origin`). The session's [handle](#listing-and-ending-sessions) comes from that, so it stays the same. The first record has no `origin` of its own, and `$session->origin()` returns its ID.

Because Keyring checks the registry on every request, revoking a session takes effect on its next request, whichever session driver you use.

### Drivers

```php
'sessions' => [
    'driver' => env('KEYRING_SESSION_DRIVER', 'database'),
    'connection' => null,
    'table' => 'keyring_sessions',
    'store' => null,
    // ...
],
```

- **`database`** (the default) uses the `keyring_sessions` table on `connection`. Its `origin` column comes from a migration of its own. If you installed Keyring before that migration came, see the [upgrade guide](../UPGRADE.md).
- **`cache`** uses the cache store named in `store`, and it needs no table. Use a persistent store. If the cache is cleared, every session's record is gone, and everyone is signed out on their next request. Revocations are kept under their own keys, so a request that saves a stale copy of a session can't undo one.

### Writing a Driver

To write your own, implement `Keyring\Contracts\SessionRegistry`, and register it with the registry manager in a service provider's `register()` method:

```php
use Keyring\Sessions\SessionRegistryManager;

$this->app->afterResolving(SessionRegistryManager::class, function (SessionRegistryManager $manager) {
    $manager->extend('custom', fn ($app) => new MySessionRegistry($app->make('db')->connection('sessions')));
});
```

Then set `sessions.driver` to `custom`. Keyring wraps every driver the manager gives, yours included, in `Keyring\Sessions\AnnouncingSessionRegistry`. The wrapper dispatches a [`RegisteredSessionEnded`](#hearing-about-ended-sessions) for each record that `revoke`, `revokeAll`, and `revokeDevice` return. What your driver returns is what gets announced, so a record it revokes and leaves out is never announced, and one it returns twice is announced twice. Your driver is announced straight away, as the cache driver is, unless it extends `DatabaseSessionRegistry`: then it's tied to the transaction on its connection, as the `database` driver is. A driver that can fail after revoking some of a user's records, because it revokes them one by one, should finish what it can and then throw a `Keyring\Exceptions\PartialRevocation` with the records it revoked and the failure, as the cache driver does. Those are announced, and the failure is thrown on. Your driver keeps working with the sweep turned on, and `keyring:sweep` says there's nothing to sweep, unless it extends `DatabaseSessionRegistry`. Mark the parameters that hold a registry ID, or a `RegisteredSession`, with `#[\SensitiveParameter]`, as the contract does. That keeps a record ID, which is a "remember me" cookie's value, out of the stack traces your error reporting sends. Leaving it off still works. So `app(SessionRegistry::class)` gives the wrapper, and `->inner()` gives your driver. Register a driver through the manager, as above. A `SessionRegistry` you bind in the container yourself isn't wrapped, and nothing it ends is announced. The [conformance suite](testing.md#the-conformance-suite) checks for this.

Keyring calls `replace`, `revokeAll`, and `revokeDevice`, and it stores a new session while it holds the user's database row. For one user, those calls never run at the same moment, so a driver doesn't have to guard them against each other. The contract's methods are:

| Method | Does |
|---|---|
| `save($session)` | Stores a new `RegisteredSession`. It must never clear a revocation made in the meantime, or what a record was replaced by. Store every field, `origin` and the [impersonation](impersonation.md) fields (`impersonatorId`, `impersonatorType`, `impersonatorSession`) included: `$session->toArray()` has them all. |
| `find($id)` | Returns the session, or `null`, with every field it was saved with. `RegisteredSession::fromArray()` reads what `toArray()` gave, and a record saved without `origin` comes back with none. A driver that loses `origin` gives a session a new handle each time it moves. |
| `forUser($user)` | Returns the user's sessions that haven't expired, been revoked, or been replaced, most recent first. A session belongs to a user by more than its ID. Match on the record's `userType` (`RegisteredSession::typeOf($user)`, the connection and table the ID is one of) and its `userId`, here and in `revokeAll` and `revokeDevice`. Otherwise, two user models with the same IDs would share sessions. `$session->belongsTo($user)` checks both. |
| `update($id, $changes)` | Changes only the named fields, such as `['lastActivityAt' => $now]` or `['assurance' => $level, 'expiresAt' => $at]`. Field names match those on `RegisteredSession`. `RegisteredSession::columns($changes)` turns them into snake case columns. Writing only these fields means a request can't write back a stale copy of the rest. |
| `revoke($id)` | Revokes one session. Returns the record as it now stands, with `revokedAt` set, or `null` when it revoked nothing: there's no such record, or it was revoked already. A record that was replaced but not revoked is still revoked and returned, and its `replacedBy` says where the session went. Of two calls for the same record at the same moment, only one may return it. The database driver reads the row with a lock and revokes it in one transaction, and the cache driver returns it when its `add()` of the revoked key won. A record the cache driver finds revoked already, by its own keys or by `revokeEveryone()`, returns `null`, and has its revoked key and record written again with the time it already had. |
| `replace($id, $successor, $revoke = false)` | Moves a session to a new record. It stores `$successor`, and it sets the old record's `replacedBy` and `replacedAt` fields. It also revokes the old record when `$revoke` is true. It only does this for a record that is neither revoked nor replaced, and it returns whether it did. Of two calls for the same record at the same moment, exactly one may return `true`. The other must not leave its record behind, because "remember me" being single use depends on this. The database driver uses one conditional `UPDATE` in a transaction, and the cache driver uses the store's `add()`. |
| `revokeAll($user, $except = null)` | Revokes every session of the user but one. Returns a `Collection` of the records it revoked, each as it now stands, and none that were replaced or revoked already. Every record it revokes must be in what it returns. A driver may also return one another call ended at the same moment, but never leave out one it revoked. The database driver reads the records with a lock, then revokes them by ID in the same transaction, so what it returns is exactly what it revoked, even inside your own transaction that read the table earlier. On that driver, what's returned may include records that had expired but were never revoked. `Sessions::signOutEverywhere` calls this, then also changes the remember token, stops trusting the other devices, and cancels a pending email change. So call that one from your own code. It returns how many records were revoked. |
| `revokeDevice($user, $deviceId)` | Revokes the user's sessions on one device. Returns the records it revoked, as `revokeAll` does. |
| `revokeEveryone()` | Revokes every user's sessions that signed in up to now, for [`keyring:sign-out --all`](#for-administrators). A session that is moving to a new record (`replace`) while this runs must end up revoked there too. Otherwise, "remember me" would carry it past the sign-out. The database driver revokes in rounds until none are left. The cache driver can't list every user's records, so it keeps the moment and treats every session that signed in by then as revoked. |
| `prune()` | Deletes sessions that have expired or been revoked, for `keyring:prune`. Returns how many. A replaced record is kept until it expires, whether or not it has been revoked, because that's how a used "remember me" cookie is told apart from one that was never issued. A store that expires records itself can return `0`. |

### How Many Sessions

An account can be signed in 100 times at once (`sessions.max`). A sign in beyond that still succeeds. It ends whichever of the account's sessions has gone unused longest. That record is revoked, so the browser is signed out on its next request, with `revoked` as the reason. A session that has already [idled out](#timeouts) goes before one that can still be carried on. A session someone is [impersonating](impersonation.md#what-happens-to-the-sessions) the user in isn't one of theirs here: it doesn't count, and isn't ended to make room.

```php
'sessions' => [
    'max' => 100,
],
```

Keyring ends the oldest session and never refuses the new sign in. Refusing would let whoever holds an account's sessions keep its owner out, and the owner couldn't even sign in to end them.

The number is a ceiling, not a rule about how many devices someone may use. It's twice [`devices.limit`](#devices). That leaves room for each of the 50 devices an account keeps to have two sessions, the one in use and one left behind when the browser was closed, before anything still in use is ended. Without devices, it's the only thing that stops one account from filling the registry by signing in over and over. You may lower it to allow fewer sessions at once. For example, `1` allows a single session, and each sign in ends the last. You may also set it to `null` for no limit.

Only sessions count. A record that was revoked, has expired, or that its session [moved on from](#the-session-registry) doesn't count. Sign ins for one account are counted one at a time, so two at the same moment can't both slip under the limit. A session your application starts with its own `Auth::login()` counts like any other.

### The Session Middleware

`Keyring\Http\Middleware\AuthenticateSession` does the checking. Keyring adds it to the `web` middleware group for you. To add it yourself, set `sessions.middleware` to `false`, and then use the `keyring.session` alias.

The middleware only checks routes it runs on, and it needs Laravel's session to have started. A route that reads cookies and uses `auth` without `StartSession` lets a "remember me" cookie through with none of Keyring's checks. If signed-in sessions reach other groups, add `keyring.session` there too. Otherwise, revoked and timed-out sessions keep working on those routes until Laravel's own session lifetime runs out. The most common case is Sanctum's stateful `api` routes for a single-page app:

```php
// bootstrap/app.php
->withMiddleware(function (Middleware $middleware) {
    $middleware->statefulApi();
    $middleware->appendToGroup('api', 'keyring.session');
})
```

The [conformance suite](testing.md#the-conformance-suite) checks this for you. It fails for any route that uses `auth` for Keyring's guard without `keyring.session`, and it names the route.

On each signed-in request, the middleware:

- signs the user out if their registry record was revoked, has expired, belongs to someone else, has been idle for too long, or was [carried on by "remember me" somewhere else](#a-cookie-used-twice),
- registers sessions that started some other way, such as your own `Auth::login()` (on the response that signs in),
- carries a remembered session on when a ["remember me" cookie](#remember-me) signs its browser back in, or signs it out if that session has ended,
- runs the cheap [risk signals](risk.md#checkpoints),
- updates the last activity time, at most once a minute.

A second middleware, `keyring.password`, is added to the `web` group after it. It does nothing until a user is [held for a new password](protected-changes.md#requiring-a-password-change).

A session whose record has gone missing is signed out rather than registered again. This means clearing records can't restart a session's window.

A sign-out your app does itself ends the record as well. Keyring listens for the guard's `Logout` and `CurrentDeviceLogout` events, so on Keyring's guard, in a request with a session, `Auth::logout()` and `Auth::logoutCurrentDevice()` revoke the session's record, forget its "remember me" cookie and clear what the session proved, on any route. If the registry can't be reached, the user is still signed out and the error is reported. After `logoutCurrentDevice()`, the user's "remember me" token is then changed, as `Auth::logout()` already does, so a kept copy of the cookie stops working.

The record also ends when your app empties the session first, as in `$request->session()->invalidate()` followed by `Auth::logout()`, on any route the middleware runs on. The middleware notes the session's record on the request before your code runs, so the sign-out can still find it.

A signed-out request is sent to the login page with the `signed-out` status, and it comes back to where it was going after signing in again. JSON clients get a `401` with `{"status": "signed-out", "message": "...", "page": "login", "redirect": "..."}`, where `redirect` is the login page. Either way, the response sends `Clear-Site-Data`, as signing out does. `Keyring\Events\SessionEnded` is dispatched with the reason, and it's logged as `session_ended`.

### Pages That Also Serve Guests

Some pages work for guests too, like a public page that shows more when you're signed in, or an OIDC authorize endpoint that has to answer `prompt=none` itself. Sending those to the login page when a session ends is wrong. List their route names in `sessions.continue_as_guest`, in any form `Request::routeIs()` takes, wildcards included:

```php
'sessions' => [
    // ...
    'continue_as_guest' => ['welcome', 'oauth.authorize', 'docs.*'],
],
```

When a session ends on a `GET` page visit to one of those routes, the browser is signed out and `SessionEnded` is dispatched as usual. The browser is then redirected back to the URL it asked for, so it asks for the page again as a guest. The query string is kept, though its parameters may come back in a different order. The redirect sends `Clear-Site-Data` and clears the session and "remember me" cookies, as signing out does. The `signed-out` status is flashed, as on the way to the login page, so a page that shows statuses can say why. The page it's redirected to uses the flash up. No intended URL is saved, so the next sign in doesn't come back to this request. JSON requests still get the `401`. `HEAD`, `POST`, and other methods are signed out as before. This happens before your own [`SignedOutResponse`](sign-in-flow.md#responses) is used, so binding one doesn't change it.

This is the same for every reason a session ends, a ["remember me" cookie used twice](#a-cookie-used-twice) (`reused`), a [risk response](risk.md#responding-to-risk) (`risk`), and an [impersonation](impersonation.md#going-back) that ended with nothing to go back to (`impersonator_session_ended`, `lost`) included, which dispatches `ImpersonationEnded` rather than `SessionEnded`. For `reused` and `risk` the login page wouldn't reliably reach the owner anyway: it goes to whichever browser asks next, and the owner's browser, whose session then ends as `revoked`, carries on as a guest. The owner is asked about a reused cookie by its ["was this you?" alert](security-log-and-emails.md#was-this-you-alerts) the next time they sign in, and `SessionEnded` and the security log record the reason either way.

An Inertia visit gets a `409` with an `X-Inertia-Location` header instead of a redirect, which makes Inertia load the page in full. A redirect would be followed with the same headers, so a partial reload or a poll would get back only the props it asked for, and the page would still show the user as signed in. A prefetch gets the same answer. Inertia keeps that answer until the link is followed, and only then loads the page.

Only list pages that render for a guest. The route has to let guests in, because one behind `auth` sends the guest to log in anyway. A broad pattern like `*` also matches Keyring's own pages. A route without a name can't be listed. If any entry in the list isn't a non-empty string, Keyring ignores the whole list, and the visit goes to log in as before.

### "Remember Me"

Laravel's "remember me" cookie holds a token. That token is the same in every browser the user ticked the box in, and nothing on the server makes it run out. On its own, it would sign a browser back in for as long as the browser kept sending it, whatever had happened to the session it came with.

So a remembered sign in also sets a Keyring cookie that holds that session's registry ID. It's httpOnly, `SameSite=Lax`, and lasts as long as the record does. See [Keyring's Cookies](#keyrings-cookies) for its name and for when it's `Secure`. When Laravel's cookie signs a browser back in, the middleware looks up the record that the Keyring cookie names:

- If the record belongs to the user, hasn't been revoked, is inside its `absolute` limit, and was last used within `remember_idle`, the new session carries it on. This happens under a new record and a new cookie. The new record is a copy of the old one with the same start and the same expiry, so coming back never starts the `absolute` limit again. Its device, IP address, and browser are those of the request that came back. Its level starts from nothing, so routes that need a level ask the user to verify. The carried-on session is recorded like a sign in, so a browser the account hasn't used before is announced as a [new device](#new-device-sign-ins).
- Otherwise, the request is signed out like any other ended session, with both cookies cleared. This happens when there was no Keyring cookie, when its record is gone or was never issued (`expired`), or when the record was revoked, timed out, or belongs to someone else. A client that kept the cookies after a timeout or a risk response gets nowhere with them.

The "remember me" sign in is also refused while the account is [risk locked](risk.md#actions).

A session carried on this way dispatches `Keyring\Events\SessionResumed` and is logged as `session_resumed`. As a result, the [security log](security-log-and-emails.md#entry-types) shows every time a browser was signed in, with a proof or without.

Your own `Auth::login($user, remember: true)` gets the Keyring cookie too, on the response that signs in, as long as that route has the middleware. A session given a new registry record (during a mid-session [step-up](risk.md#actions), or with `rotate` on the `cookie` session driver) gets a new cookie for it.

If Laravel's cookie first reaches a route without the middleware, Laravel signs the user in there, and Keyring notes that in the session. The next request the middleware sees is checked the same way.

A remembered browser may stay away for longer than `idle`, up to `remember_idle` (14 days by default). [Timeouts](#timeouts) explains why, and what it comes back to.

### A Cookie Used Twice

Each Keyring cookie works once. Coming back replaces the record it names, and it gives the browser a new cookie. So if two browsers hold the same pair, a copy and the one it was copied from, only the first to come back gets the session.

When the other one turns up, Keyring can't tell which of them is the owner. So the session ends for both:

- the request is signed out, with `reused` as the reason,
- the record the session has moved to since is revoked, however many times it was carried on. This signs the other browser out on its next request (`revoked`),
- `Keyring\Events\RememberMeReused` is dispatched with the `user` and the `session` that was ended, and it's logged as `remember_me_reused`. This is one of the default ["was this you?" alerts](security-log-and-emails.md#was-this-you-alerts).

That happens when a used cookie is sent again, and when a browser is still signed in on a record that "remember me" carried on somewhere else. If the session it was carried on to has timed out since, whether the sweep or the session middleware ended it, the event is still dispatched, with that ended session, and the used record is revoked so the same cookie is only reported once. If the session had been ended some other way, such as signing out, the request is signed out and nothing is reported.

The user's remember token is left alone, so their other remembered browsers stay signed in. Neither holder's cookies lead to a record that still works. To do more, such as signing the account out everywhere or requiring a new password, listen for the event:

```php
use Illuminate\Support\Facades\Event;
use Keyring\Events\RememberMeReused;
use Keyring\Sessions\Sessions;

Event::listen(function (RememberMeReused $event) {
    app(Sessions::class)->signOutEverywhere($event->user);
});
```

A browser that comes back usually sends several requests at once: the page, and whatever it loads alongside. All of them carry the cookie that the first one uses up. So for a few seconds (`sessions.remember_grace`, 10 seconds by default), a request with the cookie that was replaced a moment ago joins the session the first request resumed, as long as it comes from the same browser (the same user agent). It gets the same new cookie, and its own Laravel session points at the same record. It doesn't start another session, change the record, or record a device. The seconds count from when the cookie was replaced, so sending it again doesn't keep it alive. A used cookie from a different browser counts as used twice, however soon it comes.

A shorter time leaves less room for a copy to slip in next to the owner. It also means a slow request of the owner's own is more likely to end their session. Set it to `0` only if a browser's requests never overlap.

## Keyring's Cookies

Keyring sets two cookies of its own. One is the device cookie. The other ties ["remember me"](#remember-me) to its session. Their names depend on how your application is served:

| Your App | Device Cookie | "Remember Me" Cookie |
|---|---|---|
| Served over HTTPS | `__Host-known_device` | `__Host-remembered_session` |
| Served over HTTPS, with `session.domain` set or `session.path` other than `/` | `__Secure-known_device` | `__Secure-remembered_session` |
| Served over plain HTTP, as on `http://localhost` | `known_device` | `remembered_session` |

The names say what each cookie is for, not what set it. OWASP's Session Management Cheat Sheet asks for that, because a name that tells an attacker which software is behind it also tells them what to look up. Laravel's session cookie is yours to name (`SESSION_COOKIE`). See [Secure Cookies](security.md#secure-cookies).

Keyring treats your application as served over HTTPS when `APP_URL` starts with `https://`, or when `session.secure` (`SESSION_SECURE_COOKIE`) is `true`. It goes by those settings and not by the request. The name has to be the same on every request. Behind a proxy that your application doesn't [trust](security.md#trusted-proxies), every request looks like plain HTTP.

Over HTTPS, both cookies are always `Secure`. A browser only accepts a `__Host-` cookie that is `Secure`, has `Path=/`, and has no `Domain`. So another subdomain, or a page loaded over plain HTTP, can't set or replace it. A cookie shared with subdomains can't have that prefix, so Keyring falls back to `__Secure-`, which only promises that the cookie was set over HTTPS. Over plain HTTP, a browser refuses both prefixes, so the plain names are used. The cookies are `Secure` whenever the request itself came over HTTPS.

To use names of your own, set `devices.cookie` and `sessions.remember_cookie`. Keyring uses a name you set exactly as it is, and it's still `Secure` over HTTPS. It's up to you to give it a prefix.

A browser that was given the plain cookies before your application moved to HTTPS keeps its device and its remembered session. While it holds no cookie under the new name, Keyring reads the plain one. The next time that browser signs in, or "remember me" brings it back, it gets the cookie under the new name, and the plain one is deleted. Anything on your domain could have set a plain cookie. So a plain cookie is only ever used to find a device the account already has, never to start a new one.

## For Administrators

Whoever runs the application can end sessions without waiting for them to time out.

```bash
php artisan keyring:sign-out 42
php artisan keyring:sign-out taylor@example.com
php artisan keyring:sign-out --all
```

**One user** is named by ID or by username (the `username` attribute, typed the way the user would type it). The command says who it signed out and how many sessions ended. It does what `Sessions::signOutEverywhere($user)` does. Every session is revoked, the "remember me" token is changed, no device stays trusted, and a pending email change is cancelled, so nothing gets back in without signing in. It dispatches `SessionsRevoked`, which is logged as `sessions_revoked`. If the name is one user's ID and another user's username, nobody is signed out, and the command names both. Run it again with `--id` and the ID of the user you mean.

**Everyone** takes `--all`, and it asks first unless you pass `--force`. Every session that signed in up to that moment ends, whichever record it's on, and each browser is signed out on its next request. "Remember me" brings none of them back. A cookie is only good for the session it names, and a session that was being carried on at that very moment is ended on the record it moved to. People can sign in again straight away. The command only ends sessions. Trusted devices, "remember me" tokens, and pending email changes are left as they are, since signing everyone out says nothing about any one account. It dispatches one `EveryoneSignedOut`, not an event for each session.

From your own code, such as an admin screen, you may use:

```php
use Keyring\Contracts\SessionRegistry;
use Keyring\Facades\Keyring;
use Keyring\Sessions\Sessions;

app(Sessions::class)->signOutEverywhere($user);   // one user, returns how many sessions ended

app(SessionRegistry::class)->revokeEveryone();    // everyone

Keyring::unlock($user);                           // let a locked-out user try again
```

`Keyring::unlock` is the other half of looking after an account. It lifts a [risk lock](risk.md#actions) and the [sign-in lockouts](security.md#rate-limiting) on the account, as a completed password reset does. To keep someone out for good, use [`Keyring::allowSignInWhen`](sign-in-flow.md#who-may-sign-in), and call `signOutEverywhere` as you set your flag. By itself, the gate ends the account's sessions when the first of them next makes a request.

As with every sign-out that isn't the browser's own, these take effect on a session's next request, [where the session middleware runs](#the-session-middleware).

## Timeouts

```php
'sessions' => [
    'idle' => '2h',
    'remember_idle' => '14d',
    'absolute' => '30d',
    'levels' => [
        'aal2' => ['idle' => '1h', 'absolute' => '24h'],
        'aal3' => ['idle' => '15m', 'absolute' => '12h'],
    ],
    'end_on_lapse' => false,
],
```

- **`idle`** ends a session after this much inactivity. The default is two hours, which is the lifetime of Laravel's own session in a new app. Keyring counts it on the registry record, so it holds whatever your session driver and `session.lifetime` are. A session that idled out can't be picked up again. `null` leaves inactivity to Laravel's session lifetime alone.
- **`remember_idle`** is the same limit for a browser that ticked ["remember me"](#remember-me). The default is 14 days. `null` lets it stay away for the whole `absolute` limit.
- **`absolute`** ends a session this long after sign in, however active it is. A browser that comes back on ["remember me"](#remember-me) carries the same session on, under a new record with the same expiry, so that doesn't start the limit again. The browser is also asked to hold Laravel's "remember me" cookie for no longer than this, unless you set your guard's `remember` (in minutes) yourself. That only changes how long the browser keeps it. The cookie still stops working when its session ends.
- **`levels`** sets how long each [assurance level](policies.md#assurance-levels) keeps counting (`aal1`, `aal2`, or `aal3`). The defaults are NIST SP 800-63B-4's reauthentication limits (Sec. 2.2.3 and 2.3.3).
- **`end_on_lapse`** ends a session when the level it signed in at runs out. See [below](#ending-a-session-with-its-level).

### Inactivity and "Remember Me"

Ticking "remember me" asks to stay signed in on that browser between visits, so the two-hour limit can't apply to it. Otherwise, every remembered browser would ask for a sign in again after an afternoon away, and the checkbox would do nothing. Instead, Keyring handles it like this:

- A remembered session isn't ended by `idle`. It's ended by `remember_idle`, after 14 days without a request, and by `absolute`, 30 days after the sign in. Coming back never restarts that limit.
- Once it has been unused for `idle`, it keeps nothing it proved. A browser that comes back on its cookies starts with no level at all. A browser whose Laravel session outlived the two hours has every level lapsed. Either way, routes behind [`keyring:aal2`](step-up.md#raising-assurance) or [`keyring.fresh`](step-up.md#fresh-verification) ask the user to verify again, and so do Keyring's own routes for changing how someone signs in.
- So a remembered browser left unattended still opens whatever sits behind `auth` alone. Put anything that shouldn't be reachable that way behind a level or a fresh verification, or don't offer "remember me". You can avoid offering it by leaving the `remember` field off your login form, or by setting `remember_idle` to the same value as `idle`. NIST SP 800-63B-4 (Sec. 5.1) doesn't accept a cookie in place of authentication at all, so an application that follows it leaves the checkbox out. See [Known Limitations](security.md#where-keyring-departs-from-a-standard).

Set `remember_idle` no shorter than `idle`, or ticking the box would sign people out sooner.

A level lapses on its own clock, without ending the session. It lapses after its `idle` without a request, or after its `absolute` limit counted from the verifications that reached it, however active the session is. The user stays signed in at whatever level is left. Routes that need the lapsed level ([`keyring:aal2`](step-up.md#raising-assurance)) ask them to verify again. Once inactivity has lapsed a level, every factor for that level is asked for again, not only the missing one. Nothing verified before the lapse counts toward it, wherever the user verifies next. Verifying again restarts the idle clock.

### Ending a Session With Its Level

NIST SP 800-63B-4 (Sec. 5.2) says a session is terminated when its inactivity or overall timeout passes. It also lets a session be treated as a lower level than it was authenticated at (Sec. 5.1). That's what Keyring does by default. A session that signed in with two factors stops being AAL2 after an hour idle or 24 hours. It then carries on as the AAL1 session that its password alone would have started, under `idle` and `absolute`. Nothing behind `keyring:aal2` or `keyring.fresh` is reachable in the meantime. This is the default because ending those sessions would sign out the people who set up a second factor after an hour away, and it would leave everyone who didn't set one up signed in for 30 days.

That isn't enough where the whole application is meant to be AAL2, or where you want NIST's wording to the letter. In that case, turn the lapse into the end of the session:

```php
'sessions' => [
    'end_on_lapse' => true,
],
```

- A session ends on the first request after the level it **signed in at** runs out. That's after that level's `idle` without a request, or after its `absolute` limit counted from when the factors were proved. The user is signed out as for any other timeout, with the reason `idle` or `expired` on `SessionEnded`.
- Proving every factor for that level again before then (any [step-up](step-up.md) that asks for them all) starts both limits over, as reauthenticating does in NIST.
- A level reached later by a step-up still lapses on its own, and it takes nothing with it. A session that signed in with a password and stepped up for one page stays an AAL1 session.
- A [risk response](risk.md#responding-to-risk) that asks a signed-in session to step up ends it too. Forgetting what the session proved is its level running out. The reason on `SessionEnded` is `risk`.
- An impersonator whose session signed in above AAL1 is signed out when the impersonation ends, rather than coming back at AAL1. See [Impersonation](impersonation.md#going-back).
- "Remember me" brings nothing back. Its cookie proves nothing, so there's no level for the session to carry on at, and the browser signs in again. NIST doesn't accept such a cookie in place of authenticating either (Sec. 5.1), so leave the checkbox off your login page.
- The timeouts leave sessions signed in at AAL1 as they were, because `idle` and `absolute` already end those.

[Recipes](recipes.md#an-app-whose-every-page-needs-aal2) has the full setup for an application whose every page needs AAL2.

## Pruning

`php artisan keyring:prune` deletes what Keyring no longer needs:

- devices revoked more than 30 days ago, or not seen for a year (`devices.keep_revoked_for` and `devices.keep_unseen_for`),
- email changes that ended (expired, cancelled, reverted, or past their revert window) more than 30 days ago (`email_changes.keep_ended_for`), since they hold both addresses,
- security log entries older than `security_log.keep_for`,
- when an account last removed or replaced an established sign-in method, once that no longer [freezes](authenticators.md#frozen-sign-in-methods) anything (`authenticator_changes.established_after`),
- registered sessions that have expired or been revoked, through the registry's `prune` method. A record "remember me" replaced stays until it would have expired, so its cookie is still recognised as used. Once the [sweep's migration](#sweeping-ended-sessions) has run, a session waits until a sweep has ended and announced it, or for a day, and one the sweep ended for timing out waits until a day after it expired. The cache driver's records expire on their own.

Keyring adds the prune task to Laravel's scheduler itself, every day at 03:00. That means it runs wherever your application's `schedule:run` does, and nothing is kept past its time because a line was left out of `routes/console.php`. `php artisan schedule:list` shows it. To run it at another time, change `prune_at`:

```php
// config/keyring.php
'prune_at' => '01:30',
```

Set it to `null` and Keyring schedules nothing, which leaves scheduling to you. For example, you might run it on one server only, or from a job of your own:

```php
// routes/console.php
use Illuminate\Support\Facades\Schedule;

Schedule::command('keyring:prune')->daily()->onOneServer();
```

Either way, it only runs if your server runs Laravel's scheduler (`* * * * * php artisan schedule:run`), as any scheduled task does.

It runs Laravel's `model:prune` for Keyring's models, including your own [device model](#your-own-device-model). Laravel's plain `model:prune` only looks in `app/Models`, so it won't find them on its own.

## Events

The events are in `Keyring\Events`:

| Event | Properties |
|---|---|
| `NewDeviceSignedIn` | `user`, `device`, and `revokeUrl($days = null)` |
| `DeviceRevoked` | `user`, `device`, `reported` (whether it came from the "this wasn't me" link) |
| `SessionsRevoked` | `user`, `count`. After signing out everywhere else, ending one session, an administrator's `keyring:sign-out` for one user, or the first request refused for an account the application keeps out. |
| `SessionEnded` | `user`, `reason` (`revoked`, `expired`, `idle`, `other_user`, `reused`, `risk`, or `not_allowed`) |
| `RegisteredSessionEnded` | `handle`, `handles`, `userId`, `userType`, `guard`, `deviceId`, `endedAt`, `reason`. One for every registered session that ends. See [Hearing About Ended Sessions](#hearing-about-ended-sessions). |
| `EveryoneSignedOut` | `at`. Every user's sessions ended at once. |
| `RememberMeReused` | `user`, `session` (the `RegisteredSession` that was ended), `handle` |
| `ImpersonationStarted`, `ImpersonationEnded` | `handle` (the impersonated session's), among others. See [Impersonation](impersonation.md#security-log-and-events). |
| `SessionResumed` | `user`, `session` (the `RegisteredSession` a remembered browser carries on as), `handle` |
| `AccessRefused` | `user`, `resource` (`device`, `session`, `authenticator`, or `email_verification`), `id`. A request for a device, session or authenticator that isn't the user's, answered with a 404, or a verification link made for another account. |
| `LinkRefused` | `link` (the route's name), `reason` (`signature` or `expired`). A "this wasn't me" link that was refused. |

`handle` is the session's [handle](#listing-and-ending-sessions). A listener in the request sees the record's registry ID as well, but it's the value of the "remember me" cookie, so a queued listener gets the record with a blank `id` and a null `replacedBy`, and has only the handle to go by.
