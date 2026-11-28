# Impersonation

- [Introduction](#introduction)
- [Turning It On](#turning-it-on)
- [Who May Impersonate Whom](#who-may-impersonate-whom)
- [Routes](#routes)
    - [Starting](#starting)
    - [Stopping](#stopping)
- [From Your Own Code](#from-your-own-code)
- [What Happens to the Sessions](#what-happens-to-the-sessions)
    - [Going Back](#going-back)
    - [Signing Out While Impersonating](#signing-out-while-impersonating)
- [What's Refused While Impersonating](#whats-refused-while-impersonating)
    - [Your Own Routes](#your-own-routes)
- [Showing a Banner](#showing-a-banner)
- [The Time Limit](#the-time-limit)
- [The Sessions List](#the-sessions-list)
- [Security Log and Events](#security-log-and-events)
- [Migrating From Another Package](#migrating-from-another-package)

## Introduction

Impersonation lets someone, usually support staff or an administrator, sign in as another user to see the application as they do, then come back to their own account. Keyring does it with its own [session registry](devices-and-sessions.md#the-session-registry) rather than by editing Laravel's session by hand:

- Nobody may impersonate anyone until your application says who may.
- Starting is a `POST` that needs two factors proved in the last 15 minutes.
- The impersonated session is a session of its own, on a new session ID. Nothing the impersonator proved carries over, and nothing can be proved as the user while it lasts.
- The impersonator's own session is parked, not ended, and their "remember me" cookies are left as they are. Coming back takes that session still being good. Otherwise the browser is signed out. They come back at AAL1 at most, so anything behind `keyring:aal2` asks for their second factor again, and anything that needs a fresh verification asks again too.
- It ends by itself after an hour.
- While it lasts, Keyring refuses every change to how the user signs in, and you can refuse your own routes the same way.
- Step-up can't be met while it lasts: a `keyring:{level}` or `keyring.fresh` route, and `StepUp::unlessMet()`, answer with a `403`. With `keyring:aal2` on every signed-in page, impersonating gets a `403` on all of them, so keep step-up to the routes that need it, or leave it out of your own check when `Keyring::impersonating()` is `true`. See [What's Refused While Impersonating](#whats-refused-while-impersonating).
- The start and the end are logged on both accounts, with why it ended. A start that can't be logged doesn't happen, and a refused start is logged on the impersonator's account.

## Turning It On

Add `Features::impersonation()` to the features in `config/keyring.php`:

```php
'features' => [
    // ...
    Features::impersonation(),
],
```

On the `database` session registry driver, run the migration that adds three columns to `keyring_sessions` for it. `keyring:install` publishes it, and adds only the migrations you don't have yet:

```bash
php artisan keyring:install
php artisan migrate
```

The columns are only written for an impersonated session, so nothing else needs them. Without them, the first start throws a `LogicException` naming the missing columns and these two commands, rather than a database error. The `cache` driver needs no migration.

By default the impersonator needs a second factor: [starting](#starting) takes `keyring:aal2` and `keyring.fresh:15m`. An application that only signs in with a password can ask for a recent password alone in `config/keyring.php`:

```php
'impersonation' => [
    // ...
    'middleware' => ['keyring.fresh:15m'],
],
```

## Who May Impersonate Whom

With the feature on, impersonation is still refused for everyone until you register a callback, usually in your `KeyringServiceProvider`. It's given the impersonator, then the user they want to sign in as, and only `true` lets them:

```php
use App\Models\User;
use Keyring\Facades\Keyring;

Keyring::allowImpersonationWhen(fn (User $impersonator, User $user) => $impersonator->isAdmin() && ! $user->isAdmin());
```

Whatever the callback says, Keyring always refuses:

- impersonating yourself,
- an account Keyring's guard wouldn't load, such as one of another user model,
- a user the application doesn't let sign in ([`Keyring::allowSignInWhen`](sign-in-flow.md#who-may-sign-in)),
- starting while already impersonating someone. It's one at a time.

A [risk](risk.md) lock doesn't refuse an impersonation: it only refuses sign ins, so a locked user can still be impersonated, and a locked impersonator whose session is still signed in can still start one. If a lock should keep support out too, refuse those accounts in your callback.

The callback is asked again on every request while the impersonation lasts, so taking someone's admin role away, or protecting a user, ends an impersonation that's already running. The browser goes back to the impersonator's own session, with the `revoked` [reason](#security-log-and-events).

A callback that throws on one of those requests counts as a no. The exception is reported to your exception handler, and the impersonation ends the same way, rather than every request the browser makes failing, stopping and signing out included, until its cookies are cleared. Before starting, and in `Keyring::allowsImpersonation()` and `Keyring::impersonationRefusal()`, what it throws is thrown on, a `500` if nothing catches it, since nothing has started yet.

On those requests the signed-in user is the one being impersonated, so decide from the two arguments alone. `auth()->user()`, `$request->user()`, and `Gate::allows()` all ask about the user, and would end the impersonation on its first request. To use a gate, ask it about the impersonator:

```php
use Illuminate\Support\Facades\Gate;

Keyring::allowImpersonationWhen(fn (User $impersonator, User $user) => Gate::forUser($impersonator)->allows('impersonate', $user));
```

`Keyring::allowsImpersonation($impersonator, $user)` asks all of that but the last, for a button that only shows when it would work:

```blade
@if (Keyring::allowsImpersonation(auth()->user(), $user))
    <form method="POST" action="{{ route('keyring.impersonation.store', $user) }}">
        @csrf
        <button>Sign in as {{ $user->name }}</button>
    </form>
@endif
```

`Keyring::impersonationRefusal($impersonator, $user)` asks the same, and says why not as an [`ImpersonationRefusal`](#from-your-own-code), or `null` when they may.

## Routes

| Method | URI | Name | Middleware | Does |
|---|---|---|---|---|
| `POST` | `/impersonate/{user}` | `keyring.impersonation.store` | `auth:{guard}`, `keyring.not-impersonating`, `impersonation.middleware`, `keyring` limiter | Signs in as the user with that ID. |
| `POST`, `DELETE` | `/impersonate` | `keyring.impersonation.destroy` | `auth:{guard}` | Stops, and goes back. |

Both are only registered with `Features::impersonation()` on. They sit in Keyring's route group, so they have the `web` middleware and its CSRF check. Neither answers `GET`, so a link or an image on a page can't start or stop one.

### Starting

`{user}` is the user's ID, as Keyring's guard loads them. An ID nobody has gets the same `403` as a user who may not be impersonated, and so does one the database won't look up, such as `abc` for an integer key on PostgreSQL, so the answer doesn't say which IDs have an account. Only the [security log](#security-log-and-events) tells them apart. That's a database error in SQLSTATE class `22`, data the column won't take. Any other database error looking the user up, a deadlock or a dropped connection say, is thrown on as usual.

The route takes `impersonation.middleware`, which is `['keyring:aal2', 'keyring.fresh:15m']` by default: the impersonator has to have proved two factors, the second a possession factor or a passkey, in the last 15 minutes. One who hasn't is sent to confirm, as on any [step-up](step-up.md) route, and one without a second factor is sent to [`enrollment_url`](configuration.md#account-changes-and-enrollment), or gets a `403` without one. An empty list asks for nothing more: any signed-in session your callback allows can start one, with no step-up.

A refusal is a `403`, with `{"status": "impersonation-refused", "message": "You can't sign in as that user."}` for JSON clients, the same whatever the reason, and Laravel's `403` page for a page visit or an Inertia one. Otherwise the answer is a [status response](sign-in-flow.md#status-responses) with `impersonation-started`, to `impersonation.redirect_url` (`home` when it's `null`). A JSON client gets `{"status": "impersonation-started", "message": "...", "redirect": "..."}`. Either way the response sends `Clear-Site-Data`, as signing out does, so nothing the browser cached for the impersonator stays for the user's pages, and the other way round when stopping.

### Stopping

`POST` or `DELETE /impersonate` stops, so a plain form works as well as a `DELETE` from JavaScript. It answers with `impersonation-ended`, to `impersonation.return_url` (`home` when it's `null`). An Inertia visit is told to load that page in full (a `409` with `X-Inertia-Location`), as starting is, so nothing of the other account's page is kept. If the impersonator's own session ended meanwhile, the browser is signed out instead, and the answer is the same as for any session Keyring ended: back to the login page with the `signed-out` status, or a `401` for JSON clients. When the [session middleware](devices-and-sessions.md#the-session-middleware) is the one that finds an impersonation over with nothing to go back to, a page visit to a [route that also serves guests](devices-and-sessions.md#pages-that-also-serve-guests) is asked for again as a guest, as for any other ended session. A browser that isn't impersonating anyone, such as a second stop from a tab left open after another stopped, is back already: a JSON client gets a `409` with `{"status": "not-impersonating", "message": "...", "redirect": "..."}`, and a page visit goes to `impersonation.return_url` with the `not-impersonating` status (an Inertia visit loads it in full). Nothing changes hands, so it sends no `Clear-Site-Data`.

An impersonation that had already ended by itself, its [time limit](#the-time-limit) up or its session ended by the user, never reaches the route: the [session middleware](devices-and-sessions.md#the-session-middleware) ends it first, goes back, and answers a JSON client with a `409` and the `impersonation-ended` status. The browser is back in the impersonator's account either way.

```blade
<form method="POST" action="{{ route('keyring.impersonation.destroy') }}">
    @csrf
    <button>Back to my account</button>
</form>
```

From the [browser package](frontend.md):

```ts
import { impersonate, stopImpersonating } from '@keyringjs/keyring'

await impersonate(user.id)     // { status: 'impersonation-started', redirect: 'https://example.com/dashboard' }
await stopImpersonating()      // { status: 'impersonation-ended', redirect: 'https://example.com/dashboard' }
```

Load the page in full afterwards, at the `redirect` the answer gives, so nothing on the page is left from the other account. `stopImpersonating()` resolves the same way, with that `status`, for the middleware's `409` `impersonation-ended` and the route's `409` `not-impersonating`, since the browser is back either way, and throws for the `401` when it was signed out instead.

## From Your Own Code

The routes call the same methods you can, for a controller of your own:

```php
use App\Models\User;
use Illuminate\Http\Request;
use Keyring\Exceptions\ImpersonationRefused;
use Keyring\Facades\Keyring;

Route::post('/admin/users/{user}/impersonate', function (Request $request, User $user) {
    Keyring::impersonate($request, $user);   // throws ImpersonationRefused

    return redirect('/dashboard');
})->middleware(['auth', 'keyring.not-impersonating', 'keyring:aal2', 'keyring.fresh:15m'])->block();

Route::delete('/admin/impersonation', function (Request $request) {
    if (! Keyring::impersonating($request)) {
        return redirect('/admin/users');   // back already: a second stop, from a stale tab say
    }

    $impersonator = Keyring::stopImpersonating($request);   // null when it signed out instead

    return $impersonator === null ? redirect('/login') : redirect('/admin/users');
})->middleware('auth')->block();
```

`Keyring::impersonate()` checks who may, but not how the request got there: keep it to a `POST` with the middleware above, as Keyring's route does. Keep `->block()` too, as Keyring's routes have it. Without it, two starts sent at once from the same browser, a double click say, both find nobody being impersonated yet, and each starts one. Laravel's [session blocking](https://laravel.com/docs/session#session-blocking) makes them take turns, so the second is refused as `impersonating`. It needs a cache store that supports locks.

`Keyring::stopImpersonating()` throws a `LogicException` when nobody is being impersonated, which left uncaught is a `500`. A browser that stops twice, or a tab left open from before, gets there, so check `Keyring::impersonating()` first, as above and as Keyring's route does, which answers that it's back already (`not-impersonating`).

Keyring's routes also send `Clear-Site-Data`, and tell an Inertia visit to load the next page in full, so nothing the browser kept from one account's pages is left for the other's. A route of your own does neither: send `Clear-Site-Data: "cache", "storage"` yourself, and answer an Inertia visit with `Inertia::location()`, to get the same.

`ImpersonationRefused` is Laravel's `AuthorizationException`, so left uncaught it's a `403`, whatever the reason: `{"status": "impersonation-refused", "message": "..."}` for JSON clients, as from Keyring's route, and Laravel's `403` page otherwise. Its `reason` says why, as a `Keyring\Enums\ImpersonationRefusal`:

| Case | Value | Why |
|---|---|---|
| `Disabled` | `disabled` | `Features::impersonation()` is off. |
| `NoCallback` | `no_callback` | The feature is on, but [`Keyring::allowImpersonationWhen()`](#who-may-impersonate-whom) was never called, so nobody may impersonate anyone yet. |
| `Self` | `self` | The impersonator asked to sign in as themselves. |
| `NotAllowed` | `not_allowed` | The callback didn't answer `true`, the user may not sign in, or one of the two isn't an account Keyring's guard loads. |
| `Impersonating` | `impersonating` | The session is impersonating someone already. |
| `Unregistered` | `unregistered` | The impersonator's session has no record in the registry to come back to. |
| `NotFound` | `not_found` | Keyring's route found nobody with that ID. It's only [logged](#security-log-and-events): what's thrown is `NotAllowed`, so the answer doesn't say which IDs have an account. |

`disabled` and `no_callback` mean impersonation isn't set up yet, so a forgotten callback doesn't look like the callback saying no. The answer is the same `403` as for any refusal, so Keyring also writes a warning to your app's log naming what's missing, `Features::impersonation()` or `Keyring::allowImpersonationWhen()`, once a request. Each refusal is logged as `impersonation_refused` on the impersonator's account, with that value, and so is one that never gets this far because Keyring's route found no user with that ID. A start that can't be logged throws whatever the security log threw, and leaves the browser as it was. The user's session record it had saved is ended without a `RegisteredSessionEnded`, as nobody used it, and the [sweep](devices-and-sessions.md#sweeping-ended-sessions) doesn't announce it later either. The same goes for a start that's logged but then fails handing the browser over, such as when a listener of yours for Laravel's `Authenticated` event throws: the browser is put back as the impersonator's session was, and the end is logged straight after the start, with the `failed` [reason](#security-log-and-events). Neither `ImpersonationStarted` nor `ImpersonationEnded` fires for it.

These answer questions about the current request:

| Method | Returns |
|---|---|
| `Keyring::impersonating()` | Whether the session is impersonating someone. |
| `Keyring::impersonator()` | Who is, as your user model, or `null`. It's `null` too once they've been deleted. |
| `Keyring::impersonation()` | What a [banner](#showing-a-banner) needs, or `null`. |

`Keyring::user()` and `Auth::user()` are the impersonated user throughout.

## What Happens to the Sessions

Starting gives the browser a new session ID, and a session record of its own for the user. That record:

- names the impersonator and the record of their own session,
- proved nothing, so its level is none, whatever the impersonator had proved,
- is never remembered, and is on no device,
- lasts no longer than `impersonation.lifetime`,
- isn't one of the user's own [`sessions.max`](devices-and-sessions.md#how-many-sessions): it doesn't end one of their sessions to make room when it starts, doesn't count toward the limit when the user signs in again, and isn't ended to make room for them.

The session keeps nothing the impersonator's had for Keyring: what they proved, a sign in or confirm in progress, Laravel's `auth.password_confirmed_at`, the password hash Laravel's `auth.session` middleware compares, and Laravel's `url.intended`. Going back forgets `url.intended` too, so a page of the user's can't choose where the impersonator's next confirm or sign in sends them.

The rest of your application's session data is left as it is, and carries over both ways: into the user's session when it starts, and back into the impersonator's when it ends. If your application keeps anything about who is signed in in the session, such as their roles, their team or tenant, or an "is admin" flag, the user's pages see the impersonator's, and the impersonator comes back with whatever the user's pages put there. Look those up from the signed-in user on each request instead, or key them by the user's ID, or forget them when `ImpersonationStarted` and `ImpersonationEnded` fire.

Keyring doesn't call `Auth::login()`, so Laravel's `Login` event and Keyring's `Authenticated` don't fire for the user. Nothing that listens for a sign in, such as new device emails, risk signals, or a "last signed in" column of your own, takes it for one. Risk signals aren't assessed on the impersonated session's requests either, and [`InactiveAccount`](risk.md#built-in-signals) doesn't count the impersonated session as the user using their account, so a dormant account still gets its finding when its owner, or someone with their password, next signs in.

The impersonator's own session isn't ended. Its record stays good, and while the impersonator is busy it's kept from idling out along with the impersonated one, and so are its levels: they're the one using the browser all along. A gap between requests longer than a level's idle limit still lapses that level, as it would in their own session. Their "remember me" cookies aren't touched. What it had proved, and the password hash Laravel's `auth.session` middleware compares, are kept aside in the session, where nothing reads them until they come back.

### Going Back

Stopping, or the [time limit](#the-time-limit), ends the impersonated session's record and goes back to the impersonator's, on a new session ID, as long as:

- the impersonator still exists, may still sign in, and isn't [held for a new password](protected-changes.md#requiring-a-password-change),
- their password hasn't changed since the impersonation started: Keyring keeps its hash from the start, in the form Laravel's `auth.session` middleware compares, and compares it with theirs now, whether or not that middleware runs. A password set on an account that had none when it started, or removed from one that had one, is a change too. An impersonator who had no password then and still has none goes back,
- their session's record is still good: not revoked, not expired, and not idled out,
- the browser's session is still the impersonation it started: on the impersonated session, signed in as its user.

Their own session's levels are kept under its own limits while they're away. Their requests while impersonating count as activity for it, so a level doesn't lapse, or end the session under `sessions.end_on_lapse`, just because the impersonation went on for longer than its idle limit. Going without a request for longer than that does lapse it, as in their own session. Under `sessions.end_on_lapse`, a gap that lapses the level their session signed in at ends it, and the browser is signed out with the `impersonator_session_ended` reason rather than going back.

They come back at AAL1 at most, whatever their session had reached. A page of the user's account, a stored script say, could have sent the stop: it runs in the impersonator's browser, can read the CSRF token, and keeps running once the browser is theirs again. So Keyring forgets their second factor: of what they proved, it keeps only as much as stays short of AAL2, putting what isn't something they have first. Beside an authenticator app or a security key, that's their password, which still counts toward AAL1. An authenticator app's code that was all they proved is short of AAL2 on its own, so it's kept. A `keyring:aal2` or `keyring:aal3` route asks them to [step up](step-up.md) again, and since the password still counts, that's the second factor alone. A passkey that verified them is both factors at once, so after signing in with one alone, nothing is kept and the passkey is asked for again. Nothing they proved counts as fresh either, so `keyring.fresh` and Laravel's `password.confirm` ask again. Their record in the [sessions list](devices-and-sessions.md#listing-and-ending-sessions) shows the level they came back at, until a step-up raises it. The password hash Laravel's `auth.session` middleware compares is put back. If their session had ticked "remember me", it still has.

Under [`sessions.end_on_lapse`](devices-and-sessions.md#ending-a-session-with-its-level), a session doesn't outlive the level it signed in at, as with a "remember me" cookie or a risk step-up there. Coming back at AAL1 would be that level running out for a session that signed in above AAL1, so the impersonator doesn't come back: the browser is signed out, their session ends, and the end is logged and announced once, with the `impersonator_session_ended` reason. The same goes for a session that signed in at AAL1 but held that level only by what coming back forgets, an authenticator app's code beside a password past AAL1's overall limit say. Any other session that signed in at AAL1 comes back as usual.

Put your admin routes behind `keyring:aal2` (or a [fresh verification](step-up.md#fresh-verification)), not `auth` alone. A script on the user's pages that sends the stop is then held at the step-up, which it can't get past without the impersonator's second factor, while a route behind only `auth` is open to it as soon as the browser is the impersonator's again.

Going back also moves the impersonator's session to a new record, as a [step-up](step-up.md) does, on every session driver. A copy of the session from while they were impersonating then has nothing to go back to, and is signed out. On Laravel's `cookie` driver that's a copy of the cookie, which lives in the browser where nothing can destroy it. On the others it's a request that overlapped the stop and saved the old session after it. If their session ticked "remember me", Keyring's cookie that ties it to the record moves to the new one. Laravel's own cookie is left as it is.

Only one request ends an impersonation, however many of the browser's find it over at once, such as XHRs that were on their way as the time limit ran out, or a copy of the session from before another request ended it. The first to claim its end goes back, or signs out, and is the only one that logs the end and fires `ImpersonationEnded`. Only ending an impersonation claims it, so when its record was ended some other way meanwhile, by the user from their sessions list, "sign out everywhere", a password change, a risk response, `keyring:sweep` or `keyring:sign-out` say, the request that finds it ended still ends the impersonation. The claim is kept in the rate limiter's cache store (`cache.limiter`, or your default), as [answered WebAuthn challenges](security.md#single-use-codes) are, for as long as the impersonation had left plus your `session.lifetime`, so every server has to share that store. If the store fails, the request ends it anyway and the failure is reported: the end could then be logged twice, rather than not at all. A copy of the session never goes back, whichever request claims it: by then the impersonator's session it parked has moved to a new record, or ended. Any other is answered as signed out with the `lost` reason, and touches nothing: no end is logged or announced, no record is ended or moved, and the "remember me" cookies are left as they are. Its own copy of the session is emptied, so the browser holds a guest's session if that answer is the last to arrive, rather than ending it again. A browser that ticked "remember me" is then signed back in to the impersonator's session by its cookie, at no level, as after any other "remember me" sign in. One that didn't signs in again.

If any of that no longer holds, the browser is signed out, and the impersonator's session ends with it. That includes the impersonator's own session being ended from somewhere else while they were impersonating, such as by "sign out everywhere" on another browser. It also includes any change to their password hash while the impersonation runs, even one that doesn't end their sessions: Keyring's own password change on another browser with `sign_out_others` off, your own code saving it with the query builder or inside `Keyring::withoutProtection()`, Laravel rehashing it when they sign in somewhere else after you raised the hashing cost, and a password set or removed. A password they changed before starting, in the same session, doesn't count. The next request notices and signs out. So does a session whose user can no longer be loaded, deleted say, and one someone else has signed in on, such as with your own `Auth::login()`: the reason is `lost`. Signing in on a session that still holds an impersonation, however it got there, ends it first. If the session registry can't end it then, the browser is signed out and the error is thrown on, rather than carrying on as the user.

### Signing Out While Impersonating

Signing out with Keyring's `POST /logout` while impersonating signs the browser out of both: the impersonated session, and the impersonator's parked one, since nobody can come back to it now. The user's "remember me" token is left alone, so the user's own remembered browsers aren't signed out.

When the session registry can't be reached, the browser is still signed out, as it is for any sign-out, and the error is thrown on. The browser's "remember me" cookies are the impersonator's, and their parked session is what refuses a copy of them, so when that session couldn't be ended the impersonator's "remember me" token is changed instead. The user's is never changed for it. The end is still logged, and `ImpersonationEnded` still fires, once, with the `signed_out` reason, also when a later go ends the parked session.

Your application's own `Auth::logout()` ends both sessions the same way, also after `$request->session()->invalidate()`. But Laravel's guard changes the user's "remember me" token whenever it logs out, which signs out every other browser where the user ticked "remember me", so use Keyring's sign-out, or `Auth::logoutCurrentDevice()`, while impersonating.

## What's Refused While Impersonating

Keyring refuses all of these with a `403`, and `{"status": "impersonating", "message": "..."}` for JSON clients:

- changing the password,
- changing the email address, or cancelling a change,
- adding, confirming, renaming, and removing authenticators,
- ending sessions and devices, "sign out everywhere else" included,
- confirming who they are: the confirm page, its challenges, and the identity provider confirm,
- verifying the email address with the emailed link's button, and sending the link again,
- starting another impersonation.

Step-up can't be met either. A `keyring:{level}` or `keyring.fresh` route the session hasn't already met answers with the same `403`, rather than sending the impersonator to a confirm page that would refuse them. The impersonated session starts having proved nothing, so in practice that's every such route. A route with `keyring.enrolled`, or a user [held for a new password](protected-changes.md#requiring-a-password-change), lets the impersonator through, since only the user can do what those ask.

Listing the user's sessions and devices still works, as does `GET /user/email`, which shows a pending new email address, and signing out.

### Your Own Routes

Put `keyring.not-impersonating` on the routes of your own that only the user should use, like deleting the account, changing billing details, or creating API tokens:

```php
Route::delete('/account', [AccountController::class, 'destroy'])
    ->middleware(['auth', 'keyring.not-impersonating', 'keyring.fresh:5m']);
```

It answers with the same `403`, and lets everyone else through.

## Showing a Banner

`Keyring::impersonation()` gives what a page needs to say who is impersonating, with a way to stop, or `null` when nobody is. It's read from the session, so it costs no query. Share it through your Inertia middleware:

```php
use Keyring\Facades\Keyring;

public function share(Request $request): array
{
    return [
        ...parent::share($request),
        'impersonation' => fn () => Keyring::impersonation($request),
    ];
}
```

```json
{
  "impersonator": { "id": "1", "name": "Ada Admin" },
  "startedAt": "2026-11-27T09:00:00+00:00",
  "expiresAt": "2026-11-27T10:00:00+00:00",
  "stopUrl": "https://example.com/impersonate"
}
```

The name is the impersonator's `name` attribute, or their username without one. `expiresAt` is when it [ends by itself](#the-time-limit): `impersonation.lifetime` after it started, or sooner when `sessions.absolute` is shorter. `stopUrl` is Keyring's [stop route](#stopping), or `null` when Keyring's routes aren't registered: with `routes` set to `false` in `config/keyring.php` and no `Keyring::routes()` of your own. Stop through a [route of your own](#from-your-own-code) then. The browser package types it as `Impersonation`:

```tsx
import { router, usePage } from '@inertiajs/react'
import type { Impersonation } from '@keyringjs/keyring'

export function ImpersonationBanner() {
  const { impersonation } = usePage<{ impersonation: Impersonation | null }>().props

  if (!impersonation) return null

  return (
    <div role="status">
      You ({impersonation.impersonator.name}) are signed in as this user.
      <button onClick={() => router.delete(impersonation.stopUrl!)}>Stop impersonating</button>
    </div>
  )
}
```

Keyring answers Inertia's `DELETE` by having it load the page it goes back to in full, so the banner and the rest of the user's page go with it.

In Blade:

```blade
@if (Keyring::impersonating())
    <div role="status">
        Signed in as {{ auth()->user()->name }}.
        <form method="POST" action="{{ route('keyring.impersonation.destroy') }}">
            @csrf
            <button>Back to my account</button>
        </form>
    </div>
@endif
```

## The Time Limit

An impersonation ends by itself `impersonation.lifetime` after it started, an hour by default. It's a [duration](configuration.md#durations), and never longer than `sessions.absolute`. On the next request after that, the [session middleware](devices-and-sessions.md#the-session-middleware) ends it and goes back to the impersonator's session, as stopping does.

Left unused for `sessions.idle`, it ends sooner. The impersonator's own session has then gone unused as long, so unless it ticked "remember me", which gives it `sessions.remember_idle`, it has idled out too, and the browser is signed out like any other [ended session](devices-and-sessions.md#the-session-middleware). When it does go back, a page visit is sent to `impersonation.return_url` with the `impersonation-ended` status. An Inertia visit is told to load that page in full, and a JSON request gets a `409` with `{"status": "impersonation-ended", "message": "...", "redirect": "..."}`, since what it asked for was the user's.

## The Sessions List

With `impersonation.show_in_sessions` on, which is the default, the impersonated session is in the user's own [sessions list](devices-and-sessions.md#listing-and-ending-sessions), marked as such and with the impersonator's name:

```json
{
  "id": "9f2c41d0...",
  "name": null,
  "ip": null,
  "device": null,
  "remembered": false,
  "signedInAt": "2026-11-27T09:00:00+00:00",
  "lastActiveAt": "2026-11-27T09:12:00+00:00",
  "expiresAt": "2026-11-27T10:00:00+00:00",
  "current": false,
  "impersonated": true,
  "impersonator": { "name": "Ada Admin" }
}
```

It shows no browser, IP address, or device: those would be the impersonator's, so the user would see where support staff are and what they use. Keyring doesn't keep them on the impersonated session's record at all, and `name`, `ip`, and `device` are always `null` for it in the list, whatever a [registry of your own](devices-and-sessions.md#the-session-registry) stores. The times are its own. The [security log](#security-log-and-events) keeps them off the user's account too.

The user can end it from there, like any of their sessions. The impersonator's next request then goes back to their own session. `impersonator` has only their name, not their ID as [`Keyring::impersonation()`](#showing-a-banner) does, since the user has no use for it. It's `null` once the impersonator has been deleted.

With `show_in_sessions` off, it's left out of the user's list, except to the impersonated session itself: the list it asks for still has it, as `current`, since that browser knows it's there anyway. It's still one of their sessions: "sign out everywhere else", a password change, or anything else that ends all their sessions ends it too. So it isn't perfectly invisible: the number of sessions "sign out everywhere else" says it ended counts it.

## Security Log and Events

Each start and end is logged on both accounts, as `impersonation_started` and `impersonation_ended`. The start is written before the browser changes hands, and before `ImpersonationStarted` fires, so a listener of yours that throws can't leave it unlogged. If it can't be written, the start is refused and the browser stays as it was. An end is logged once its sessions have been ended, even if signing the browser out or moving the impersonator's session to a new record fails after that. If handing the browser back to the impersonator fails, or moving their session to a new record does, the impersonator's session ends too and the browser is signed out, so the next request is a guest's, the end isn't logged twice, and no copy of the session can go back to a record that didn't move. The user's entries have no IP address or user agent, as those would be the impersonator's, and neither does anything else written on the user's account while the impersonation runs. The impersonator's entries keep them. Both entries carry `impersonator` and `user`, the two accounts' IDs, and `role`, which is `impersonator` or `impersonated` for the account the entry is on. An end also has `reason` and `returned`, which says whether the browser went back to the impersonator's session. Once the impersonator has been deleted, the end is only logged on the user's account, with a `null` `impersonator`, and once the user has, only on the impersonator's, with a `null` `user`. See [Entry Types](security-log-and-emails.md#entry-types).

A refused start is logged as `impersonation_refused` on the impersonator's account, with `reason` and `user`, the ID asked for. The reason is an [`ImpersonationRefusal`](#from-your-own-code) value: `not_found` for an ID nobody has, which gets the same `403` as `not_allowed`, or the one `ImpersonationRefused` was thrown with. Like Keyring's other refusals, it's written at most `security_log.refusals` times every `refusals_per` period. A browser that's already impersonating is turned away from Keyring's route by `keyring.not-impersonating` before it gets that far, and that isn't logged.

The reasons are the `Keyring\Enums\ImpersonationEndReason` enum:

| Reason | When |
|---|---|
| `stopped` | The impersonator stopped. |
| `expired` | It ran for `impersonation.lifetime`, or its session idled out. |
| `revoked` | Its session was revoked some other way: by the user from their sessions list, by signing out everywhere, a password change, a risk response, the user no longer being allowed to sign in, or the impersonator no longer being allowed to impersonate them. |
| `impersonator_session_ended` | There was nobody to go back to: the impersonator's session had ended, or they were deleted, may no longer sign in, are held for a new password, or their password changed. Under `sessions.end_on_lapse`, also a session that signed in above AAL1, which [coming back at AAL1](#going-back) would lapse. The browser was signed out. |
| `lost` | The browser's session no longer held the impersonation it started: the user can no longer be loaded, someone else is signed in on it, or it lost what it had parked. The browser was signed out, and the impersonator's parked session ends with it, found from the impersonated session's record when the browser's session no longer says. A request of the browser's that another one [beat to ending it](#going-back) is answered with `lost` too, with nothing logged or announced for it. |
| `signed_out` | The browser signed out while impersonating, or someone signed in on a session that still held one. |
| `failed` | Starting failed after the start was logged, handing the browser over, so the browser stayed the impersonator's and `returned` is `true`. It's only logged: `ImpersonationEnded` never has it, as `ImpersonationStarted` never fired. |

`stopped`, `expired`, and `revoked` go back, as long as the impersonator's session is still good. When it isn't, the reason is `impersonator_session_ended`, or `lost`. The browser is signed out with that reason too: a [`SignedOutResponse`](sign-in-flow.md#responses) of your own is built with `impersonator_session_ended` or `lost`.

Keyring dispatches `ImpersonationStarted` (`impersonator`, `user`, and `handle`) and `ImpersonationEnded` (`impersonator`, `user`, `reason`, `returned`, and `handle`). `handle` is the impersonated session's [handle](devices-and-sessions.md#listing-and-ending-sessions), the same in both, and the same one the user's sessions list shows it under. `ImpersonationEnded`'s is `null` only when nothing says which session it was, such as an impersonation that started before Keyring noted it, and it still fires. In `ImpersonationEnded`, `impersonator` is `null` once deleted, and `user` is `null` once the user can no longer be loaded. One of the two is always there. `user` is always the user who was impersonated, even if your application signed someone else in on the session meanwhile. `ImpersonationEnded` fires in the request of the browser that was impersonating, when it stops or notices it has ended, and in only one of them when several notice at once. An impersonation whose browser never comes back isn't announced by it, but its session's `RegisteredSessionEnded` still is, by the [sweep](devices-and-sessions.md#sweeping-ended-sessions) if nothing else, with the `expired` reason. To tell which impersonation it was, look for the handle `ImpersonationStarted` gave in its `handles`, which has the handle under each of your app's keys, so it still matches after `APP_KEY` is rotated. The records an impersonation ends itself are announced with `impersonation_ended`. See [Events](events.md#sessions-and-devices).

No email is sent by default. To tell users, listen for `ImpersonationStarted` and send your own. To keep the entries out of [`Keyring::activity`](security-log-and-emails.md#showing-recent-activity), set `impersonation.show_in_activity` to `false`. That hides them from the impersonator's activity too, and from a query of your own that leaves out `Keyring::unlistedActivityTypes()`. They're still written. Listing the two types in `security_log.unlisted` doesn't hide them, as with any of Keyring's own types: a package could add them there without your app knowing.

## Migrating From Another Package

From `lab404/laravel-impersonate`, or `stechstudio/filament-impersonate` and Nova's impersonation, which build on the same idea:

| Before | With Keyring |
|---|---|
| `canImpersonate()` and `canBeImpersonated()` on the model | One `Keyring::allowImpersonationWhen()` callback, given both. Nobody may until it's registered. |
| `Route::impersonate()`, with `GET /impersonate/take/{id}` and `GET /impersonate/leave` | `POST /impersonate/{user}` and `POST` or `DELETE /impersonate`, which need a fresh second factor to start. |
| `$manager->take($from, $to)` and `$manager->leave()` | `Keyring::impersonate($request, $user)` and `Keyring::stopImpersonating($request)` |
| `isImpersonating()`, `@impersonating` | `Keyring::impersonating()` |
| `$manager->getImpersonatorId()` | `Keyring::impersonator()?->getKey()` |
| The `impersonate.protect` middleware | `keyring.not-impersonating` |
| `TakeImpersonation` and `LeaveImpersonation` events | `ImpersonationStarted` and `ImpersonationEnded` |
| No time limit | `impersonation.lifetime`, an hour by default |

Some things work differently:

- Going back restores the impersonator's own session, and only while it's still good. The packages above sign the impersonator back in by their ID alone, and edit the password hash Laravel keeps in the session by hand.
- Nothing the impersonator proved carries over, and the impersonated session can't step up, so routes behind `keyring:aal2` or `keyring.fresh` are refused while impersonating.
- Keyring's own security changes are refused while impersonating, without any middleware of yours.
- Both accounts' security logs say who impersonated whom, and why it ended.

Take out the package's routes, its trait, and its middleware, register the callback, and swap its Blade directives and route names for Keyring's. Anyone impersonating when you deploy is left signed in as the user, on a session Keyring doesn't know is impersonated, until they sign out.
