# Step-Up

- [Introduction](#introduction)
- [Raising Assurance](#raising-assurance)
- [Fresh Verification](#fresh-verification)
- [Asking From a Controller](#asking-from-a-controller)
    - [Passing a Fixed Moment](#passing-a-fixed-moment)
    - [Asking Without Starting a Confirm](#asking-without-starting-a-confirm)
    - [An Example](#an-example)
- [Reading What Was Proved](#reading-what-was-proved)
- [The Confirm Flow](#the-confirm-flow)
- [JSON Requests](#json-requests)
- [Laravel's Password Confirmation](#laravels-password-confirmation)
- [Events](#events)

## Introduction

Step-up asks a signed-in user to prove something again before they continue. Keyring provides two middleware for this:

- `keyring:{level}` requires the session to have reached an [assurance level](policies.md#assurance-levels).
- `keyring.fresh:{window}` requires a verification within a time window.

You may use either one as route middleware, or with Laravel's `#[Middleware]` attribute, which takes one middleware per attribute. Always place them after `auth`. They read the user from Keyring's guard (`Keyring::user()`), not the default guard. A request with nobody signed in to that guard gets Laravel's usual `AuthenticationException`. For example:

```php
use Illuminate\Routing\Attributes\Controllers\Middleware;

#[Middleware('auth')]
#[Middleware('keyring:aal2')]
class BillingController
{
    #[Middleware('keyring.fresh:15m')]
    public function destroy()
    {
        // ...
    }
}
```

Or, if you prefer to attach it to a route definition:

```php
Route::delete('/account', [AccountController::class, 'destroy'])
    ->middleware(['auth', 'keyring.fresh:5m']);
```

## Raising Assurance

`keyring:aal2` lets the request through when the session has reached AAL2 or higher. `keyring:aal1` and `keyring:aal3` work the same way. On its own, `keyring` means `keyring:aal2`. An unknown level name throws an `InvalidArgumentException`.

`keyring:aal3` needs a key that was added with a [verified attestation](passkeys.md#attestation-and-aal3). An application that doesn't check attestation can ask for more of AAL2 by name instead. `keyring:aal2,device-bound` requires a phishing-resistant key that stays on its device, among what the session proved. `keyring:aal2,phishing-resistant` requires any passkey or security key. [`keyring.enrolled`](policies.md#requiring-a-second-factor) takes the same names.

The middleware counts everything proved so far in the session, so it only asks for what's missing. An emailed code isn't a factor, so it counts for nothing here. A user who signed in with a password is asked for a possession factor to reach AAL2. A user who signed in with a passkey is already at AAL2. That user is at AAL3 too, if the passkey stays on its device and was added with a verified attestation.

A level doesn't last for the whole session. It lapses after its idle and overall limits. By default, at AAL2, those are an hour without a request or 24 hours, as NIST SP 800-63B-4 asks. After that, the next `keyring:aal2` route asks again. See [Timeouts](devices-and-sessions.md#timeouts). To end the session at that point instead, see [Ending a Session With Its Level](devices-and-sessions.md#ending-a-session-with-its-level). The idle limit is tracked by the [session middleware](devices-and-sessions.md#the-session-registry), which Keyring adds to the `web` group. Routes outside that group, such as Sanctum's `api` group, need `keyring.session` too. A [risk response](risk.md#checkpoints) can also clear a level. An authenticator that's removed stops counting in every session it was used in.

A browser that's [impersonating](impersonation.md#whats-refused-while-impersonating) the user can't step up as them: a level it hasn't reached, or a fresh verification, is refused with a `403` rather than a confirm.

Users who don't have the authenticators to reach a level can't get there by confirming. Instead, they're sent to your [`enrollment_url`](configuration.md#account-changes-and-enrollment) with the `enroll-first` status, the same as the [`keyring.enrolled`](policies.md#requiring-a-second-factor) middleware does. JSON requests get a `403` with that status and the URL. Without an `enrollment_url`, they get a plain `403`.

To check the session's level in your own code, ask `Keyring\Sessions\SessionAssurance`:

```php
use Keyring\Enums\Assurance;
use Keyring\Sessions\SessionAssurance;

app(SessionAssurance::class)->level()->atLeast(Assurance::AAL2);
```

## Fresh Verification

`keyring.fresh:15m` lets the request through when the user verified, in the last 15 minutes, the strongest combination their account can give, and at least as much as signing in would ask of them. The window takes any [duration](configuration.md#durations), and it defaults to `15m`.

NIST SP 800-63B-4 (Sec. 4.1.2.1) binds a new authenticator at the highest level the account can authenticate at, or at the level the new one will be used at if that's lower. Keyring always asks for the highest level, so what's asked here follows the account, not the sign-in policy:

- Users with only a password confirm with their password, so an account can always add its first sign-in method.
- Users with two factors prove both again, even where the policy would sign them in with one. A stolen session that's no longer fresh, plus one phished factor, can't add, remove, or change anything.
- Users with a key that can't leave its device use that key, with its own user verification or their password alongside it. A password and an authenticator app's code isn't enough for them, whatever the policy says. This applies to an attested key, which could reach AAL3, and to a key that nothing vouches for. Only an [established](authenticators.md#established-authenticators) key counts here. So a key added from a stolen session isn't the one thing the owner has to prove to remove it.
- A recovery code stands in for a lost key, along with the password, as it does at sign in. A policy that takes no codes there (`noDowngrade(except: [])`, or an explicit `phishingResistant()`) takes none here either. A code is never the whole of a confirmation. A user whose only other sign-in method is a set of recovery codes confirms with the password, and isn't offered the codes.
- Users who have any possession factor (an authenticator app, a passkey, or a security key) always use one. An [email code](factors.md#email-codes) isn't a possession factor, so it can't stand in. A user whose only other sign-in method is an emailed code proves the password and that code. That's what lets them add a real second factor.
- A policy the user can't fully meet yet, such as one that asks for a passkey they haven't added, counts as far as they can go, so they can still add it.
- A policy that asks for more than that is honoured. A [policy closure](policies.md#deciding-per-user-and-attempt) is asked about the browser the request comes from, and about an attempt nothing is known of, and the stricter answer stands. A policy that asks more of a new device is honoured, and a trusted device gets no discount. Risk isn't assessed again, so a policy that reads `$attempt->risk` is asked with none.
- The window starts at the moment of verification, and it doesn't slide with activity. Using the app doesn't keep it fresh.
- A link at an [identity provider](sso.md#step-up) is offered on the confirm page as its [`freshness`](sso.md#freshness) says, and sends the user back to the provider. With `reauthenticate`, the default for any OpenID Connect provider and Microsoft, it has them sign in again there. With `never`, the default for Google and GitHub, it's only offered toward a level, as a plain round trip that counts as much as signing in with it again would and never as fresh: on a `keyring.fresh` page the user confirms another way, and it's left out of what that asks of them. A user with nothing else is sent to enroll, and their way out is a [password reset](sso.md#users-whose-only-way-in-is-never-fresh). Only a provider you opt into `round_trip` is a plain round trip that proves as much as signing out and in with it again would, which may be nothing more than a session the user still has there.
- Signing in counts as a verification, so a fresh login is also fresh for step-up. A sign in with an identity provider whose `freshness` is `reauthenticate` counts from when the user last signed in at the provider, as its ID token says (`auth_time`), so one the provider let straight through on an old session isn't fresh, and one without `auth_time` never is. One with a `never` provider is never fresh. So does [adding a sign-in method](authenticators.md#confirming), for the method that was added.

Signing in counts, so whoever holds a copy of a session that has just signed in can use it for those 15 minutes, without proving anything. On an account with an established second factor, they can add a sign-in method of their own. Keyring limits what that gets them:

- A second factor on an account with none established yet, such as a password-only account, takes [the current password](authenticators.md#the-password-for-a-first-second-factor) in the request. A copy of the cookie doesn't have it. An account without a password has nothing to ask for, so this doesn't cover it.
- A new sign-in method isn't [established](authenticators.md#established-authenticators) for 7 days. Until then, it doesn't make `noDowngrade()` ask for a passkey, so the owner's password and authenticator app still sign them in.
- While the account has a sign-in method that isn't established, it can't remove, rename or replace an established one, or replace established recovery codes. The owner can still remove the new one.
- One such removal or replacement freezes the rest for 7 days too. So a fresh session can do at most one of them, and only when the account had nothing new. It can't take the last second factor, which needs the password.

See [Frozen Sign-In Methods](authenticators.md#frozen-sign-in-methods).

Keyring uses `keyring.fresh:15m` on its own sensitive routes. It applies this through the `changes_middleware` config option, on top of `auth:{guard}`. Those routes cover managing authenticators, ending sessions, signing out devices, changing the password, and starting an email change.

## Asking From a Controller

An integration, such as an OpenID Connect provider, may need to decide what to ask for from the request itself, from parameters like `acr_values` and `max_age`. Route middleware can't do that, so `Keyring\Login\StepUp` makes the same decision from a controller:

```php
public function unlessMet(Request $request, ?Assurance $level = null, ?DateTimeInterface $since = null): ?Response
```

It returns `null` when the user has already proved what's asked, and the request may carry on. Otherwise, it returns the response the middleware would give: a redirect to the confirm page, a `423` for JSON requests, or [enrolling first](#raising-assurance) for a user who can't reach what's asked.

- `$level` works like `keyring:{level}`. The session must have reached that [assurance level](policies.md#assurance-levels), and the confirm asks only for what's missing. The `device-bound` and `phishing-resistant` names are only for the middleware.
- `$since` works like `keyring.fresh`. The user must have verified, at or after that moment, the strongest combination their account can give. A proof made in the same second as the moment counts. See [Fresh Verification](#fresh-verification) for what that means. A moment on its own doesn't look at whether a level lapsed: a password and an authenticator app proved 90 minutes ago meet a moment a day ago, though AAL2 lapsed after an hour idle. Pass `$level` too when the level the session holds now matters.
- With both, the session must have reached the level, and the user must have verified since the moment. The confirm asks for both at once, and it doesn't build on what the session proved earlier. A recovery code is taken beside another factor whenever the level alone would take one, and never in place of the key AAL3 asks for. When the account can't freshly prove the level, so that one confirm couldn't give both, they're asked in turn instead: first the level, as `$level` alone asks it, building on what still counts, then the fresh verification, as `$since` alone asks it. A user with a [`never`](sso.md#freshness) GitHub link and an authenticator app, and no password, can reach AAL2 with a round trip to GitHub and the app, but GitHub can't be fresh, and the app alone isn't AAL2. They confirm the level, and the app they proved for it meets the moment, so they're asked once. Without the fallback they'd be sent to enroll. `meets()` answers the same way.

When nobody is signed in to Keyring's guard, `unlessMet` throws an `AuthenticationException`, which Laravel answers by sending the browser to sign in. It throws an `InvalidArgumentException` when it's asked for nothing (no level and no moment), and for `Assurance::None`. It also throws for a moment more than `StepUp::CLOCK_LEEWAY` (5) seconds in the future. Nothing could meet that moment yet, so the user would confirm and be sent back to confirm again. A moment less than that ahead is taken as now, since another of your servers may have stored it with its clock a little ahead.

### Passing a Fixed Moment

A confirmation counts for any moment before it, so once the user confirms, the check is met. Each factor is stamped when it's proved, though, so a confirm with two steps only meets moments up to its first step. The password is older than the code the user typed after it.

A moment that moves on with every request can't be met. If you pass `now()` each time, the user confirms, comes back a moment later, and is asked again. That's what `max_age=0` would do if you turned it into `now()->subSeconds(0)`. Any `max_age` does the same once a confirm takes longer than it. With `max_age=60`, a user who proves the password and then takes 90 seconds to find their phone comes back with a password older than `now()->subSeconds(60)`, and is sent to confirm again, every time.

So whenever there's a `max_age`, or a `prompt=login`, store the moment the authorization request arrived. `max_age=0` and `prompt=login` ask for a proof made during this authorization, so pass the stored moment itself. Any other `max_age` asks for a proof made in the last `max_age` seconds, as OpenID Connect counts it, so pass `max_age` seconds before now, or the stored moment if that's earlier. A proof made during this authorization still counts however long the confirm takes, and one made before it must be within `max_age` of now. Keep the moment for that one authorization request:

- Store it under an ID that only this request carries, and add the ID to the URL the user comes back to. A single key for the whole session would let a moment left by an abandoned flow satisfy a later `prompt=login` without asking. Two tabs would also share it.
- Store a hash of the authorization request beside it (`client_id`, `redirect_uri`, `state`, and `nonce`), and only take the moment for a request with the same hash. Otherwise, someone at the browser could start a `prompt=login` flow, leave it, wait for the user to confirm something else, and replay the ID with other parameters.
- Let it expire after a few minutes, and keep only a few per session. Every visit to an authorization URL with `max_age` or `prompt=login`, from any site, stores another.
- A request without an ID, or with one you don't have a moment for, starts a new authorization. Store a new moment for it.
- Forget the moment once the authorization ends.

Store the moment before a guest signs in, so don't put this route behind `auth`. Without it, the controller stores the moment and then sends the guest to sign in, so their sign-in comes after the moment and counts toward it. Behind `auth`, the guest signs in before the controller runs, and the moment comes after their sign-in. With two steps at sign in, the password is older than that moment, and `prompt=login` would send them to confirm right after they signed in.

### Asking Without Starting a Confirm

Some requests must get an answer without showing the user anything. An OpenID Connect request with `prompt=none` is one. When the session falls short, the provider sends `login_required` back to the client instead of showing a page. `unlessMet` can't answer that, because by the time it returns a response, it has started the step-up. A confirm attempt is waiting in the session, and the request is saved as the page to come back to. The next time the user confirms, they're sent to that silent request.

`meets` asks the same question and starts nothing:

```php
public function meets(Request $request, ?Assurance $level = null, ?DateTimeInterface $since = null): bool
```

It takes the same arguments as `unlessMet`, and throws the same `InvalidArgumentException` for ones it can't answer. It returns `true` when `unlessMet` would return `null`, and `false` when `unlessMet` would send the user to confirm or to enroll, or answer with a plain `403` because there's no `enrollment_url` to send them to. Either way, it leaves the session as it was.

Like `unlessMet`, it throws an `AuthenticationException` when nobody is signed in to Keyring's guard. A request that mustn't show the sign-in page either should check for a guest first, as the example below does. A silent request never comes back from a confirm, so it stores no moment, and its `max_age` counts back from now.

### An Example

This controller reads `acr_values`, `max_age`, and `prompt`. Values from outside are checked before they reach `unlessMet`. A negative `max_age` would otherwise be a moment in the future, and throw. The route isn't behind `auth`, so the controller sends a guest to sign in itself, once the moment is stored. A request that asks for nothing would otherwise reach the authorization code without anyone signed in.

```php
use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;
use Keyring\Enums\Assurance;
use Keyring\Facades\Keyring;
use Keyring\Login\StepUp;

class AuthorizeController
{
    public function __invoke(Request $request, StepUp $stepUp)
    {
        $validated = $request->validate([
            'acr_values' => ['nullable', 'string', 'max:255'],
            'max_age' => ['nullable', 'integer', 'min:0', 'max:31536000'],
            'prompt' => ['nullable', 'string', 'max:255'],
            'flow' => ['nullable', 'string', 'max:64'],
            'client_id' => ['required', 'string', 'max:255'],
            'redirect_uri' => ['required', 'string', 'max:2048'],
            'state' => ['nullable', 'string', 'max:1024'],
            'nonce' => ['nullable', 'string', 'max:1024'],
        ]);

        $level = in_array('aal2', explode(' ', $validated['acr_values'] ?? ''), true) ? Assurance::AAL2 : null;
        $maxAge = isset($validated['max_age']) ? (int) $validated['max_age'] : null;
        $freshProof = $maxAge === 0 || in_array('login', explode(' ', $validated['prompt'] ?? ''), true);
        $silent = in_array('none', explode(' ', $validated['prompt'] ?? ''), true);

        // The moment this authorization started, stored under an ID only
        // this authorization request carries, with a hash of the request
        // so the ID can't be replayed with others. prompt=login asks for a
        // proof since then, and max_age takes one since then too, so a slow
        // confirm doesn't send the user round again.
        $hash = hash('sha256', json_encode([
            $validated['client_id'], $validated['redirect_uri'], $validated['state'] ?? null, $validated['nonce'] ?? null,
        ], JSON_THROW_ON_ERROR));
        $flows = collect($request->session()->get('oidc.flows', []))
            ->filter(fn (mixed $flow) => is_array($flow) && $flow['at'] > now()->subMinutes(10)->getTimestamp());

        $flow = $validated['flow'] ?? null;
        $stored = $flow === null ? null : $flows->get($flow);
        $started = $stored !== null && hash_equals($stored['request'], $hash) ? $stored['at'] : null;

        // A silent request can't confirm, so it stores no moment.
        if (($freshProof || $maxAge !== null) && ! $silent && $started === null) {
            $flow = Str::random(40);
            $request->session()->put('oidc.flows', [
                ...$flows->sortByDesc('at')->take(4)->all(),
                $flow => ['at' => now()->getTimestamp(), 'request' => $hash],
            ]);

            return redirect($request->fullUrlWithQuery(['flow' => $flow]));
        }

        // prompt=none mustn't show the user anything, not even the sign-in page.
        if ($silent && Keyring::guard()->guest()) {
            return $this->loginRequired($validated);
        }

        // Signing in comes after the moment, so it counts toward it.
        if (Keyring::guard()->guest()) {
            throw new AuthenticationException(guards: [config('keyring.guard')]);
        }

        // A silent request stores no moment, so it counts from now, when
        // it arrived.
        $arrived = $started ?? now()->getTimestamp();

        $since = match (true) {
            $freshProof => Carbon::createFromTimestamp($arrived),
            $maxAge !== null => Carbon::createFromTimestamp(min($arrived, now()->getTimestamp() - $maxAge)),
            default => null,
        };

        // A silent request only asks meets(), which starts no confirm, so
        // it's never saved as the page to come back to.
        $response = match (true) {
            $level === null && $since === null => null,
            $silent => $stepUp->meets($request, $level, $since) ? null : $this->loginRequired($validated),
            default => $stepUp->unlessMet($request, $level, $since),
        };

        if ($response !== null) {
            return $response;
        }

        if ($started !== null) {
            $request->session()->forget("oidc.flows.{$flow}");
        }

        // Issue the authorization code, with the claims from below...
    }
}
```

A flow ID that's expired, unknown, or was stored for another request isn't used. The request starts a new authorization instead, so the user confirms again.

`validate()` keeps the example short. A real provider sends an `invalid_request` error back to the client instead. `loginRequired()` stands for the same kind of error response, with `login_required`. Map outside values to a level yourself, and decide what to do with ones you don't know. `Assurance::fromName()` throws an `InvalidArgumentException` for a name it doesn't know.

## Reading What Was Proved

An integration may also need to say how the user authenticated, for example as `amr`, `acr`, and `auth_time` in an ID token. Read that from `Keyring\Sessions\SessionAssurance`:

- `level(int $since = 0)` returns the highest `Assurance` the session holds right now. Given a Unix timestamp, it counts only what was proved since then.
- `countingToward(Assurance $level, int $since = 0)` returns the verifications that still count toward that level. Those are the ones made within the level's overall limit, and since inactivity last [lapsed](devices-and-sessions.md#timeouts) it. Given a Unix timestamp, it returns only those made since then too.
- `all()` returns every verification recorded in the session whose authenticator still exists. That includes verifications that no longer count toward any level, such as a code proved a day ago, or before the session sat idle past its limit. Reporting from `all()` overstates what the session holds. A session could report `mfa` after its second factor stopped counting. Use `countingToward()` for what you report.

Each item is a `Keyring\Login\Verification`, with these public properties:

| Property | Type | Meaning |
|---|---|---|
| `factor` | `string` | The factor's key, such as `password`, `totp`, `passkey`, or `recovery`. |
| `authenticator` | `?string` | The ID of the user's authenticator (the stored sign-in method, not a session record), or `null` for a factor with no stored authenticator, such as the password. |
| `categories` | `list<Category>` | What it proved, as `Keyring\Enums\Category` cases: `Knowledge`, `Possession`, `Inherence`, or `Address` for an emailed code, which isn't an authentication factor. |
| `phishingResistant` | `bool` | Whether it was a passkey or security key. |
| `at` | `int` | When it was verified, as a Unix timestamp. Assurance levels and their timeouts go by this. |
| `deviceBound` | `bool` | Whether the key can't leave its device. |
| `attested` | `bool` | Whether the key was added with a verified attestation. |
| `authenticatedAt` | `?int` | When the user really proved it, if earlier than `at`, as a Unix timestamp. Only a sign in with an [identity provider](sso.md) that says, with `auth_time`, that the user signed in there earlier sets it. `Verification::UNKNOWN` (`0`) means the provider should have said when and didn't: treat it as unknown, and never as recent. `null` when it's the same as `at`. |
| `providerAmr` | `list<string>` | For an [identity provider](sso.md#second-factors-and-policies), the `amr` values its ID token sent, as it named them, at most 10. Empty for every other factor, and when the provider sent none. It's the provider's claim: Keyring counts it toward nothing, not the categories, the level, or phishing resistance. |
| `providerAcr` | `?string` | For an identity provider, the `acr` its ID token sent, or `null`. Like `providerAmr`, the provider's claim, and counted toward nothing. |

`provedAt()` returns when the user last proved it: `authenticatedAt`, or `at` when that's `null` or earlier. It returns `Verification::UNKNOWN` (`0`) when that's unknown. Freshness (`keyring.fresh`, and `StepUp` with a moment) goes by `provedAt()`. `provedAtIfKnown()` returns the same, or `null` when it's unknown. Use it whenever you report the time, so an unknown one can't come out as a sign in on 1 January 1970, as it would from `min()` or a date formatted from `provedAt()`.

To ask whether a set of verifications meets a requirement, use `Requirement::isMetBy(array $verifications): bool`. `Requirement::factors(2)` counts distinct authentication categories, so two codes of the same kind aren't multi-factor. `Assurance::of(array $verifications)` returns the highest level a set of verifications reaches.

Report `auth_time` as the oldest `provedAtIfKnown()` among the verifications you build `amr` from, not the newest, and leave it out when any of them is `null`: a provider didn't say when the user signed in there. The claims say every method in `amr` was proved at or after `auth_time`. Say a session proved the password and an authenticator app 20 hours ago, and only the password again a minute ago. Its `amr` is `password`, `totp`, and `mfa`, and the newest time would claim all of that happened a minute ago. The authenticator app was proved 20 hours ago.

When you asked with `$since`, build the claims from what was proved since that moment, so they describe the proof this authorization asked for. `level()` and `countingToward()` take a Unix timestamp for that. They count only what was proved since then, with each level still on its own clock. Don't work the level out again with `Assurance::of()` from what counts toward a lower level. Say AAL2 lapsed after an hour idle, and the session is at AAL1. What counts toward AAL1 still holds the authenticator app proved before the lapse, so `Assurance::of()` would give AAL2. For the same reason, only report `mfa` at AAL2 or higher, and at AAL1 only report the one factor that holds it. Listing the authenticator app beside the password would read as two factors to a client that looks at `amr`. For example:

```php
use Keyring\Enums\Assurance;
use Keyring\Login\Requirement;
use Keyring\Login\Verification;
use Keyring\Sessions\SessionAssurance;

$assurance = app(SessionAssurance::class);
$from = $since?->getTimestamp() ?? 0;

$level = $assurance->level($from);
$proved = $level === Assurance::None ? [] : $assurance->countingToward($level, $from);

// One factor holds AAL1: report the newest, not a second factor that
// stopped counting toward AAL2 when it lapsed.
if ($level === Assurance::AAL1) {
    usort($proved, fn (Verification $a, Verification $b) => $b->at <=> $a->at);
    $proved = [array_find($proved, fn (Verification $verification) => Requirement::for(Assurance::AAL1)->isMetBy([$verification]))];
}

// Null for a verification proved at an unknown time.
$times = array_map(fn (Verification $verification) => $verification->provedAtIfKnown(), $proved);

$claims = [
    'acr' => $level === Assurance::None ? null : strtolower($level->name),
    'amr' => [
        ...array_values(array_unique(array_column($proved, 'factor'))),
        ...($level->atLeast(Assurance::AAL2) ? ['mfa'] : []),
    ],
    // Left out (null) when nothing was proved, or when it was proved at an
    // unknown time.
    'auth_time' => $times === [] || in_array(null, $times, true) ? null : min($times),
];
```

Work the claims out in the authorization request, while the user's browser session is there, and keep them with the authorization code. `SessionAssurance` reads that session. The token endpoint is called by the client, with no session, so it would read nothing.

Keyring's factor keys aren't the registered `amr` values (RFC 8176), so map them to the ones your clients expect. A sign in with an identity provider has that provider's own `amr` and `acr` as `providerAmr` and `providerAcr`, which you may pass on, say as what the upstream provider claimed, but don't let them raise `acr` or add `mfa`: Keyring doesn't count them, and nor does the level it reports. Tell your clients to read `acr` for the level, and not to work it out from `amr`. An `otp` in `amr` says a code was proved, not that it still counts as a second factor.

## The Confirm Flow

When a request needs step-up, Keyring starts a confirm attempt with the requirement, and redirects to the confirm page. The flow is the same as the [login challenge](sign-in-flow.md#the-challenge-page), but it uses its own routes:

| Method | URI | Name |
|---|---|---|
| `GET` | `/confirm/{factor?}` | `keyring.confirm.challenge` |
| `POST` | `/confirm/{factor}` | `keyring.confirm.verify` |
| `POST` | `/confirm/{factor}/send` | `keyring.confirm.send` |

These routes need a user signed in to Keyring's guard (`auth:{guard}`). The page, and its verify and send routes, take the session lock, as the login challenge does. The page rendered is `confirm` (not `challenge`), with `purpose: "confirm"` and `canTrustDevice: false`. Visiting `/confirm` with no confirm attempt in progress, including after one times out, starts one. Any single factor except a recovery code satisfies that attempt, as long as it can be proved recently. Keyring doesn't know which route the user was heading for, so a recovery code spent on this page might not be enough to get them through. Laravel's `password.confirm` sends users to this page, and that's a freshness check, so a link at a [`never`](sso.md#freshness) identity provider isn't offered here. A user with nothing to confirm with (no password, and no other sign-in method a challenge can ask for and that can be proved recently) is sent to your [`enrollment_url`](configuration.md#account-changes-and-enrollment) instead. Without one, they get a `403`.

A link at an identity provider is offered like any other method, except that one whose provider's [`freshness`](sso.md#freshness) is `never`, the default for Google and GitHub, is only offered toward a level, never for a fresh verification. Its `challenge` prop holds the `provider`, its `label`, and the `url` of `GET /confirm/sso/redirect` (`keyring.sso.confirm`), which sends the user to the provider to sign in there, asked to sign in again when its `freshness` is `reauthenticate`. The provider sends them back to its callback, which finishes the confirm through the same pipeline, and goes on to the intended URL. See [Single Sign-On](sso.md#step-up).

If a page asks again while a confirm attempt for the same requirement is in progress, it continues that attempt. That way, what the user already proved isn't lost.

Recovery codes are only offered when using one could finish the confirm. In other words, what's left must not need another possession factor. A passkey-only user is asked for the passkey, not a code that would leave the confirm unfinished.

Once the user has verified enough, Keyring does the following:

1. regenerates the session ID, which destroys the old one,
2. records the new verifications, which resets the [level's clocks](devices-and-sessions.md#timeouts), and raises the registered session's assurance,
3. sets Laravel's `auth.password_confirmed_at` to when the user proved what this confirm added (see [below](#laravels-password-confirmation)),
4. dispatches `Keyring\Events\Confirmed`,
5. redirects to the intended URL, or `home`.

For a `GET` request, the intended URL is the page that needed step-up. For other methods, Keyring uses the page the request came from (its `Referer`, or failing that the last page Laravel saw) when that's on the app's own origin, and `home` otherwise. That way, the user returns to the page with the form, rather than to a URL they can't `GET`.

The confirm attempt expires after `pending_logins.keep_for`, in the same way as a sign in attempt. When it expires, the user returns to `/confirm`, and `keyring::keyring.expired` appears on the field of the factor it asks for next.

## JSON Requests

Requests that expect JSON (and aren't Inertia visits) get a `423 Locked` response instead of a redirect:

```json
{
  "message": "Please confirm it's you to continue.",
  "page": "confirm",
  "redirect": "https://example.com/confirm"
}
```

Send the user to `redirect`, and then let them try again. Keyring remembers the page that made the call (the `Referer`), so after confirming, the user comes back to it. You may also protect the page's own `GET` route with the same middleware. That works too, and it asks up front when the page loads. See [Handling Step-Up in JavaScript](frontend.md#handling-step-up-in-javascript).

## Laravel's Password Confirmation

Confirming through Keyring also satisfies Laravel's `password.confirm` middleware, so routes that already use it keep working. The reverse isn't true. Laravel's own password confirmation doesn't count for Keyring's middleware.

Keyring sets `auth.password_confirmed_at` to the latest moment the user really proved one of the factors the confirm added (`Verification::provedAt()`), so a sign in at an identity provider that let them straight through counts from when they signed in there. What the confirm built on, such as the password from signing in, confirms nothing. A confirm that added only a round trip to a [`never`](sso.md#freshness) identity provider, say toward AAL2 after it lapsed, leaves it as it was, since nobody may have typed anything. The marker never moves back.

## Events

Keyring dispatches `Keyring\Events\Confirmed` with `user` and `attempt` when a confirmation completes. The `FactorVerified` and `FactorFailed` events, along with the other [verification events](sign-in-flow.md#events), fire as they do at login, with the `confirm` purpose.
