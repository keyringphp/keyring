# Headless Frontends

- [Introduction](#introduction)
- [Choosing a Layout](#choosing-a-layout)
- [Configuring Laravel](#configuring-laravel)
    - [Pages and Redirects](#pages-and-redirects)
    - [Session Cookies](#session-cookies)
    - [Sanctum](#sanctum)
    - [CORS](#cors)
    - [CSRF](#csrf)
    - [Passkeys](#passkeys)
    - [Emailed Links](#emailed-links)
    - [Single Sign-On](#single-sign-on)
    - [Local Development](#local-development)
- [One Origin](#one-origin)
- [Pages as JSON](#pages-as-json)
- [Where Each Answer Goes](#where-each-answer-goes)
- [Building the Frontend With Nuxt](#building-the-frontend-with-nuxt)
    - [Calling Laravel](#calling-laravel)
    - [Signing In](#signing-in)
    - [Step-Up](#step-up)
    - [The Pages Emailed Links Open](#the-pages-emailed-links-open)
    - [Rendering on the Server](#rendering-on-the-server)
- [What Doesn't Work](#what-doesnt-work)

## Introduction

Most Keyring applications build their pages with Inertia or Blade, and Laravel serves them. This guide is for the other kind: a frontend that Laravel doesn't serve, such as a Nuxt app on `app.example.com` that calls Laravel on `api.example.com`. It's the same setup as Fortify with `'views' => false`.

The browser signs in with Laravel's session cookie, the way Sanctum's single-page app authentication works. Keyring's routes stay what they are: `web` routes with a session, CSRF protection, and Keyring's headers. The frontend calls them with `fetch`, sending cookies, and asks for JSON. Every one of them already answers JSON, the pages included:

- A form route answers with a [status response](sign-in-flow.md#status-responses), or one of the other [responses](sign-in-flow.md#responses), or a validation error.
- A page route answers with the page's name and props, so the frontend can [render its own page](#pages-as-json) from them.
- Whenever an answer sends the browser to one of Keyring's pages, it [names that page](#where-each-answer-goes), so the frontend can go to its own page of that name without reading the URL.

The examples use Nuxt, but nothing here is specific to it. Any frontend that can send cookies with its requests works the same way.

## Choosing a Layout

The browser has to send Laravel's cookies with every request. Where the frontend lives decides how much setting up that takes.

| Layout | Example | |
|---|---|---|
| One origin | Nuxt on `example.com`, passing everything under `/backend` on to Laravel. | Supported, with less to set up: no CORS, and cookies, CSRF and passkeys work as they are. See [One Origin](#one-origin). |
| Subdomains of one site | `app.example.com` and `api.example.com` | Supported. The rest of this guide sets it up. |
| Different sites | `example-app.com` and `example-api.net` | Not supported. The session cookie is `SameSite=Lax`, so the browser doesn't send it on a `fetch()` from another site, and browsers block third-party cookies anyway. |

"Same site" means the same registrable domain, so `app.example.com` and `api.example.com` are the same site, while being different origins. A request between them is a cross-origin request, so it needs CORS, but the browser still sends `SameSite=Lax` cookies with it.

## Configuring Laravel

### Pages and Redirects

Laravel renders none of Keyring's pages, so turn them off in `config/keyring.php`, and point the places Keyring sends users at your frontend:

```php
'pages' => false,

'home' => 'https://app.example.com/dashboard',

'enrollment_url' => 'https://app.example.com/settings/security',

'password_change_url' => 'https://app.example.com/settings/password',
```

With [`pages`](configuration.md#pages) set to `false`, a request for a page that isn't JSON gets a `404`, and Keyring never throws a `MissingPage` exception. JSON requests still get each page's props. `home`, `enrollment_url` and `password_change_url` come back to the frontend as the `redirect` of the answers that use them, so full URLs on the frontend are what it can act on.

While a user is held, those last two only let through what Laravel can see. The `keyring.enrolled` middleware lets a request through when its path on Laravel is the path of `enrollment_url`, which a page on the frontend never is. So every Laravel route the frontend's enrollment page calls is refused with the `403` `enroll-first`, unless it's one of Keyring's own, signing out, or email verification. If you put `keyring.enrolled` on your `api` routes, or on the `web` group your own routes are in, list the ones that page needs, such as the route behind `GET /api/user`, in `enrollment_except`, by route name. A password hold is only checked in the `web` group, where Keyring's routes are. While it lasts, only `PUT /auth/user/password`, the confirm routes, signing out and email verification answer there, and every other route of Keyring's gets the `403` `change-password`. Your `api` routes aren't held unless you add `keyring.password` to them, and that middleware has no list of routes to let through. See [Requiring a Second Factor](policies.md#requiring-a-second-factor) and [Requiring a Password Change](protected-changes.md#requiring-a-password-change).

Putting Keyring's routes under a prefix keeps the CORS paths short, and keeps them apart from your own routes:

```php
'prefix' => 'auth',
```

Keyring's paths then start with `/auth`, such as `/auth/login` and `/auth/login/challenge`. The rest of this guide uses that prefix. If you use the browser package, tell it about the prefix with [`configureRoutes({ prefix: 'auth' })`](frontend.md#changing-routes).

### Session Cookies

Set the session cookie's domain to the site, so it's shared with every subdomain:

```ini
SESSION_DOMAIN=.example.com
SESSION_SECURE_COOKIE=true
SESSION_SAME_SITE=lax
```

The browser would send a cookie that only belongs to `api.example.com` to Laravel anyway. Sharing it with the site is what lets the frontend's JavaScript read the `XSRF-TOKEN` cookie for [CSRF](#csrf), and lets the Nuxt server receive the session cookie, to pass on when it [renders a page](#rendering-on-the-server). Laravel's `XSRF-TOKEN` cookie takes the same domain as the session.

With `session.domain` set, Keyring's own device and "remember me" cookies are shared with the subdomains too, and they're named with the `__Secure-` prefix rather than `__Host-`. See [Keyring's Cookies](devices-and-sessions.md#keyrings-cookies). Every subdomain of the site is then sent these cookies, and can set them, so only share a domain whose subdomains you control. A domain that hosts other people's content, under user subdomains say, isn't safe to share.

### Sanctum

Keyring's own routes don't need Sanctum: they're `web` routes. Sanctum is for your application's own `api` routes, such as `GET /api/user`, so that `auth:sanctum` signs the browser in from its session cookie. Install it with `php artisan install:api`, then turn on its stateful mode, and add Keyring's [session middleware](devices-and-sessions.md#the-session-middleware) to the `api` group:

```php
// bootstrap/app.php
->withMiddleware(function (Middleware $middleware) {
    $middleware->statefulApi();
    $middleware->appendToGroup('api', 'keyring.session');
})
```

`statefulApi()` adds Sanctum's `EnsureFrontendRequestsAreStateful` middleware to the `api` group. It starts the session, with cookies and CSRF protection, for requests whose `Referer`, or `Origin` when there's no `Referer`, is one of the hosts in `sanctum.stateful`. Requests from anywhere else are treated as token requests, with no session. Add the frontend's host:

```ini
SANCTUM_STATEFUL_DOMAINS=app.example.com
```

Without `keyring.session`, a session that Keyring revoked or timed out keeps working on your `api` routes until Laravel's own session ends. The [conformance suite](testing.md#the-conformance-suite) fails for any `auth:sanctum` route without it.

### CORS

The frontend's requests are cross-origin, so Laravel has to allow them, with credentials. Laravel's `HandleCors` middleware runs on every request, and reads `config/cors.php`. Publish that file with `php artisan config:publish cors`, then set:

```php
'paths' => ['api/*', 'sanctum/csrf-cookie', 'auth/*'],

'allowed_origins' => ['https://app.example.com'],

'supports_credentials' => true,
```

Without a prefix, list Keyring's paths instead: `login`, `login/*`, `logout`, `register`, `forgot-password`, `reset-password`, `reset-password/*`, `confirm`, `confirm/*`, `user/*`, `email/*`, `email-changes/*` and `devices/*`.

> [!WARNING]
> Never use `'allowed_origins' => ['*']` with `supports_credentials`. Laravel's CORS middleware then allows whichever origin asks, so any page the browser sends the user's cookies from could read Keyring's JSON, a page on any other subdomain of your site included. The same goes for `allowed_origins_patterns` that match more than the frontend, such as every subdomain of `example.com`. List the frontend's exact origin.

### CSRF

Keyring's routes keep Laravel's CSRF protection. A request from `app.example.com` to `api.example.com` is `same-site`, not `same-origin`, so Laravel's `PreventRequestForgery` middleware checks its token. The frontend sends the `XSRF-TOKEN` cookie's value as an `X-XSRF-TOKEN` header, as the browser package's `json()` and axios both do. Cross-origin, axios only sends the cookies and the header when asked:

```ts
axios.defaults.withCredentials = true
axios.defaults.withXSRFToken = true
```

The cookie is set on any response from a `web` route, but the usual first request is Sanctum's:

```
GET /sanctum/csrf-cookie
```

Laravel can also accept every request from the same site without a token, with `$middleware->preventRequestForgery(allowSameSite: true)`. That trusts every subdomain of the site as much as the frontend. Keep the token unless you control them all.

### Passkeys

A WebAuthn ceremony runs in the frontend's page, so the browser checks its keys against the frontend's origin, not Laravel's. By default, Keyring uses the host of `APP_URL` as the relying party ID and the `APP_URL` origin as the only one allowed, which here is `api.example.com`. Browsers refuse that ID on `app.example.com`. Set both in `config/keyring.php`:

```php
'webauthn' => [
    'relying_party' => [
        'id' => 'app.example.com',
    ],
    'origins' => ['https://app.example.com'],
],
```

The relying party ID has to be the frontend's host or a domain it belongs to. `app.example.com` keeps keys to the frontend. Use `example.com` only when users sign in with their keys on several subdomains, since it lets every subdomain of the site ask for them, and list each of their origins. Choose before anyone registers a key: changing the ID later makes existing keys stop working. See [Relying Party and Origins](passkeys.md#relying-party-and-origins).

### Emailed Links

Keyring builds its emailed links from `APP_URL`, which here is Laravel's host. Start them at the frontend instead, in your `KeyringServiceProvider`'s `boot()` method:

```php
Keyring::linkRootUsing(fn () => config('app.frontend_url'));
```

Only the root changes. The paths stay Keyring's, so the frontend serves a page at each of them. With the `auth` prefix:

| Link | Opens | Page |
|---|---|---|
| Password reset | `/auth/reset-password/{token}?email=...` | `reset-password` |
| Email verification | `/auth/email/verify/{id}/{hash}?expires=...&signature=...` | `email-verification` |
| Email change, confirm or undo | `/auth/email-changes/{change}/confirm/{token}`, `/auth/email-changes/{change}/revert/{token}` | `email-change` |
| "This wasn't me" | `/auth/devices/{device}/report?expires=...&signature=...` | `device-report` |

Some emails also link to `/auth/login` and `/auth/forgot-password`, such as the one sent when someone tries to register with an address that has an account. The emails about a new sign-in method and new recovery codes link to your own settings page when you set [`authenticators_url`](configuration.md#account-changes-and-enrollment). A path there is put after the same root, so `/settings/security` opens on the frontend.

Signed links are signed over their path and query only, so their signatures hold under the frontend's root. The frontend's page sends the same path, and the query, to Laravel, and Laravel checks the signature as if the link had opened there. A root with a path of its own works too: `https://app.example.com/account` starts the reset link at `https://app.example.com/account/auth/reset-password/...`, and the frontend leaves `/account` off the path it sends to Laravel.

Mirroring the paths is all it takes, so Keyring has no hook for building one link differently. Laravel's own `ResetPassword::createUrlUsing` and `VerifyEmail::createUrlUsing` still work for those two, and Keyring leaves a callback of yours alone. See [Emailed Links](security.md#emailed-links).

### Single Sign-On

With `Keyring::linkRootUsing()` set as above, the callback URL that Keyring gives [identity providers](sso.md) starts at the frontend too, such as `https://app.example.com/auth/auth/google/callback` with the `auth` prefix. Register that URL with the provider, and serve a page at that path that passes its path and query on to Laravel as JSON. See [Frontends Laravel Doesn't Serve](sso.md#frontends-laravel-doesnt-serve). A JSON request to `GET /auth/auth/{provider}/redirect` answers with the provider's URL as `url`, for the frontend to send the browser to, and the browser package's `signInWithProvider()` and `linkProvider()` do that for you. A confirm page that offers a link at a provider does the same with `GET /auth/confirm/sso/redirect?authenticator={id}`, which `confirmWithProvider(id)` calls. The provider sends the user back to the same callback page, which gets `authenticated` with the `redirect` to carry on to.

### Local Development

With Nuxt on `http://localhost:3000` and Laravel on `http://localhost:8000`, both are the same site, and cookies don't keep ports apart, so each sees the other's cookies:

```ini
APP_URL=http://localhost:8000
SESSION_DOMAIN=localhost
SESSION_SECURE_COOKIE=false
```

Leaving `SESSION_DOMAIN` empty works too. `SANCTUM_STATEFUL_DOMAINS` already lists `localhost:3000` unless you set it. Allow `http://localhost:3000` in `cors.allowed_origins`, and for passkeys set `webauthn.relying_party.id` to `localhost` and `webauthn.origins` to `['http://localhost:3000']`. Browsers allow WebAuthn on `localhost` without HTTPS.

Keep `SESSION_SECURE_COOKIE` off over plain HTTP. Chrome and Firefox take a `Secure` cookie from `http://localhost`, but Safari refuses it, so a secure session cookie signs nobody in on Safari.

## One Origin

The frontend can also serve Laravel from its own origin, under a path of its own. Keyring's pages stay on the frontend, at `/auth/...`, and Laravel lives under `/backend`:

| The Browser Asks For | Served By |
|---|---|
| `https://example.com/auth/login` | Nuxt, the `login` page |
| `https://example.com/backend/auth/login` | Laravel, `/auth/login` |
| `https://example.com/backend/api/user` | Laravel, `/api/user` |

Don't pass `/auth/*` itself on to Laravel. A proxy picks by path, not by `Accept`, so a full page load of `/auth/login`, or an emailed link to `/auth/reset-password/{token}`, would reach Laravel as a page visit, which is a `404` with `pages` off.

A Nitro server route does the passing on:

```ts
// server/routes/backend/[...path].ts
import { getRequestHost, getRequestIP, getRequestProtocol, proxyRequest } from 'h3'

export default defineEventHandler((event) => {
  const path = event.path.replace(/^\/backend/, '')

  return proxyRequest(event, useRuntimeConfig().laravelUrl + path, {
    headers: {
      // Replaced, never passed on: the browser can send any X-Forwarded-For.
      'x-forwarded-for': getRequestIP(event) ?? '',
      'x-forwarded-host': getRequestHost(event),
      'x-forwarded-proto': getRequestProtocol(event),
      'x-forwarded-prefix': '/backend',
    },
  })
})
```

Laravel has to [trust the Nuxt server as a proxy](security.md#trusted-proxies), with `$middleware->trustProxies(at: ...)` naming its address, to read the host, scheme, prefix and IP address from those headers. Because Laravel trusts them, the proxy must set `X-Forwarded-For` to the address it saw, never pass on one the browser sent. Otherwise anyone could choose the IP address Keyring's rate limits count, and get round them. If Nuxt is behind a load balancer of its own, take the address from the header that load balancer sets.

What changes from the rest of this guide:

- `APP_URL` is `https://example.com`, the frontend's origin. Emailed links start there, at Keyring's paths such as `/auth/reset-password/{token}`, which are the frontend's pages, so no `linkRootUsing()` is needed.
- The URLs in Keyring's answers, such as `redirect`, are built from the forwarded headers, so they point at `https://example.com/backend/auth/...`. The frontend goes by `page` anyway.
- After confirming, `redirect` is the page whose request got the `423`, and that can be the frontend's page now that it shares Laravel's origin. The same goes for a sign in that follows Keyring's `signed-out` `401`. Any other sign in still answers `home`.
- There's no CORS to set up, and `SESSION_DOMAIN` stays empty. Every request is same-origin, so cookies are the origin's own, and Laravel's CSRF check passes on `Sec-Fetch-Site: same-origin`.
- The relying party ID and the allowed origin default to `APP_URL`'s host and origin, which are the frontend's, so passkeys need no settings.
- Sanctum's `sanctum.stateful` already lists `APP_URL`'s host.
- The browser package's `baseUrl` may include a path, such as `https://example.com/backend`.

## Pages as JSON

A request for one of Keyring's pages that expects JSON, and isn't an Inertia visit, gets the page's name and props:

```
GET /auth/reset-password/{token}?email=taylor@example.com
Accept: application/json
```

```json
{
  "page": "reset-password",
  "props": { "token": "...", "email": "taylor@example.com" }
}
```

The props are the ones listed under [Pages](sign-in-flow.md#pages), with everything each page needs to post back: the reset token and address, an email change's token, and the `expires` and `signature` that the verification and "this wasn't me" pages post. The `url` prop of those pages is a path on Laravel, without the token or signature, for the frontend to post to.

A user whose address is already verified gets the `email-verified` status from the verification link instead of the page, with `justNow` false, as a page visit would be sent on. See [Where Each Answer Goes](#where-each-answer-goes).

These are the same props an Inertia visit gets, so a JSON page shows nothing that wasn't already sent to the browser. The answer comes with every one of Keyring's headers. The pages emailed links open still send `Referrer-Policy: no-referrer`, and every page is sent with `Cache-Control: no-store, private`. A page you render with a closure through [`Keyring::page`](sign-in-flow.md#pages) answers JSON requests too, so that's where to change what a JSON client gets, or to leave a prop out.

## Where Each Answer Goes

Keyring's answers carry a `redirect`, a URL on Laravel or one from your config. When that's one of Keyring's pages, they also carry `page`, its name. So the frontend goes by `page` when there is one, then `redirect`, then stays where it is:

| Answer | `page` | `redirect` |
|---|---|---|
| `202` `challenge`, after a correct password when another factor is needed | `challenge`, or `confirm` for step-up | The challenge page. |
| `200` `authenticated` | | The intended URL, or `home`. |
| `423`, a route needs [step-up](step-up.md) | `confirm` | The confirm page. |
| `401` `signed-out`, a session Keyring ended | `login` | The login page. |
| `401` `{"message": "Unauthenticated."}`, Laravel's own answer to a guest on a signed-in route | | |
| `403` `enroll-first` | | `enrollment_url` |
| `403` `change-password` | | `password_change_url` |
| `403` `impersonation-refused`, a start of an [impersonation](impersonation.md#starting) that was refused, the same whatever the reason | | |
| `403` `impersonating`, refused while [impersonating](impersonation.md#whats-refused-while-impersonating) the user | | |
| `409` `not-impersonating`, a stop with nobody being impersonated, such as a second one from another tab. Back already | | `impersonation.return_url`. Load it in full. |
| `409` `impersonation-ended`, an impersonation that [ended by itself](impersonation.md#the-time-limit) and went back to the impersonator | | `impersonation.return_url`. Load it in full. |
| `422` with `page`, a sign in or step-up that ran out or used up its guesses | `login` or `confirm` | That page. The reason is in `errors`, on the username field or the factor's. |
| `422` with `frozen`, a removal, rename or replacement while sign-in methods are [frozen](authenticators.md#frozen-sign-in-methods) | | Stay. `frozen.skip` says whether a key can make the change now, with `proof` sent through `POST /auth/user/authenticators/{factor}/proof-options` first. For an enrollment, the proof goes with `POST /auth/user/authenticators/{factor}`, which begins it, and a refused confirm means beginning again. See [Making a Change With an Established Key](authenticators.md#making-a-change-with-an-established-key). |
| `422` with `errors.password`, beginning to add a second factor | | Stay. Ask for the current password and begin again with it as `password`. An account with no [established](authenticators.md#established-authenticators) second factor needs it. See [The Password for a First Second Factor](authenticators.md#the-password-for-a-first-second-factor). |
| `200` `email-verified` | | The intended URL, or `home` with `?verified=1` when the link just verified the address. `justNow` says which. |
| A [status](sign-in-flow.md#status-responses) such as `password-reset`, `registration-received` or `device-reported` | `login`, `register`, `forgot-password`, `verify-email`, `challenge` or `confirm`, when that's where it goes | Where to go, when it isn't back. |

Map each page name to a route of the frontend:

| Page | Keyring's Path | A Nuxt Route |
|---|---|---|
| `login` | `/auth/login` | `pages/auth/login.vue` |
| `register` | `/auth/register` | `pages/auth/register.vue` |
| `forgot-password` | `/auth/forgot-password` | `pages/auth/forgot-password.vue` |
| `reset-password` | `/auth/reset-password/{token}` | `pages/auth/reset-password/[token].vue` |
| `verify-email` | `/auth/email/verify` | `pages/auth/email/verify/index.vue` |
| `email-verification` | `/auth/email/verify/{id}/{hash}` | `pages/auth/email/verify/[id]/[hash].vue` |
| `email-change` | `/auth/email-changes/{change}/{action}/{token}` | `pages/auth/email-changes/[change]/[action]/[token].vue` |
| `device-report` | `/auth/devices/{device}/report` | `pages/auth/devices/[device]/report.vue` |
| `challenge` | `/auth/login/challenge` | `pages/auth/login/challenge.vue` |
| `confirm` | `/auth/confirm` | `pages/auth/confirm.vue` |

Mirroring Keyring's paths is only required for the pages emailed links open. The others may live wherever you like.

Laravel's plain `401` names no page. Send the user to your login page.

Laravel only remembers the page a browser was going to from navigations it sees itself, and from a `Referer` on its own host. So after a JSON sign in or step-up, `redirect` is `home`, never the frontend's page, when the frontend is on another origin. On one origin ([One Origin](#one-origin)), the `Referer` is kept, so `redirect` can be the page the request came from. Keep the page the user was going to in the frontend, such as in a `?redirect=` query on your login route, and go there when the answer is `authenticated`. Only go to a path on your own site from that query, one that starts with a single `/`: anyone can send a link with `?redirect=https://elsewhere.example`. In the same way, `continue` is never set on `authenticator-added` for a JSON client (see [Flash Messages and Alerts](frontend.md#flash-messages-and-alerts)).

## Building the Frontend With Nuxt

### Calling Laravel

This plugin gives the app a `$keyring` that calls Laravel with the browser's cookies, asks for JSON, and sends the CSRF token. It sets headers with `options.headers.set()`, which needs ofetch 1.4 or later: Nuxt 3.14 or later, or Nuxt 4.

```ts
// plugins/keyring.ts
import { appendResponseHeader } from 'h3'

export default defineNuxtPlugin(() => {
  const config = useRuntimeConfig()
  const event = useRequestEvent()

  // On the server, the token is in the cookies the browser sent. In the
  // browser, it's read for every request, since Laravel replaces it.
  const serverToken = useCookie('XSRF-TOKEN', { readonly: true }).value

  const keyring = $fetch.create({
    baseURL: config.public.apiBase, // https://api.example.com
    credentials: 'include',
    headers: {
      accept: 'application/json',
      'x-requested-with': 'XMLHttpRequest',
      ...(import.meta.server ? forwardedHeaders(config.public.appUrl) : {}),
    },
    onRequest({ options }) {
      const token = import.meta.server ? serverToken : xsrfToken()

      if (token) {
        options.headers.set('x-xsrf-token', token)
      }
    },
    onResponse({ response }) {
      // On the server, hand the cookies Laravel set on to the browser.
      if (import.meta.server && event) {
        for (const cookie of response.headers.getSetCookie()) {
          appendResponseHeader(event, 'set-cookie', cookie)
        }
      }
    },
  })

  return { provide: { keyring } }
})

function xsrfToken(): string | undefined {
  const match = document.cookie.match(/(?:^|; )XSRF-TOKEN=([^;]*)/)

  return match ? decodeURIComponent(match[1]) : undefined
}

// What Laravel needs from the browser's request when the Nuxt server makes
// it instead: its cookies and browser, and a Referer Sanctum recognises.
function forwardedHeaders(appUrl: string): Record<string, string> {
  return {
    ...useRequestHeaders(['cookie', 'user-agent', 'accept-language']),
    referer: appUrl,
  }
}
```

`$fetch` throws a `FetchError` for any answer that isn't a 2xx, with the body as `error.data`. A `202` from signing in is a 2xx, so it's returned like any other answer.

A page rendered with the cookies Laravel set must never be cached and served to someone else, not with a `swr` or `isr` route rule, and not by a CDN in front of Nuxt. It would hand the next visitor the first one's session. Keep those rules off every page that calls Laravel on the server.

The browser package's helpers make requests of their own. Tell it where Laravel is, in a plugin that only runs in the browser:

```ts
// plugins/keyring-package.client.ts
import { configureRequests, configureRoutes } from '@keyringjs/keyring'

export default defineNuxtPlugin(() => {
  const config = useRuntimeConfig()

  configureRoutes({ prefix: 'auth' })
  configureRequests({ baseUrl: config.public.apiBase, csrfCookie: '/sanctum/csrf-cookie' })
})
```

`configureRequests()` takes `baseUrl`, `credentials`, `csrfCookie` and `fetch`. `credentials` defaults to `'include'` when `baseUrl` is on another origin. The package's helpers throw a `KeyringRequestError`, with `status` and `data`, not ofetch's `FetchError`. See [Frontends on Another Origin](frontend.md#frontends-on-another-origin).

### Signing In

```ts
const { $keyring } = useNuxtApp()
const route = useRoute()

const pages: Record<string, string> = {
  login: '/auth/login',
  challenge: '/auth/login/challenge',
  confirm: '/auth/confirm',
  // ...the rest of the table above
}

async function signIn(email: string, password: string) {
  await $keyring('/sanctum/csrf-cookie')

  const answer = await $keyring<{ status: string, page?: string }>('/auth/login', {
    method: 'POST',
    body: { email, password, remember: true },
  })

  // A second factor is needed: answer.status is "challenge".
  if (answer.page) {
    return navigateTo({ path: pages[answer.page], query: route.query })
  }

  return navigateTo(localPath(route.query.redirect) ?? '/dashboard')
}

// Only a path on this site, never another site's URL.
function localPath(value: unknown): string | undefined {
  return typeof value === 'string' && /^\/(?![/\\])/.test(value) ? value : undefined
}
```

A wrong password is a `422`, with Laravel's validation errors in `error.data.errors`.

The challenge page loads its props from `GET /auth/login/challenge`, posts the proof to `POST /auth/login/challenge/{factor}`, and asks for a code with `POST /auth/login/challenge/{factor}/send`. "Try another way" loads `GET /auth/login/challenge/{factor}?authenticator={id}`. The props and fields are in [The Challenge Page](sign-in-flow.md#the-challenge-page). When the sign in has run out, both the `GET` and the `POST` answer with a `422` that names `login` as its `page`, with the reason on the username field. Show it there.

```ts
const { $keyring } = useNuxtApp()

// Client-side only: the challenge belongs to the browser that signed in.
const { data } = await useAsyncData('challenge', () => $keyring('/auth/login/challenge'), { server: false })
```

### Step-Up

A route that needs a recent verification answers with a `423` naming the `confirm` page. Note where the user was, send them to your confirm page, and bring them back once the confirmation answers `authenticated`:

```ts
import { FetchError } from 'ofetch'

const route = useRoute()

try {
  await $keyring('/auth/user/password', { method: 'PUT', body })
} catch (error: unknown) {
  if (error instanceof FetchError && error.status === 423) {
    return navigateTo({ path: pages[error.data.page], query: { redirect: route.fullPath } })
  }

  throw error
}
```

The confirm page works like the challenge page, on `/auth/confirm`. See [Step-Up](step-up.md) and [Handling Step-Up in JavaScript](frontend.md#handling-step-up-in-javascript).

### The Pages Emailed Links Open

These pages hold a token or a signature in their URL, so the frontend has to send them with the same headers Keyring sends with its own:

```ts
// nuxt.config.ts
const emailedLink = {
  headers: {
    'referrer-policy': 'no-referrer',
    'cache-control': 'no-store',
    'x-frame-options': 'DENY',
  },
}

export default defineNuxtConfig({
  routeRules: {
    '/auth/reset-password/**': emailedLink,
    '/auth/email/verify/**': emailedLink,
    '/auth/email-changes/**': emailedLink,
    '/auth/devices/**': emailedLink,
  },
})
```

`no-referrer` keeps the URL out of the `Referer` of everything the page loads, and `no-store` keeps it out of caches. Scripts on the page can still read the URL: analytics, session replay and error reporters read `location.href` themselves, and send it on. Keep them off these pages. The verification, email change and "this wasn't me" pages each act on one press of a button, so they mustn't be framed either. See [Tokens in Emailed Links](security.md#tokens-in-emailed-links).

Each page posts its secret in the body, to a path without it, as on any Keyring app (see [The Pages Emailed Links Open](frontend.md#the-pages-emailed-links-open)):

- The reset page has the token in its own path and the address in its query, so it needs nothing from Laravel before posting `token`, `email`, `password` and `password_confirmation` to `POST /auth/reset-password`.
- The email change page posts `token` to `POST /auth/email-changes/{change}/confirm` or `/revert`.
- The verification and "this wasn't me" pages post `expires` and `signature` to their own path on Laravel. Loading the page as JSON first gets the address being verified or the device's description, and checks the link: a bad or expired signature is a `403`. The verification page needs the user signed in, and answers a `401` when they aren't: send them to sign in, then back to the link. For a user whose address is already verified, it answers with the `email-verified` status instead of the page. Where registration [hides who has an account](sign-in-flow.md#without-revealing-who-has-an-account), Keyring remembers the link in the session, and signing in verifies the address.

```vue
<!-- pages/auth/devices/[device]/report.vue -->
<script setup lang="ts">
const { $keyring } = useNuxtApp()
const route = useRoute()

const { data, error } = await useAsyncData(
  'device-report',
  () => $keyring(route.path, { query: route.query }),
  { server: false },
)

async function report() {
  const { url, expires, signature } = data.value.props
  const answer = await $keyring(url, { method: 'POST', body: { expires, signature } })

  // "device-reported", with "page": "login"
  await navigateTo(pages[answer.page])
}
</script>
```

Load these pages in the browser (`server: false`), as the example does. That keeps the link's secret out of the Nuxt server's logs, and the request comes from the user's own IP address, which their [rate limit](security.md#rate-limiting) counts.

### Rendering on the Server

When Nuxt renders a page on the server, its `$fetch` doesn't send the browser's cookies, and doesn't pass the cookies Laravel sets back to the browser. The plugin above does both. Each part matters:

- **Cookies.** The session cookie is what signs the request in, so the Nuxt server needs it from the browser. That's why `SESSION_DOMAIN` covers the frontend's host.
- **Cookies Laravel sets.** Keyring can move a session to a new record on any request, such as when "remember me" brings a browser back, and it sets new cookies when it does. A cookie that's dropped on the Nuxt server leaves the browser holding a used "remember me" cookie, which ends the session the next time it's sent. See [A Cookie Used Twice](devices-and-sessions.md#a-cookie-used-twice).
- **User agent.** Keyring's `SessionFingerprintChanged` risk signal compares the browser a session came from with each request's. A request with the Nuxt server's own user agent looks like the session moved to another browser.
- **`Referer` or `Origin`.** Sanctum only starts the session for a request from a host in `sanctum.stateful`. A request from the Nuxt server has neither header unless you set one.

Even with all of that, a request from the Nuxt server comes from the server's IP address, not the user's. Keyring's rate limits count by IP address, and the security log, risk signals and device records use it. So use server-side rendering for reading, such as your own `GET /api/user`, and send Keyring's forms and challenges from the browser.

## What Doesn't Work

- **Different sites.** The frontend and Laravel must be on [one site](#choosing-a-layout).
- **Bearer tokens and mobile apps.** Pending logins and step-up live in the session, so Keyring only signs in session guards. See [Known Limitations](security.md#known-limitations).
- **Coming back after signing in, confirming or enrolling.** On another origin, Laravel doesn't learn the frontend's pages, so JSON answers give `home` as the `redirect` after signing in or confirming. On one origin, the `Referer` can make it the page the request came from. `authenticator-added` carries no `continue` either way. Keep the page the user was going to [in the frontend](#where-each-answer-goes).
- **Laravel's `guest` middleware.** Keyring's sign-in and registration routes are only for guests. Laravel redirects a signed-in request to them, a JSON one too, rather than answering it. Check whether the user is signed in, with `GET /api/user` say, before showing those pages. `$middleware->redirectUsersTo()` in `bootstrap/app.php` changes where the redirect goes, but don't point it at the frontend. `fetch()` follows the redirect to the frontend's origin, which sends no CORS headers, so the request fails with a network error.
- **Clearing the browser's data on sign out.** Keyring's `Clear-Site-Data` header only clears what the browser keeps for Laravel's origin. Clear what the frontend kept itself when signing out answers `204`.
- **The Inertia helpers.** `useChallenge` and the browser package's other Inertia helpers need Inertia. Its WebAuthn, enrollment, session, passkey sign in and single sign-on helpers work in any frontend, once [`configureRequests()`](#calling-laravel) tells them where Laravel is. See [Frontends on Another Origin](frontend.md#frontends-on-another-origin).
