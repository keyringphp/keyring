# Frontend

- [Introduction](#introduction)
- [Building the Pages](#building-the-pages)
- [The Pages Emailed Links Open](#the-pages-emailed-links-open)
- [The Challenge Page](#the-challenge-page)
    - [Vue](#vue)
    - [React](#react)
    - [Factor Components](#factor-components)
- [Signing In With a Passkey](#signing-in-with-a-passkey)
- [Signing In With an Identity Provider](#signing-in-with-an-identity-provider)
- [Challenge Helpers Without Vue or React](#challenge-helpers-without-vue-or-react)
- [Managing Authenticators](#managing-authenticators)
- [Sessions](#sessions)
- [Handling Step-Up in JavaScript](#handling-step-up-in-javascript)
- [JSON Requests](#json-requests)
- [WebAuthn Helpers](#webauthn-helpers)
- [Changing Routes](#changing-routes)
- [Frontends on Another Origin](#frontends-on-another-origin)
    - [Cookies and CSRF](#cookies-and-csrf)
    - [Signing In Without Inertia](#signing-in-without-inertia)
    - [Rendering on the Server](#rendering-on-the-server)
- [Flash Messages and Alerts](#flash-messages-and-alerts)
- [Without Inertia](#without-inertia)

## Introduction

Keyring is headless. It renders [pages](sign-in-flow.md#pages) with props and answers JSON requests, and your application owns every page. `@keyringjs/keyring` is a small browser package that handles the tricky parts for you: WebAuthn, enrollment, and Vue and React bindings for Inertia v3.

```bash
npm install @keyringjs/keyring
```

The package is plain ES modules, so it works with any bundler. Its main entry point has no dependencies, so a Blade application without a bundler can copy its `dist` folder into `public/` and import it from a `<script type="module">` tag. The package has four entry points:

| Import | Contains |
|---|---|
| `@keyringjs/keyring` | WebAuthn helpers, enrollment and session helpers, `passkeyCredential()`, the single sign-on helpers, `json()` and `configureRequests()`, routes, and types. No framework code. |
| `@keyringjs/keyring/inertia` | The [challenge helpers](#challenge-helpers-without-vue-or-react), for Inertia with any framework. |
| `@keyringjs/keyring/vue` | Everything above, plus `useChallenge()` and `usePasskeyLogin()` for Vue. |
| `@keyringjs/keyring/react` | Everything above, plus `useChallenge()` and `usePasskeyLogin()` for React. |

## Building the Pages

Keyring renders components named `auth/login`, `auth/challenge`, and so on. The [Pages](sign-in-flow.md#pages) documentation lists each one and its props. Most are plain forms that post to Keyring's routes, but two need a little more work:

- **The challenge page** (and `confirm`, for step-up) shows whichever factor comes next. [`useChallenge`](#the-challenge-page) does the work.
- **The login page** can offer passkeys, with [`usePasskeyLogin`](#signing-in-with-a-passkey), and [identity providers](#signing-in-with-an-identity-provider) from its `providers` prop.

Settings pages for authenticators, sessions, devices, and the email address are yours to build too, using the [helpers below](#managing-authenticators) and the JSON routes. If you'd like a reference, the [example application](https://github.com/keyringphp/example) has every page, written in React with the components from the Laravel starter kit.

## The Pages Emailed Links Open

Four pages are where an emailed link lands: `reset-password`, `email-verification`, `email-change`, and `device-report`. Each link carries a token or a signature in its URL, and none of these pages does anything when it's merely opened. Each page's form posts that secret in the request body, to a URL that doesn't include it:

| Page | Post To | With |
|---|---|---|
| `reset-password` | `/reset-password` | `token`, `email`, `password`, `password_confirmation` |
| `email-change` | its `url` prop | `token` |
| `email-verification` | its `url` prop | `expires`, `signature` |
| `device-report` | its `url` prop | `expires`, `signature` |

The last three pages each have a single button. In React, you may build one with Inertia's `<Form>` component:

```tsx
import { Form } from '@inertiajs/react'

export default function DeviceReport({ device, url, expires, signature }: { device: string, url: string, expires: string, signature: string }) {
  return (
    <Form action={url} method="post" transform={data => ({ ...data, expires, signature })}>
      <p>This signs out {device}.</p>
      <button type="submit">Sign that device out</button>
    </Form>
  )
}
```

The `email-verification` page works the same way, with its own wording. The `email-change` page posts `{ token }` and reads `action` (`confirm` or `revert`) to choose its wording. Hidden inputs work as well as `transform`. Don't put the token or signature back in the URL you post to. Keyring reads them from the body only.

These pages are sent with `Referrer-Policy: no-referrer`, since their address holds the secret. When the form succeeds, Keyring has Inertia load the next page in full, so the rest of your application goes back to sending a referrer. That's why the visit after one of these pages isn't a client-side visit, and there's nothing you need to do for it.

## The Challenge Page

The `challenge` page (and `confirm`) receives the [challenge props](sign-in-flow.md#page-props). `useChallenge` turns them into everything the page needs: the component for the current factor, a form, "try another way", and submission.

Pass it a map of factor keys to components. For example, you may define that map in `resources/js/keyring/factors.ts`:

```ts
import { defineAsyncComponent } from 'vue'

export default {
  'password': defineAsyncComponent(() => import('./factors/Password.vue')),
  'totp': defineAsyncComponent(() => import('./factors/Code.vue')),
  'email-code': defineAsyncComponent(() => import('./factors/Code.vue')),
  'recovery': defineAsyncComponent(() => import('./factors/Code.vue')),
  'passkey': defineAsyncComponent(() => import('./factors/SecurityKey.vue')),
  'security-key': defineAsyncComponent(() => import('./factors/SecurityKey.vue')),
}
```

When you add a factor on the server, you also add one line to this map. In React, use `lazy` and a `<Suspense>` boundary instead.

### Vue

```vue
<script setup lang="ts">
import { useChallenge, type ChallengeProps } from '@keyringjs/keyring/vue'
import factors from '../../keyring/factors'

const props = defineProps<ChallengeProps>()
const challenge = useChallenge(props, factors)
</script>

<template>
  <component :is="challenge.component" :key="`${props.factor}:${props.authenticator.id}`" :challenge="challenge" />

  <label v-if="props.canTrustDevice">
    <input v-model="challenge.form.trust" type="checkbox"> Don't ask again on this device
  </label>

  <button v-for="option in props.alternatives" :key="`${option.factor}:${option.id}`" @click="challenge.switchTo(option)">
    {{ option.name }}
  </button>
</template>
```

`useChallenge(props, factors)` returns a reactive object, typed `Challenge`:

| | |
|---|---|
| `form` | An Inertia form with `code`, `password`, and `trust`. |
| `props` | The page props you passed in. |
| `component` | The component for `props.factor`, or `undefined` when the map has none. |
| `submit(data?)` | Posts the form, plus `data` and the authenticator ID, to the verify route. Clears `code` and `password` afterwards. |
| `switchTo(option)` | Visits the challenge page for one of `props.alternatives`. |
| `send()` | Asks the server to send a code, for factors that send one. |
| `verifyKey()` | Runs the WebAuthn ceremony with `props.challenge.options` and submits the result. Calling it again while the prompt is open replaces that prompt. Closing the prompt does nothing, while other browser errors are set on `form.errors.credential`. |

Factor components receive `challenge`, and read the page from `challenge.props`.

If a factor has no component in the map, `component` is `undefined`. A good fallback is your security key component when the challenge has WebAuthn `options`, and your code component otherwise.

### React

```tsx
import { useChallenge, type ChallengeProps } from '@keyringjs/keyring/react'
import { Suspense } from 'react'
import factors from '../../keyring/factors'

export default function ChallengePage(props: ChallengeProps) {
  const challenge = useChallenge(props, factors)
  const { Component, form } = challenge

  return (
    <>
      <Suspense fallback={null}>
        {Component && <Component key={`${props.factor}:${props.authenticator.id}`} challenge={challenge} />}
      </Suspense>

      {props.canTrustDevice && (
        <label>
          <input type="checkbox" checked={form.data.trust} onChange={e => form.setData('trust', e.target.checked)} />
          Don't ask again on this device
        </label>
      )}

      {props.alternatives.map(option => (
        <button key={`${option.factor}:${option.id}`} onClick={() => challenge.switchTo(option)}>{option.name}</button>
      ))}
    </>
  )
}
```

The React hook returns the same values as Vue's, except that the component is called `Component` (capitalised) instead of `component`. Factor components receive `challenge` (typed `Challenge`) in the same way.

### Factor Components

A factor component shows the right input and calls the challenge's methods. Factors that send codes include `sent` in their challenge props, which lets a component decide whether to show a "send code" button first. Here's a minimal code factor in Vue:

```vue
<script setup lang="ts">
import type { Challenge } from '@keyringjs/keyring/vue'

const { challenge } = defineProps<{ challenge: Challenge }>()
</script>

<template>
  <button v-if="'sent' in challenge.props.challenge && !challenge.props.challenge.sent" @click="challenge.send()">Send code</button>

  <form v-else @submit.prevent="challenge.submit()">
    <input v-model="challenge.form.code" autocomplete="one-time-code" inputmode="numeric">
    <p v-if="challenge.form.errors.code">{{ challenge.form.errors.code }}</p>
    <button :disabled="challenge.form.processing">Verify</button>
  </form>
</template>
```

A security key component usually calls `challenge.verifyKey()` as soon as it mounts. It also usually shows a "try again" button, in case the user dismisses the browser prompt. Under React's StrictMode, guard the call with a ref so the prompt opens only once.

## Signing In With a Passkey

`usePasskeyLogin` runs a [usernameless passkey sign in](passkeys.md#signing-in-without-a-username). It fetches the options, asks the browser for a passkey, and posts the result.

```vue
<script setup lang="ts">
import { usePasskeyLogin } from '@keyringjs/keyring/vue'
import { useForm } from '@inertiajs/vue3'

const form = useForm({ email: '', password: '', remember: false })
const { supported, processing, error, signIn } = usePasskeyLogin({ autofill: true, remember: () => form.remember })
</script>

<template>
  <input v-model="form.email" type="email" autocomplete="username webauthn">

  <button v-if="supported" :disabled="processing" @click="signIn()">Sign in with a passkey</button>
  <p v-if="error">{{ error }}</p>
</template>
```

| Option | |
|---|---|
| `autofill` | Also offer passkeys in the email field's autofill, when the browser supports it. The field needs `autocomplete="username webauthn"`. |
| `factor` | The factor key, `passkey` by default. |
| `remember` | A function returning whether "remember me" is ticked, read when the passkey is used. It works the same way in Vue and React. In React, for example, pass `remember: () => form.data.remember`. |

`usePasskeyLogin` returns `supported` (whether the browser has WebAuthn), `processing`, `error`, and `signIn`. In Vue, the first three are refs. A few details are worth knowing:

- Starting a new sign in cancels the one in progress, and only the newest one updates `processing` and `error`.
- `processing` is also true while a passkey picked from autofill is being checked.
- Closing the prompt isn't an error.
- After an explicit sign in that didn't work, the email field offers passkeys again.
- The autofill request is cancelled when the component unmounts.

If your starter kit's passkey button uses `@laravel/passkeys`, you can keep it. It [signs in through the same two routes](passkeys.md#laravels-passkeys-client) once you give it their paths. Adding a passkey and the challenge page still need the helpers here.

## Signing In With an Identity Provider

When the [`SingleSignOn`](sso.md) factor is registered, the login page's `providers` prop lists the identity providers to offer, each with a `name`, a `label`, and the `url` that starts a sign in. Link to the `url`, adding `?remember=1` for "remember me". The `LoginProps` and `IdentityProvider` types describe them:

```tsx
import type { LoginProps } from '@keyringjs/keyring'

export default function Login({ providers, status }: LoginProps) {
  return (
    <>
      {status && <p>{status}</p>}
      {providers.map(provider => (
        <a key={provider.name} href={provider.url}>Sign in with {provider.label}</a>
      ))}
    </>
  )
}
```

The browser leaves your site for the provider, so use a plain link. When the sign in doesn't work, the user comes back to the login page with the error on the username field, in the page's `errors`.

To link an account at a provider from a settings page, `linkProvider(name, { password })` begins the `sso` enrollment and sends the browser to the provider. The `password` is needed while the account has a password and no [established](authenticators.md#established-authenticators) second factor, as it is for any other sign-in method. It throws a `KeyringRequestError` before going anywhere when the request fails, such as with the `423` of [step-up](#handling-step-up-in-javascript), or a `422` on `password`. When the provider sends the user back, Keyring finishes the link and returns them to the page they started from, with the `authenticator-added` status. A linked account is presented as an `SsoAuthenticator`, with its `provider` and `email` added.

| Function | Does |
|---|---|
| `linkProvider(provider, { password? })` | `POST /user/authenticators/sso` with `provider`, and `password` when it's given, then `location.assign()` to the provider's URL in the answer. |
| `signInWithProvider(provider, { remember? })` | Asks `GET /auth/{provider}/redirect` for the provider's URL as JSON, then `location.assign()` to it. A link does the same on a page Laravel serves, so this is for a [frontend on another origin](#frontends-on-another-origin). |
| `confirmWithProvider(authenticator)` | Asks `GET /confirm/sso/redirect` for the provider's URL for that link as JSON, then `location.assign()` to it, to [confirm a step-up](sso.md#step-up) by signing in there. |

On the confirm page, a link at an identity provider is offered like any other method. When its provider's [`freshness`](sso.md#freshness) is `never`, the default for Google and GitHub, it's only offered toward a level, such as getting a lapsed AAL2 back, and never for `keyring.fresh`, so your confirm page still needs an `sso` component for those providers. Its `challenge` is an `SsoChallenge`, with the `provider`, its `label`, and the `url` that sends the user there. Link to the `url`, or call `confirmWithProvider(authenticator.id)` from a frontend on another origin. The provider sends the user back to Keyring, which goes on to the page that asked them to confirm. A provider whose `freshness` is `reauthenticate` has the user sign in again there, and one you opted into a `round_trip` may let them straight through, as signing in with it again would.

`routes.ssoRedirect(provider)`, `routes.ssoCallback(provider)` and `routes.ssoConfirm(authenticator?)` are the paths. See [Single Sign-On](sso.md) for setting up the providers, and for the callback page a frontend Laravel doesn't serve needs.

## Challenge Helpers Without Vue or React

The Vue and React bindings are thin layers over these helpers, which are exported from `@keyringjs/keyring/inertia` and re-exported by the Vue and React entry points. Use them to build the challenge page or passkey sign in with another framework. They post with Inertia's router (`@inertiajs/core`).

| Function | Does |
|---|---|
| `challengeFields()` | The fields a challenge form starts with: `code`, `password`, and `trust`. |
| `switchTo(props, option)` | Visits the challenge page for one of `props.alternatives`. |
| `sendCode(props)` | Asks the server to send a code for the current authenticator. |
| `keyCredential(props, signal?)` | Runs the browser prompt with `props.challenge.options` and resolves to the credential to post as `credential`. |
| `keyPrompt()` | Makes a prompt function for a challenge page: `await prompt(props)` resolves to the credential, or `null` when the user closed the prompt or a newer call replaced it. |
| `passkeyCredential(factor, { autofill?, signal? })` | Fetches the usernameless options, reads them from `options` in the answer, and runs the prompt (or autofill). |
| `signInWith(factor, credential, remember, { onError, onFinish })` | Posts a credential from `passkeyCredential()` to sign in. `onError` gets the first error message. |
| `passkeyLogin(options, onChange)` | The state behind `usePasskeyLogin()`: call `start()` once mounted, `signIn()` for the button, and `stop()` when unmounting. `onChange` gets `{ processing, error }`. |
| `isAbort(error)` | Whether the error means the user closed the prompt (or it timed out), or that a newer request replaced it. |
| `errorMessage(error)` | A readable message for any thrown value. |

> [!NOTE]
> Browsers report a closed prompt and a timeout as `NotAllowedError`. They also throw that error when WebAuthn isn't allowed at all, such as in a cross-origin iframe without the `publickey-credentials-get` permission. If a prompt never appears, check that first.

```ts
import { errorMessage, isAbort, passkeyCredential, signInWith } from '@keyringjs/keyring/inertia'

try {
  const credential = await passkeyCredential('passkey')
  signInWith('passkey', credential, false, { onError: showError, onFinish: () => {} })
} catch (error) {
  if (!isAbort(error)) showError(errorMessage(error))
}
```

## Managing Authenticators

The enrollment helpers call the [authenticator routes](authenticators.md) with JSON requests:

```ts
import { beginEnrollment, confirmEnrollment, enroll, linkProvider, makeDefault, removeAuthenticator, renameAuthenticator } from '@keyringjs/keyring'

// One step for factors that need no input in between. An account with no
// established second factor sends its password with the first one.
const { authenticator, recoveryCodes } = await enroll('passkey', { name: 'Laptop', password })
const { enrollment } = await enroll('recovery')   // enrollment.codes holds the new codes

// An identity provider: the browser goes there, and comes back linked. It
// takes the password when adding a second factor would.
await linkProvider('google', { password })

// Two steps for authenticator apps and email codes.
const started = await beginEnrollment('totp', { name: 'Work phone', password })
showQrCode(started.enrollment.qr)
const added = await confirmEnrollment('totp', started.enrollment, { code })

await renameAuthenticator(added.authenticator.id, 'Personal phone')
await makeDefault(added.authenticator.id)
await removeAuthenticator(added.authenticator.id)
```

| Function | Does |
|---|---|
| `beginEnrollment(factor, data?)` | `POST /user/authenticators/{factor}`. Resolves to `{ factor, enrollment }`. Send `password` in `data` when the account has no [established](authenticators.md#established-authenticators) second factor yet, or the request fails with an error on `password`. See [The Password for a First Second Factor](authenticators.md#the-password-for-a-first-second-factor). A `proof` goes here too. |
| `confirmEnrollment(factor, enrollment, data?)` | `POST /user/authenticators/{factor}/confirm`. For `passkey` and `security-key`, runs the browser ceremony first. If the server rejects the response, or refuses it as frozen, the enrollment is spent, so start again with `beginEnrollment()`. Resolves to `{ authenticator, recoveryCodes?, continue? }`, where `authenticator` is typed `Authenticator`: `factor`, `id`, `name`, `createdAt`, and `lastUsedAt`, along with any extras specific to the factor. |
| `enroll(factor, data?)` | Both, one after the other. `data` goes to both requests, apart from `password` and `proof`, which only go with the first. |
| `renameAuthenticator(id, name, { proof }?)` | `PATCH` with `name`. Resolves to `{ authenticator }`. Renaming an established authenticator while frozen needs `proof` from `proveWithKey()`. |
| `makeDefault(id)` | `PATCH` with `default: true`. Resolves to `{ authenticator }`. Recovery codes and identity provider links can't be the default, and throw a `KeyringRequestError` with a `422` on `default`. |
| `removeAuthenticator(id, password?, { signOutOthers, proof }?)` | `DELETE`. Removing the user's last second factor also needs their password. `signOutOthers: true` [ends the user's other sessions](authenticators.md#signing-out-other-sessions) too. When adding, pass `sign_out_others: true` in `data` to `confirmEnrollment()` or `enroll()`. `proof` comes from `proveWithKey()`. |
| `linkProvider(provider, { password? })` | Begins linking an account at an [identity provider](#signing-in-with-an-identity-provider), and sends the browser there. |
| `proveWithKey(factor, { action, target, name? })` | `POST /user/authenticators/{factor}/proof-options`, then the browser's ceremony. Resolves to a `FreezeProof`, `{ factor, credential }`, for the one change it was asked for. See below. |
| `frozenChanges(error)` | The `FrozenChanges` a request was refused for, or `null` when it wasn't refused as frozen. |
| `isWebAuthn(enrollment)` | Whether `confirmEnrollment()` runs the browser ceremony: true when the server sent WebAuthn creation options, whatever the factor's key. |

Removing or renaming an established authenticator, or replacing established recovery codes, while the account's sign-in methods are [frozen](authenticators.md#frozen-sign-in-methods) throws a `KeyringRequestError` with a `422`. Show `error.errors.authenticator`, which says how long is left. `error.data.frozen` is a `FrozenChanges`, with the `reason`, an ISO 8601 `until` for a page that formats the time itself, and `skip`. `frozenChanges(error)` reads it for you.

`skip` lists the factors that could make the change now. When it names a passkey or security key, offer "Use your passkey to do this now". `proveWithKey()` asks for a challenge for that one change, runs the ceremony, and returns the proof to send the request again with. See [Making a Change With an Established Key](authenticators.md#making-a-change-with-an-established-key):

```ts
import { frozenChanges, KeyringRequestError, proveWithKey, removeAuthenticator } from '@keyringjs/keyring'

try {
  await removeAuthenticator(id)
} catch (error) {
  const frozen = frozenChanges(error)

  if (!(error instanceof KeyringRequestError) || frozen === null) {
    throw error
  }

  message.value = `${error.errors.authenticator[0]} (${new Date(frozen.until).toLocaleString()})`
  // Offer a button for this when frozen.skip has the user's key factor.
  canUseKey.value = frozen.skip.includes('passkey')
}

// When they press it:
const proof = await proveWithKey('passkey', { action: 'remove', target: id })
await removeAuthenticator(id, undefined, { proof })
```

For a rename, prove `{ action: 'rename', target: id, name }` and pass the proof to `renameAuthenticator(id, name, { proof })` with the same name. For new recovery codes, prove `{ action: 'replace', target: 'recovery' }` and pass the proof to `beginEnrollment('recovery', { proof })`, or to `enroll()`. The confirm needs nothing more, and never takes a proof: if it's refused as frozen, begin again with one. Where the server allows an authenticator app (`skip_with_totp`), `skip` lists `totp`. Send `{ factor: 'totp', code }` as the proof instead, with no ceremony, and `authenticator`, the app's ID, when the user has more than one.

If `recoveryCodes` comes back, show the codes and ask the user to save them. If `continue` comes back too, it's the page the user was going to when Keyring sent them to enroll, and the account can now meet what sent them. Offer it as a "Continue" link once the codes are saved. See [Carrying On Afterwards](policies.md#carrying-on-afterwards).

## Sessions

Three helpers call the [session routes](devices-and-sessions.md#listing-and-ending-sessions), which every application has:

```ts
import { endOtherSessions, endSession, listSessions } from '@keyringjs/keyring'

const sessions = await listSessions()

await endSession(sessions[1].id)   // one session, by its handle
await endOtherSessions()           // every session but this one
```

| Function | Does |
|---|---|
| `listSessions()` | `GET /user/sessions`. Resolves to the sessions, most recently active first, each a `Session`: `id`, `name`, `ip`, `device`, `remembered`, `signedInAt`, `lastActiveAt`, `expiresAt`, `current`, `impersonated`, and `impersonator` (`{ name }`, or `null`). |
| `endSession(id)` | `DELETE /user/sessions/{id}`. Ending the one marked `current` signs the user out and resolves to `{}`, so send them to the login page. |
| `endOtherSessions()` | `DELETE /user/sessions`. |

The `id` is a handle that only these routes accept. It stays the same when the session moves to a new record. It stops matching once the session has ended (or the app key is rotated without `APP_PREVIOUS_KEYS`), so list the sessions again before ending one from a list that's been open for a while. An old handle gets a `404`. Both functions that end sessions need a fresh verification, as the authenticator helpers do. [Handling Step-Up in JavaScript](#handling-step-up-in-javascript) shows how to handle that.

`impersonate(id)` and `stopImpersonating()` call the [impersonation routes](impersonation.md#routes), and the `Impersonation` type describes what `Keyring::impersonation()` shares for a [banner](impersonation.md#showing-a-banner).

## Handling Step-Up in JavaScript

The authenticator routes need a [fresh verification](step-up.md#fresh-verification). When the user doesn't have one, a JSON request fails with a `423` status and a `redirect` to the confirm page. The helpers throw a `KeyringRequestError` with that status:

```ts
import { KeyringRequestError, enroll } from '@keyringjs/keyring'
import { router } from '@inertiajs/vue3'

async function addPasskey() {
  try {
    await enroll('passkey', { password })
  } catch (error) {
    if (error instanceof KeyringRequestError && error.status === 423) {
      router.visit(error.data.redirect)
      return
    }

    throw error
  }
}
```

After a JSON `423`, Keyring remembers the page that made the call, using the `Referer` header. Once the user confirms, they return to that page. Without a `Referer`, Laravel uses the last page it saw in the session. You may also protect the page's own `GET` route with the `keyring.fresh` middleware. In that case, step-up happens when the page loads, and the JSON calls on that page pass while the verification is fresh:

```php
Route::get('/settings/security', SecuritySettingsController::class)
    ->middleware(['auth', 'keyring.fresh:15m']);
```

> [!NOTE]
> Use a window no longer than the one in `changes_middleware`, so the page doesn't outlive the routes it calls.

The same applies to your own routes protected by `keyring:aal2` or `keyring.fresh` that you call with `fetch` or `json`.

## JSON Requests

The `json(method, url, body?)` function is a small `fetch` wrapper that the helpers use. It sends `Accept: application/json`, `X-Requested-With`, and Laravel's `XSRF-TOKEN` cookie as `X-XSRF-TOKEN`. This way, Keyring answers with JSON, and CSRF protection passes. The token only goes to the page's own origin, or to the [`baseUrl`](#frontends-on-another-origin) when you set one, never to a full URL on some other origin. You may use it for Keyring's other JSON routes:

```ts
import { json } from '@keyringjs/keyring'

const { devices } = await json('GET', '/user/devices')
const { pending } = await json('GET', '/user/email')
await json('PUT', '/user/password', { current_password, password, password_confirmation })
```

On a non-2xx response, it throws a `KeyringRequestError` with `status`, `message`, `errors` (Laravel's validation errors), and `data` (the whole body).

The requests use `credentials: 'same-origin'`, which is what an application Laravel serves needs. A frontend on another origin can change that with [`configureRequests()`](#frontends-on-another-origin).

## WebAuthn Helpers

These helpers are useful for building your own flows:

| Function | |
|---|---|
| `supportsWebAuthn()` | Whether the browser has WebAuthn. |
| `supportsAutofill()` | Whether it can offer passkeys in autofill. |
| `createCredential(options)` | Runs `navigator.credentials.create()` with Keyring's JSON options and returns the result as JSON for the server. |
| `getCredential(options, { autofill?, signal? })` | The same for `navigator.credentials.get()`. |
| `toBase64Url(buffer)`, `fromBase64Url(value)` | Encoding helpers. |

They use the browser's built-in JSON parsing when it exists, and convert by hand when it doesn't.

## Changing Routes

The helpers use Keyring's default paths. If you changed the `prefix` option, tell the helpers once, at startup:

```ts
import { configureRoutes } from '@keyringjs/keyring'

configureRoutes({ prefix: 'account' })
```

If you registered the routes yourself, override the ones you moved:

```ts
configureRoutes({
  enroll: factor => `/account/authenticators/${encodeURIComponent(factor)}`,
  confirmEnrollment: factor => `/account/authenticators/${encodeURIComponent(factor)}/confirm`,
  authenticator: id => `/account/authenticators/${encodeURIComponent(id)}`,
})
```

The keys are `prefix`, `login`, `loginOptions`, `loginWith`, `challenge`, `verify`, `send`, `challengeBase`, `enroll`, `confirmEnrollment`, `authenticator`, `proofOptions`, `sessions`, `session`, `ssoRedirect`, `ssoCallback`, `ssoConfirm`, `impersonate`, and `stopImpersonating`. `challengeBase(purpose)` is the prefix the challenge routes share (`/login/challenge` for `login`, `/confirm` for `confirm`), so changing it moves all three:

```ts
configureRoutes({
  challengeBase: purpose => purpose === 'login' ? '/account/login/challenge' : '/account/confirm',
})
```

Keyring's own paths put a factor's key or an ID into the URL as one encoded path segment. They throw a `TypeError` for `.` and `..`, since a browser resolves those away however they're written. So a value the server didn't issue, one with a `/` or a `?` in it, can't send the request and the user's cookies to another path. An override is used exactly as written, without the `prefix`, so encode the values your override receives too, as the `enroll` example above does.

Update any paths your own pages link to directly, such as `/login` or `/register`.

## Frontends on Another Origin

By default, the package sends its requests to the page's own origin, which is right when Laravel serves the frontend. When it doesn't, such as a Nuxt or Next application on `app.example.com` calling Laravel on `api.example.com`, tell the package where Laravel is, once, at startup:

```ts
import { configureRequests } from '@keyringjs/keyring'

configureRequests({
  baseUrl: 'https://api.example.com',
  csrfCookie: '/sanctum/csrf-cookie',
})
```

Laravel needs setting up for this too: CORS that allows credentials, a `SESSION_DOMAIN` both hosts share, and the frontend's origin for passkeys, plus Sanctum's stateful API if you want your own `api` routes and the `/sanctum/csrf-cookie` route. [Headless Frontends](headless.md) covers the Laravel side.

| Option | |
|---|---|
| `baseUrl` | Where Laravel is. Every path `json()` sends goes there, Keyring's routes and your own calls such as `json('GET', '/api/user')` alike. It may include a path, such as `https://example.com/backend`. A full URL given to `json()` still goes where it says. It must be an absolute `http` or `https` URL without credentials, a query or a fragment, or `configureRequests()` throws a `TypeError`. `null` goes back to the page's origin. |
| `credentials` | The `credentials` option of each `fetch`. By default it's `include` for a request to `baseUrl` when that's on another origin than the page, or when there's no page, as when rendering on the server. Anything else, including a full URL on some other origin, is `same-origin`, as before. |
| `csrfCookie` | A URL that sets the `XSRF-TOKEN` cookie, resolved against `baseUrl` like any path. When it's set and the cookie isn't there, `json()` fetches it before any request but a `GET`, once for requests made together. Off by default. If fetching it fails, the request throws a `KeyringRequestError` with that response's status. If it succeeds and the cookie still can't be read, the request throws a `KeyringRequestError` with a `419` status that says so, rather than posting without a token. |
| `fetch` | A function to call instead of the global `fetch`, taking a URL and the init and resolving to a `Response`. See [Rendering on the Server](#rendering-on-the-server). |

Only the options you pass change. Passing one as `undefined` puts it back to its default. An option the package doesn't have, such as `baseURL` spelt the way axios and ofetch spell it, throws a `TypeError`.

`routes` still holds paths, so `routes.login` is still `/login`, and `json()` adds `baseUrl` when it sends one. `configureRoutes()` works as before: set the `prefix` with it if you changed Keyring's, and the base URL is added in front of the prefix. Only the `routes.*` paths carry the prefix. A path you write yourself, such as `/api/user`, goes to `baseUrl` exactly as written.

If the frontend reaches Laravel through a proxy on its own origin, such as `app.example.com/backend`, the requests are same-origin and need no `baseUrl`. Put the proxy's path in the prefix instead, with `configureRoutes({ prefix: 'backend/auth' })` when Keyring's prefix is `auth`.

### Cookies and CSRF

Keyring signs users in with Laravel's session cookie, so the browser has to send that cookie to `api.example.com`. With `credentials: 'include'`, it does, as long as Laravel's CORS config has `supports_credentials` turned on and names your frontend's origin.

Laravel checks a CSRF token on every request but a `GET`. Sanctum's SPA flow gets that token from `GET /sanctum/csrf-cookie`, which sets an `XSRF-TOKEN` cookie. `json()` reads that cookie from `document.cookie` and sends it back as `X-XSRF-TOKEN`. Two things follow from that:

- The frontend can only read the cookie when Laravel sets it for a domain both hosts share, with `SESSION_DOMAIN=.example.com`. If the two are on unrelated domains, such as `app.com` and `api.net`, browsers treat Laravel's cookies as third-party cookies, and session sign in doesn't work. Put them on one domain, or use tokens instead.
- Before the first `POST`, the cookie has to exist. The `csrfCookie` option fetches it for you, and throws when the cookie arrives but the page can't read it, which is what a missing `SESSION_DOMAIN` looks like. Without that option, fetch it yourself first:

```ts
await fetch('https://api.example.com/sanctum/csrf-cookie', { credentials: 'include' })
```

Laravel sends a fresh `XSRF-TOKEN` cookie with its responses, so once it exists, there's nothing more to do when the token changes, such as after signing in. A `419` status means the token was missing or didn't match, which usually means one of the two points above. The package doesn't depend on Sanctum: any route that sets the `XSRF-TOKEN` cookie works as `csrfCookie`.

### Signing In Without Inertia

The `inertia`, `vue`, and `react` entry points post with Inertia's router, so a frontend that doesn't use Inertia uses the main entry point and `json()`. `passkeyCredential()` and `isAbort()` are in the main entry point too, so a passkey sign in looks like this:

```ts
import { isAbort, json, passkeyCredential, routes } from '@keyringjs/keyring'

try {
  const credential = await passkeyCredential('passkey')
  const answer = await json('POST', routes.loginWith('passkey'), { credential, remember: false })
  // Sign in done, or a challenge to show next. Headless Frontends describes the answer.
} catch (error) {
  if (!isAbort(error)) showError(error)
}
```

The challenge page works the same way. Run `getCredential(challenge.options)` for a passkey or security key, then post the `code` or `password` the factor needs, `trust`, the `authenticator` ID, and any `credential` to `routes.verify(purpose, factor)` with `json()`. [Headless Frontends](headless.md#pages-as-json) describes what each of Keyring's pages answers with JSON.

To decide which of your pages comes next, go by an answer's `page` when there is one, then its `redirect`. A `redirect`, such as the one in a step-up `423`, is a URL on Laravel's side, so point it at the matching page of your frontend rather than sending the browser to `api.example.com`. See [Where Each Answer Goes](headless.md#where-each-answer-goes). Keyring only remembers pages the browser navigates to on its own origin, so a frontend on another origin never gets `continue` and keeps track of where the user was itself.

### Rendering on the Server

On the server, there's no `document`, so `json()` sends no XSRF token there and doesn't fetch `csrfCookie`. The browser's cookies aren't there either, so a request made during server rendering is a guest's unless you forward them. The simplest approach is to call the package's helpers in the browser only, such as in `onMounted` or a client-only plugin.

The `fetch` option is useful for anything that's the same for every request, such as an internal URL to reach Laravel, a fixed header, or logging:

```ts
configureRequests({
  baseUrl: 'https://api.example.com',
  fetch: (url, init) => fetch(url, { ...init, headers: { ...init.headers, 'Accept-Language': 'en' } }),
})
```

> [!WARNING]
> `configureRequests()` sets one configuration for the whole JavaScript process. On a server that renders pages for many users at once, never pass a `fetch` that adds one user's cookies, since another user's render may use it. Forward cookies for a single request with your framework's own request-scoped fetch, and call Keyring's routes with it directly. Nuxt's `useRequestFetch()` forwards the browser's cookies, but drops the `Set-Cookie` Laravel answers with, which can end a remembered session. [Rendering on the Server](headless.md#rendering-on-the-server) in Headless Frontends covers what to do about that.

Don't pass Nuxt's `$fetch` or ofetch as `fetch`. They resolve to the parsed body rather than a `Response`.

## Flash Messages and Alerts

Keyring's non-JSON responses flash a `status` slug to the session. JSON responses include it as `status`, along with a readable `message`. Examples include `code-sent`, `password-updated`, `device-revoked`, and `email-change-requested`. Extra data, such as new recovery codes, is flashed encrypted, so read it with `Keyring::result` rather than from the session. See [Status Responses](sign-in-flow.md#status-responses).

You can share them through your Inertia middleware, alongside the ["was this you?" alerts](security-log-and-emails.md#was-this-you-alerts). `Keyring::statusMessage` translates a slug from `keyring::status.*`, and returns `null` for anything else:

```php
use Keyring\Facades\Keyring;

public function share(Request $request): array
{
    return [
        ...parent::share($request),
        'status' => fn () => $request->session()->get('status'),
        'statusMessage' => fn () => Keyring::statusMessage($request->session()->get('status')),
        'keyringResult' => fn () => Keyring::result(),
        'keyringAlerts' => fn () => $request->session()->get('keyring.alerts', []),
        'impersonation' => fn () => Keyring::impersonation($request),
    ];
}
```

`impersonation` is `null` unless someone is [impersonating](impersonation.md#showing-a-banner) the user, for a banner with a way back.

The `login`, `forgot-password`, and `verify-email` pages already receive the translated message as their `status` prop.

After a user was sent to enroll, `Keyring::result('continue')` holds the page they were going to once they've added a sign-in method that gets them in, for Inertia and Blade pages alike. One that still leaves them short, such as an email code where a second factor is asked for, leaves it out and keeps the page for the next. Like the rest of the result, it's only there on the request right after `authenticator-added`, so read it on the page that response sends the user back to. JSON clients get `continue` in the body of the `authenticator-added` response instead. After a held password change, Inertia and Blade are redirected there, and JSON clients get it as `redirect`. Keyring only remembers pages the browser navigates to. A separate SPA that calls Keyring with JSON keeps track of its own route, and won't get one.

## Without Inertia

Without Inertia, Keyring renders Blade views named `auth.login`, `auth.challenge`, and so on, with the props passed as view data. You may write those views yourself, or point pages anywhere you like with [`Keyring::page`](sign-in-flow.md#pages). The browser package's WebAuthn, enrollment, session, passkey sign in, and single sign-on helpers work without Inertia. The challenge helpers and the `vue` and `react` entry points do need it. A frontend that Laravel doesn't serve at all is covered in [Frontends on Another Origin](#frontends-on-another-origin).
