# @keyringjs/keyring

This package holds the browser side of [Keyring](https://github.com/keyringphp/keyring), the factor-driven authentication package for Laravel. It runs the WebAuthn ceremonies for passkeys and security keys, wraps the enrollment routes, starts sign ins and links with identity providers, and provides Inertia bindings for the challenge page in Vue and React.

To install it, run:

```bash
npm install @keyringjs/keyring
```

For example, you may enroll a passkey like this:

```ts
import { enroll } from '@keyringjs/keyring'

// The password is needed while the account has no established second factor.
const { authenticator, recoveryCodes } = await enroll('passkey', { name: 'Laptop', password })
```

Or link an account at an identity provider, such as Google, which sends the browser there and back:

```ts
import { linkProvider } from '@keyringjs/keyring'

await linkProvider('google')
```

The package has four entry points:

| Import | Contains |
|---|---|
| `@keyringjs/keyring` | WebAuthn helpers, enrollment and session helpers, `passkeyCredential()`, `signInWithProvider()`, `linkProvider()` and `confirmWithProvider()` for single sign-on, `impersonate()` and `stopImpersonating()` for impersonation, `json()` and `configureRequests()`, routes, and types. No framework code. |
| `@keyringjs/keyring/inertia` | The challenge helpers, for Inertia with any framework. |
| `@keyringjs/keyring/vue` | Everything above, plus `useChallenge()` and `usePasskeyLogin()` for Vue. |
| `@keyringjs/keyring/react` | Everything above, plus `useChallenge()` and `usePasskeyLogin()` for React. |

A frontend that Laravel doesn't serve, such as a Nuxt application on another subdomain, points the package at Laravel with `configureRequests({ baseUrl })`. The package needs the Keyring Composer package on the server. For the full details, see the [frontend documentation](https://github.com/keyringphp/keyring/blob/main/docs/frontend.md).

## License

MIT
