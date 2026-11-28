# Keyring Documentation

Keyring handles the authentication side of a Laravel application, taking care of signing in, registration, password resets, email verification, second factors, passkeys, single sign-on, step-up, devices, sessions, and account changes. It doesn't ship any UI of its own. Your application owns the pages and the account actions, and Keyring provides everything around them.

The pages below are grouped by topic.

## Getting Started

- [Quick Start](quick-start.md): from installing Keyring to a working sign in, along with the pages to build and your settings page.
- [Installation](installation.md): the requirements, how to install, and the files Keyring publishes.
- [Configuration](configuration.md): every option in `config/keyring.php`, and the `Keyring` facade.
- [Upgrading From Fortify](upgrading-from-fortify.md): importing existing two factor data, mapping Fortify concepts, and replacing Fortify in a starter kit.

## Signing In

- [Factors](factors.md): the built-in factors, and how to write your own.
- [Policies](policies.md): deciding what each user must prove.
- [The Sign In Flow](sign-in-flow.md): login, the challenge page, the verification pipeline, responses, and pages.
- [Step-Up](step-up.md): asking signed-in users to prove who they are again, from middleware or a controller, and reading what they proved.
- [Passkeys & Security Keys](passkeys.md): WebAuthn settings, and what Keyring does and doesn't check.
- [Single Sign-On](sso.md): signing in with Google, Microsoft, GitHub, or any OpenID Connect provider, and linking accounts at them.
- [More Identity Providers](sso-providers.md): config for GitLab, Slack, Twitch, Okta, Auth0, Keycloak, Cognito, and Salesforce, drivers for Discord, Bitbucket, Facebook, and LinkedIn, and why Apple isn't supported.

## Account Security

- [Managing Authenticators](authenticators.md): adding, renaming, and removing sign-in methods, and recovery codes.
- [Devices & Sessions](devices-and-sessions.md): device recognition, the session registry, timeouts, and pruning.
- [Protected Changes](protected-changes.md): changing the email address and the password.
- [Impersonation](impersonation.md): signing in as another user to see what they see, with a time limit, restrictions, and an audit trail on both accounts.
- [Risk](risk.md): risk signals, and what to do about them.
- [Security Log & Emails](security-log-and-emails.md): the activity log, "was this you?" alerts, and security emails.
- [Events](events.md): every event Keyring dispatches, and what each one carries.

## Security

- [Security](security.md): what Keyring guarantees, where each choice comes from, and its known limitations.
- [OWASP ASVS and NIST SP 800-63B](owasp-asvs.md): where Keyring stands on every requirement of ASVS 5.0.0 that bears on it, what to turn on for each level, and what its assurance levels mean in NIST's terms.

## Building Your Application

- [Frontend](frontend.md): the Inertia pages, and the `@keyringjs/keyring` browser package.
- [Headless Frontends](headless.md): a frontend Laravel doesn't serve, such as a Nuxt app on another subdomain, signing in with Sanctum's session cookies.
- [Example Application](https://github.com/keyringphp/example): every page, written in React.
- [Extending Keyring](extending.md): every option and hook in one place, and what stays fixed.
- [Recipes](recipes.md): worked examples with real packages, such as IP locations, Maizzle emails, and SMS codes.
- [Testing](testing.md): test helpers, fakes, factories, and the conformance suite.
