# OWASP ASVS and NIST SP 800-63B

- [Introduction](#introduction)
- [What a Default Install Gives You](#what-a-default-install-gives-you)
- [Level 1](#level-1)
- [Level 2](#level-2)
- [Level 3](#level-3)
- [Requirement by Requirement](#requirement-by-requirement)
    - [V6 Authentication](#v6-authentication)
    - [V7 Session Management](#v7-session-management)
    - [The Other Chapters](#the-other-chapters)
- [NIST SP 800-63B-4](#nist-sp-800-63b-4)
    - [What Keyring's Levels Mean](#what-keyrings-levels-mean)
    - [Section by Section](#section-by-section)
- [The OWASP Cheat Sheets](#the-owasp-cheat-sheets)
- [What Is Left to Your App](#what-is-left-to-your-app)

## Introduction

This page explains where Keyring stands against three things: the [OWASP Application Security Verification Standard 5.0.0](https://github.com/OWASP/ASVS/tree/v5.0.0/5.0), [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html), and the OWASP cheat sheets on authentication. For ASVS, it gives a setup for each of the three levels. It then covers every requirement in V6 Authentication and V7 Session Management, followed by the requirements in the other chapters that bear on an authentication package. For NIST, it explains what Keyring's AAL1, AAL2, and AAL3 mean, and what your app has to supply for each.

Both standards verify an application or a service, not a package. So Keyring can meet a requirement, give you the means to meet it, do something else on purpose, or have nothing to do with it. The tables say which:

| | Means |
|---|---|
| **Met** | Keyring does it whatever you configure. |
| **Met by default** | Keyring does it as installed. The row says which option or edit would undo it. Unless the row says so, nothing refuses or warns about that change. |
| **Needs setup** | Keyring can do it once you turn something on. The row says what. |
| **Partly** | Keyring covers some of it. The row says what's missing and what to do about it. |
| **Deviates** | Keyring does something else, on purpose. The row says what, why, and how to meet the requirement to the letter where you can. |
| **Yours** | It's about your pages, your process, or your infrastructure. |
| **N/A** | Keyring has nothing the requirement applies to. |

"As installed" means running `php artisan keyring:install` with its default answers, and using the defaults in `config/keyring.php`. Each ASVS level includes the requirements of the levels below it.

## What a Default Install Gives You

Accepting every default with `php artisan keyring:install`, or running it with `--no-interaction`, sets up the following:

- the password as the only sign-in method, with [Keyring's password rules](protected-changes.md#password-rules),
- five features: `registration`, `reset-passwords`, `email-verification`, `update-passwords`, and `security-log`,
- [registration that doesn't reveal who has an account](sign-in-flow.md#without-revealing-who-has-an-account),
- eleven [security emails](security-log-and-emails.md#security-emails): new device, password changed, sign-in method added, sign-in method removed, second factor failed, recovery code used, new recovery codes, suspicious activity, account locked, email address changed, and email change undone,
- three [risk signals](risk.md): a session turning up in another browser, repeated failed second factors, and a sign in that follows several failures,
- rate limits, the timebox, the session registry, and on every session a two hour inactivity limit (14 days for a browser that ticked "remember me"), a 30 day limit overall and a limit of 100 sessions per account.

That covers the Level 1 requirements of V6 and V7, apart from what your own pages have to do, and apart from two things below. Passwords are normalised before they're hashed ([6.2.8](#v62-password-security)). An account you disable should be signed out everywhere by your own code ([7.4.2](#v74-session-termination)). The [other chapters](#the-other-chapters) have Level 1 requirements of their own, such as HTTPS, your cipher, and the tokens in emailed links.

It doesn't cover Level 2. Keyring starts with the password and leaves the rest for you to turn on. Nothing in a default install asks for a second factor, because there isn't one to set up. Choosing a second factor is the one thing you have to decide. If you pick a second sign-in method during installation, the installer's next question, "Require a second factor for everyone?", defaults to yes ([6.3.3](#v63-general-authentication-security)). The other sign-in methods are in the published provider, commented out, for an app that adds one later.

Eight of those emails have nothing to announce in a default install. New device needs `Features::devices()`. Sign-in method added, sign-in method removed, second factor failed, recovery code used, and new recovery codes need a sign-in method besides the password. Email address changed and email change undone need `Features::emailChanges()`.

An app that doesn't use the published `KeyringServiceProvider` gets the config defaults and the security emails, which are Keyring's own. It gets no risk signals until it registers some.

## Level 1

Start from the default install, then:

1. Keep a server-side session driver: `SESSION_DRIVER=database`, which is Laravel's default, or `redis` or `file`. The `cookie` driver has nothing on the server to destroy. Keyring ends an old copy through its registry instead, which doesn't reach a sign in that isn't finished ([7.2.4](#v72-fundamental-session-management-security)).
2. Keep the rate limiter's cache store (`cache.limiter`, or your default) somewhere that holds its keys between requests and that your deploys don't clear. A database or Redis store works, but not [Octane's `octane` store](security.md#octanes-cache-store). The per-minute limits, their locks, sent codes, answered WebAuthn challenges, and which request ended an impersonation live there. Failures in a row, and the cap, are in your database ([6.3.1](#v63-general-authentication-security)).
3. Build your forms so passwords are masked and can be pasted and filled by a password manager ([6.2.6, 6.2.7](#v62-password-security)).
4. Give users a form that posts to `PUT /user/password` ([6.2.2](#v62-password-security)).
5. When your app disables an account, call `app(Sessions::class)->signOutEverywhere($user)` at the same time you set the flag ([7.4.2](#v74-session-termination)).
6. Put a sign-out button on every signed-in page, though ASVS only asks for one from Level 2.

Don't turn on `registration.reveal_taken`, add composition rules to the password, or remove a [mandatory pipeline step](sign-in-flow.md#mandatory-steps).

## Level 2

Everything in Level 1, and:

1. **Require a second factor** ([6.3.3](#v63-general-authentication-security)). Install with an authenticator app, passkeys, or security keys, and answer yes to "Require a second factor for everyone?". If your app is already installed, uncomment the sign-in methods and the `keyring.enrolled` line in your provider, then turn on `Features::manageAuthenticators()` ([Requiring a Second Factor](policies.md#requiring-a-second-factor)). Your provider and config end up looking like this:

    ```php
    // app/Providers/KeyringServiceProvider.php
    Keyring::factors([
        Factors\Password::class,
        Factors\Totp::class,
        Factors\RecoveryCodes::class,
        Factors\WebAuthn::passkeys(),
    ]);

    Keyring::require(Requirement::aal2()->ifEnrolled()->noDowngrade());

    $this->app->make(Kernel::class)->appendMiddlewareToGroup('web', 'keyring.enrolled');
    ```

    ```php
    // config/keyring.php
    'features' => [
        Features::registration(),
        Features::resetPasswords(),
        Features::emailVerification(),
        Features::updatePasswords(),
        Features::manageAuthenticators(),
        Features::securityLog(),
    ],

    'enrollment_url' => '/settings/security',
    ```

2. **Decide what to do about "remember me".** `keyring.enrolled` checks what the account has, not what the session proved. A remembered browser comes back signed in with nothing proved. If every page needs two factors, put `keyring:aal2` on your routes or set `sessions.end_on_lapse`, and leave the checkbox off your login form ([An App Whose Every Page Needs AAL2](recipes.md#an-app-whose-every-page-needs-aal2)).

3. **Hash with argon2id**, so that a 64 character password in any script is accepted ([6.2.9](#v62-password-security)). Keyring doesn't change your hasher for you. The [conformance suite](testing.md#the-conformance-suite) fails on bcrypt until you switch, or until you say you're keeping it. Set the driver like this:

    ```ini
    HASH_DRIVER=argon2id
    ```

4. **Accept authenticator app codes for 30 seconds only** ([6.5.5](#v65-general-multi-factor-authentication-requirements)). In `Keyring::factors()`, use this in place of `Totp::class`:

    ```php
    fn ($app) => $app->make(Totp::class, ['window' => 0]),
    ```

5. **Check the inactivity timeout** ([7.3.1](#v73-session-timeout)). Keyring ships with two hours, and 14 days for a browser that ticked "remember me". Shorten either one to match what your risk analysis says:

    ```php
    'sessions' => [
        'idle' => '30m',
    ],
    ```

6. **Show users their sessions** ([7.5.2](#v75-defenses-against-session-abuse)). Build the page from `GET /user/sessions`, and send `sign_out_others` when a sign-in method is added or removed ([7.4.3](#v74-session-termination)). No feature is needed for this.
7. **Write down** the list of words a password must not be made up of, and put it in `passwords.context` ([6.1.2, 6.2.11](#v62-password-security)). Also write down your session timeouts and why you chose them ([7.1.1](#v71-session-management-documentation)), and how many sessions an account may have. That's 100 unless you change `sessions.max`, and the session that has gone unused longest ends first ([7.1.2](#v71-session-management-documentation)).
8. **Decide who may run `php artisan keyring:sign-out`** ([7.4.5](#v74-session-termination)). Also set up a process for someone who has lost their second factor and their recovery codes ([6.4.4](#v64-authentication-factor-lifecycle-and-recovery)).

Email codes count toward no assurance level. A password and an emailed code make an AAL1 session, in Keyring's levels as in NIST's, and that doesn't pass `keyring:aal2` or `keyring.enrolled`. Level 3 rules them out altogether. Leave `EmailCode::asExtraStep()` out unless you need it.

## Level 3

Everything in Level 2, and:

1. **Require a hardware key that proves what it is.** Register security keys with attestation, list the manufacturers' root certificates you accept, and require AAL3 at sign in and for enrollment. The configuration looks like this:

    ```php
    // app/Providers/KeyringServiceProvider.php
    Keyring::factors([
        Password::class,
        WebAuthn::securityKeys()->requireAttestation(),
    ]);

    Keyring::require(Requirement::aal3()->ifEnrolled());

    $this->app->make(Kernel::class)->appendMiddlewareToGroup('web', 'keyring.enrolled:aal3');
    ```

    ```php
    // config/keyring.php
    'webauthn' => [
        'attestation_roots' => [storage_path('attestation/yubico-root.pem')],
    ],
    ```

    With `ifEnrolled()`, a new user signs in with their password. Then `keyring.enrolled:aal3` keeps them on your enrollment page until they've added a key, and from then on they need the key every time. Drop `ifEnrolled()` if you hand out keys before an account first signs in. See [Requiring Attestation](passkeys.md#requiring-attestation). Without attestation, "hardware" only means what the key says about itself.

2. **No email codes, and no SMS** ([6.3.6](#v63-general-authentication-security), [6.6.1](#v66-out-of-band-authentication-mechanisms)). Don't register `EmailCode::asExtraStep()`, or an SMS factor of your own. Recovery codes can't meet `aal3` either, so a lost key goes to your support process.
3. **Tell users about suspicious sign ins** ([6.3.5](#v63-general-authentication-security)). Turn on `Features::devices()`, which brings the `new_device` notice and the `NewDevice` and `InactiveAccount` signals in a new install. In an existing install, uncomment them in your `KeyringServiceProvider`. Keep the security log on. Keyring's own risk response then emails the user about a sign in after a long quiet period, or after several failures. If you write a responder of your own, it has to do the same, as [Telling the User](risk.md#telling-the-user) shows. For a sign in from an unusual place, bind a [locator](devices-and-sessions.md#locations) and add `NewCountry` or `ImpossibleTravel`.
4. **Keep the default registration** ([6.3.8](#v63-general-authentication-security)): `registration.reveal_taken` stays `false`.
5. **Ask again before your most sensitive operations** ([7.5.3](#v75-defenses-against-session-abuse)). Put `keyring:aal3` or `keyring.fresh:5m` on those routes. AAL3 lapses after 15 minutes idle or 12 hours.
6. **Shorten the inactivity timeout** to match what your risk analysis says. NIST's figure for AAL3 is 15 minutes. Also set `sessions.end_on_lapse`, so that a session ends when AAL3 runs out, rather than carrying on at a lower level.
7. **Restrict who can write** to `keyring_authenticators` and to your attestation root files ([6.7.1](#v67-cryptographic-authentication-mechanism)).
8. **Put a bot check in front of your forms** if your risk analysis calls for one ([2.4.2](#the-other-chapters)). Keyring doesn't include one. See [Bot Checks](security.md#bot-checks).

## Requirement by Requirement

### V6 Authentication

#### V6.1 Authentication Documentation

| | Level | | What to Do |
|---|---|---|---|
| 6.1.1 Rate limiting and lockout are documented | 1 | Met | Keyring's are in [Rate Limiting](security.md#rate-limiting), with how they avoid locking the owner out. Your own security documentation can point there. Write down any limit you change. |
| 6.1.2 A documented list of context-specific words | 2 | Yours | Write the list: the names of your organisation, products, systems, projects, and teams. It goes in `passwords.context`, and [Context-Specific Words](protected-changes.md#context-specific-words) documents what Keyring adds to it. |
| 6.1.3 Every authentication pathway is documented | 2 | Met | Keyring's are in [The Sign In Flow](sign-in-flow.md), with ["remember me"](devices-and-sessions.md#remember-me) and sessions that your own `Auth::login()` starts in [Devices & Sessions](devices-and-sessions.md#the-session-middleware). [Single sign-on](sso.md) is in its own page. Add your own, such as a factor of yours, or anywhere you call `Auth::login()`. |

#### V6.2 Password Security

| | Level | | What to Do |
|---|---|---|---|
| 6.2.1 At least 8 characters | 1 | Met by default | 15 without a second factor, 8 with one. Keyring throws at boot if a configured minimum is under 8. The rules run in your published actions, which are yours to edit. Keep `PasswordRules::for()` in them. |
| 6.2.2 Users can change their password | 1 | Met by default | `Features::updatePasswords()` is on in a default install. Taking it out removes the route. Build the form that posts to [`PUT /user/password`](protected-changes.md#changing-the-password). |
| 6.2.3 A change needs the current and the new password | 1 | Met | Keyring checks `current_password` itself, whatever your action does. A user with no password, who signs in with a passkey alone, sets one with a fresh verification. |
| 6.2.4 Checked against at least the top 3,000 passwords | 1 | Met by default | The bundled list holds the 10,000 most common passwords of 8 characters or more, and the 3,000 most common of 15 or more. It runs in every environment. Keep `PasswordRules::for()` in your published actions. The list is cut for minimums up to 15. If you raise `min_without_mfa` past that, fewer than 3,000 of its entries are long enough to matter (1,775 of 16 or more). |
| 6.2.5 No composition rules | 1 | Met by default | Don't add `mixedCase()`, `numbers()`, or `symbols()` through the rules' `$adjust` callback. A longer minimum is fine. |
| 6.2.6 Password fields are masked | 1 | Yours | Use `type="password"` on your forms. A "show" toggle is allowed. |
| 6.2.7 Paste and password managers are permitted | 1 | Yours | Don't block paste, and set `autocomplete="current-password"` or `"new-password"`. Keyring's browser package touches neither. |
| 6.2.8 The password is verified exactly as received | 1 | Deviates | Nothing is cut short or has its case changed. Keyring does put a password in Unicode's NFC form before hashing or checking it, as NIST SP 800-63B-4 recommends (Sec. 3.1.1.2). That's a change the requirement's wording doesn't allow for. It's made so the same password matches from every keyboard, and it can't be turned off. |
| 6.2.9 Passwords of at least 64 characters are permitted | 2 | Deviates | With bcrypt, Laravel's default, Keyring refuses anything over 72 bytes rather than cutting it short. That turns away 64 characters of accented or non-Latin text. Keyring doesn't pre-hash to fit, because Laravel's own hasher couldn't check the result. Set `HASH_DRIVER=argon2id` to meet the requirement. Keyring doesn't change your hasher for you, and the conformance suite flags bcrypt. |
| 6.2.10 No periodic rotation | 2 | Met | Keyring has no password expiry. Don't add one. |
| 6.2.11 The context word list is enforced | 2 | Met by default | The check is on. It knows your app's name, the user's name, the name part of their email address, and their organisation's part of its domain. Your own list (6.1.2) is empty until you put words in `passwords.context`. Keyring refuses a password made up of nothing but listed words, with digits and punctuation taken out, and look-alike spellings such as `k3yr1ng` read as letters. A longer passphrase that has only one listed word in it passes, by design. |
| 6.2.12 Checked against breached passwords | 2 | Met by default | In production, through Have I Been Pwned. `passwords.uncompromised => false` turns it off, and `true` runs it everywhere. Laravel's check lets a password through when the service can't be reached. Set `passwords.refuse_unchecked` to refuse it instead. |

#### V6.3 General Authentication Security

| | Level | | What to Do |
|---|---|---|---|
| 6.3.1 Credential stuffing and brute force controls | 1 | Met by default | Limits apply per account, per typed username, per IP address, and in a row, all inside the timebox. Every number is an option, and none has a ceiling. Keep the `limits` options near their defaults. `consecutive => null` removes the cap. Keep the limiter's cache store somewhere that holds its keys and that your deploys don't clear. Removing the pipeline step fails the conformance suite. See [Rate Limiting](security.md#rate-limiting). The [`CredentialStuffing`](risk.md#built-in-signals) risk signal, off until you turn it on, also flags a sign in from an IP address where many other accounts have failed a factor, and Keyring's own response emails the user about it. |
| 6.3.2 No default accounts | 1 | Met | Keyring creates no users. Don't seed any in production. |
| 6.3.3 Multi-factor authentication is required; a hardware factor at Level 3 | 2 | Needs setup | A default install has no second factor to require. Level 2 needs a second factor registered and `keyring.enrolled`. The installer sets these up when you pick a second factor and answer yes to requiring it. Otherwise they're in the published provider, to uncomment. Level 3 needs `Requirement::aal3()`, `keyring.enrolled:aal3`, and `requireAttestation()`. See [Level 2](#level-2) and [Level 3](#level-3). Until a user enrolls, they are signed in, and held at your enrollment page. `keyring.enrolled` checks the account, not the session. See "remember me" in [Level 2](#level-2). |
| 6.3.4 No undocumented pathways, and consistent strength across them | 2 | Met | Every proof runs through one pipeline. Three things don't go through it. "Remember me" carries a session on at no level. Registration with `registration.reveal_taken` signs the new user in on their password without asking the policy. Your own `Auth::login()` is registered at no level. [Single sign-on](sso.md) goes through the pipeline. Start a sign in of your own with [`Keyring::attempt()`](sign-in-flow.md#starting-a-sign-in-yourself) instead. |
| 6.3.5 Users are notified of suspicious authentication attempts | 3 | Partly | As installed, Keyring emails `suspicious_activity` when a sign in follows several failures. With the `CredentialStuffing` signal turned on, it also sends it for a sign in from an address where many other accounts have failed. It also sends it when the risk signals add up to a level that notifies ([Telling the User](risk.md#telling-the-user)). It emails `account_locked` when the password or a passkey is refused until a reset, which happens at the cap on failures in a row, or sooner with `limits.lock_after`. An ordinary lockout that lifts by itself emails nobody. `second_factor_failed`, sent when the password was right (or a sign in with an identity provider worked) and the next factor wasn't, goes out once there's a sign-in method besides the password. Left to you: a new client (`new_device`) and a sign in after a long quiet period (`InactiveAccount`) need `Features::devices()`. A sign in from an unusual place needs a [locator](devices-and-sessions.md#locations) and a location signal. A responder of your own replaces Keyring's, so have it notify for these too. See [Level 3](#level-3). Each kind is capped at five an hour per account. |
| 6.3.6 Email isn't an authentication factor | 3 | Met by default | Don't register `EmailCode::asExtraStep()`. The factor throws without that explicit opt-in, and an emailed code never counts toward a level. |
| 6.3.7 Users are notified when authentication details change | 3 | Met by default | Keyring mails a changed or reset password, a sign-in method added or removed, new recovery codes, and a recovery code used. With `Features::emailChanges()` on, it also mails a changed email address and an undone email change. Renaming a sign-in method or changing the default one sends nothing. An account whose address isn't verified is sent none of these, except the notice of the reset that proves it. A password your own code sets with `Keyring::withoutProtection()` is logged, not announced. Dispatch `Keyring\Events\PasswordChanged` yourself if users should hear of it. Setting one of these to `null` in `Keyring::notifications()` stops it being sent, and nothing warns you. |
| 6.3.8 Valid users can't be deduced from sign in, registration or forgot password | 3 | Met by default | All three answer the same for every address, in the same time. Keep `registration.reveal_taken` off. With it on, registration says when an address is taken, and the conformance check is skipped, not failed. A username of your own that must be unique will still say when it's taken. Mail that bounces is outside the request. See [Registration](sign-in-flow.md#without-revealing-who-has-an-account). |

#### V6.4 Authentication Factor Lifecycle and Recovery

| | Level | | What to Do |
|---|---|---|---|
| 6.4.1 Initial passwords and activation codes are random and short-lived | 1 | Met | Keyring never generates a password. Its links and codes are random and expire. Don't email users a password of your own making. |
| 6.4.2 No password hints or secret questions | 1 | Met | Don't add any. |
| 6.4.3 Password reset doesn't bypass multi-factor authentication | 2 | Met | A reset signs nobody in, and leaves second factors and their limits alone. |
| 6.4.4 A lost factor is recovered with identity proofing | 2 | Yours | Recovery codes are Keyring's only way back in. For someone who has lost those too, your support process decides what they must prove before an administrator removes their authenticators. |
| 6.4.5 Renewal reminders for factors that expire | 3 | N/A | Nothing Keyring issues expires. |
| 6.4.6 Administrators can start a reset but not choose the password | 3 | Yours | In your admin tool, send a reset link with `Password::broker(config('keyring.passwords.broker'))->sendResetLink(['email' => $user->email])`. Don't set a user's password with `Keyring::withoutProtection()`. |

#### V6.5 General Multi-Factor Authentication Requirements

| | Level | | What to Do |
|---|---|---|---|
| 6.5.1 Codes work once | 2 | Met | On any session driver. A sent code's state is kept in the rate limiter's cache store, which has to hold its keys between requests. |
| 6.5.2 Lookup secrets under 112 bits are stored salted and hashed | 2 | Met | Recovery codes are stored as a keyed hash, which the requirement allows from 112 bits. Keyring's own codes carry 128 bits, and those imported from Fortify carry 119. Nothing shorter is stored or accepted. |
| 6.5.3 Secrets come from a secure random generator | 2 | Met | |
| 6.5.4 Codes have at least 20 bits of entropy | 2 | Met | Emailed codes are eight digits, and a code factor set to fewer than six is refused. |
| 6.5.5 Out-of-band codes last 10 minutes at most, authenticator app codes 30 seconds | 2 | Deviates | Sent codes last 10 minutes, and a longer life is refused. Authenticator app codes are accepted for up to about 90 seconds by default, which [doesn't meet the requirement](factors.md#authenticator-apps-totp). That's one time step either side of now, to allow for delay and clocks that have drifted (RFC 6238, Sections 5.2 and 6). A code still works only once. To meet the requirement, register `Totp` with `window` set to `0` ([Level 2](#level-2)). |
| 6.5.6 Any factor can be revoked | 3 | Met by default | `DELETE /user/authenticators/{id}` removes a sign-in method, with `Features::manageAuthenticators()`, which adding one needs anyway. Taking the feature out while users hold sign-in methods (after an import, say) leaves them no way to remove one. `Features::devices()` adds revoking a device. |
| 6.5.7 Biometrics only as a secondary factor | 3 | Met | A key's user verification only counts together with possession of the key, and AAL2 needs a factor the user has. |
| 6.5.8 Authenticator app codes use the server's time | 3 | Met | |

#### V6.6 Out-of-Band Authentication Mechanisms

| | Level | | What to Do |
|---|---|---|---|
| 6.6.1 Phone and SMS codes are restricted, and absent at Level 3 | 2 | N/A | Keyring ships no SMS factor. If you [build one](recipes.md#sms-codes), offer an authenticator app or passkeys beside it, tell users it's the weaker choice, and don't register it at Level 3. |
| 6.6.2 A code is bound to the request it was made for | 2 | Met | |
| 6.6.3 Codes are protected from brute force | 2 | Met by default | Five wrong guesses per sign in, on top of the usual limits. Like the limits in 6.3.1, these numbers are options with no ceiling, so keep them near their defaults. |
| 6.6.4 Push notifications are rate limited | 3 | N/A | Keyring has no push factor. |

#### V6.7 Cryptographic Authentication Mechanism

| | Level | | What to Do |
|---|---|---|---|
| 6.7.1 Keys used to verify assertions are protected from modification | 3 | Yours | No Keyring route takes a public key from a request to replace a stored one. A key is written when it's added, behind a fresh verification, and it's rewritten from the stored record each time the key signs in. Keyring keeps no integrity check of its own on the row. Restrict who can write to the `keyring_authenticators` table and to the files in `webauthn.attestation_roots`. |
| 6.7.2 Challenges are at least 64 bits and unique | 3 | Met | |

#### V6.8 Authentication with an Identity Provider

| | Level | | What to Do |
|---|---|---|---|
| 6.8.1 An identity can't be spoofed through another provider | 2 | Met | The `SingleSignOn` factor finds a user by the provider's issuer and subject together, never by email address, and a Microsoft user is kept under their own tenant's issuer. See [Single Sign-On](sso.md#security-notes). A factor of your own that signs in through a provider has to do the same. |
| 6.8.2 Signatures on assertions are validated | 2 | Met | `SingleSignOn` checks every ID token's signature against the provider's published keys, with an asymmetric algorithm only, and checks its issuer, audience, times and nonce, even though the token came straight from the provider. GitHub sends no assertion: who signed in is read from its API over HTTPS with the access token. |
| 6.8.3 SAML assertions are used once | 2 | N/A | Keyring doesn't process SAML. |
| 6.8.4 Authentication strength claimed by the provider is verified | 2 | Yours | `SingleSignOn` counts a sign in with a provider as one factor, whatever the provider did, and Keyring then asks for the user's own second factor. It keeps the provider's `acr` and `amr` on the verification as `providerAcr` and `providerAmr`, and on the `ProviderIdentityAccepted` event, but counts them toward nothing. For a provider that can be asked for a new sign in, it reads `auth_time`: a sign in counts toward `keyring.fresh` from when the user signed in at the provider, one without `auth_time` never counts as recent, and a [confirm with a provider](sso.md#step-up) asks for `max_age=0` (and `prompt=login` where it's taken) and needs an `auth_time` from after the user was sent there. For any other, such as GitHub, the default [`freshness`](sso.md#freshness) is `never`: neither a sign in nor a confirm counts as recent. Only a provider you opt into `round_trip` counts as recent when the user comes back. To rely on `acr` or `amr`, read them there, or check them in a [driver](sso.md#custom-drivers) of your own. |

### V7 Session Management

#### V7.1 Session Management Documentation

| | Level | | What to Do |
|---|---|---|---|
| 7.1.1 Timeouts are documented and justified | 2 | Met | Keyring's defaults, and where they come from, are in [Timeouts](devices-and-sessions.md#timeouts). They are two hours unused, 14 days for a remembered browser, 30 days overall, and each assurance level lapsing on NIST SP 800-63B-4's clock. That page also gives Keyring's reasons for letting "remember me" outlast the idle limit, and for lowering a session's level rather than ending it. Write down the values you chose and why. |
| 7.1.2 The number of concurrent sessions and what happens at the limit is documented | 2 | Met | An account can have 100 sessions at once (`sessions.max`). A sign in beyond that ends the session unused for longest, and is never refused. See [How Many Sessions](devices-and-sessions.md#how-many-sessions). Write down the number you chose. |
| 7.1.3 Federated session lifetimes are documented | 2 | Yours | Keyring's session carries on after an identity provider's session ends, and there's no single logout, as [Single Sign-On](sso.md#security-notes) says. Document how the two relate. |

#### V7.2 Fundamental Session Management Security

| | Level | | What to Do |
|---|---|---|---|
| 7.2.1 Session tokens are verified on the backend | 1 | Met by default | On every `web` request. Keep `sessions.middleware` on, and add `keyring.session` to any other route group that users are signed in on. |
| 7.2.2 Tokens are generated dynamically | 1 | Met | |
| 7.2.3 Tokens are random with at least 128 bits | 1 | Met | |
| 7.2.4 A new token on authentication, and the old one ended | 1 | Met by default | With a server-side session driver, the old session is destroyed. On Laravel's `cookie` driver, Keyring signs the old copy out through its registry after a sign in or a step-up, where the session middleware runs. It doesn't do this between the steps of a sign in that isn't finished. |

#### V7.3 Session Timeout

| | Level | | What to Do |
|---|---|---|---|
| 7.3.1 An inactivity timeout | 2 | Met by default | `sessions.idle`, two hours, counted on the server. A browser that ticked "remember me" has `sessions.remember_idle`, 14 days, and comes back with nothing proved. Setting either to `null` hands inactivity back to Laravel's `session.lifetime`, or removes it. Routes behind `keyring:aal2` or `keyring.fresh` ask again either way. |
| 7.3.2 An absolute maximum lifetime | 2 | Met by default | `sessions.absolute`, 30 days. Choose the length from your risk analysis. It can't be turned off, and any length is accepted. Keep `sessions.middleware` on. |

#### V7.4 Session Termination

| | Level | | What to Do |
|---|---|---|---|
| 7.4.1 A terminated session can't be used again | 1 | Met by default | Keep `sessions.middleware` on, and add `keyring.session` to signed-in route groups outside `web`. The conformance suite names signed-in routes that lack it. |
| 7.4.2 Sessions end when an account is disabled or deleted | 1 | Partly | Deleting a user revokes their sessions. Disabling one is your app's flag, read by [`Keyring::allowSignInWhen()`](sign-in-flow.md#who-may-sign-in). While the flag is set, no session works, and the first request one of the account's signed-in sessions makes ends every session the account has. A refused sign-in attempt ends nothing. A session only finds out when it makes a request, though, so if none does before the account is let back in, they all still work. Call `app(Sessions::class)->signOutEverywhere($user)` as you set your flag to end them there and then. |
| 7.4.3 The option to end other sessions after a factor changes | 2 | Met | A password change ends the other sessions unless you tell it not to. A reset ends them all, and an applied email change ends the others. Adding or removing a sign-in method, or making new recovery codes, ends them when the request sends `sign_out_others`. `DELETE /user/sessions` is always there. Offer the choice on your settings page. |
| 7.4.4 Sign out is easy to find on every signed-in page | 2 | Yours | Put a button that posts to `/logout` in your layout. |
| 7.4.5 Administrators can end a user's sessions, or everyone's | 2 | Met | `php artisan keyring:sign-out {user}` ends one user's sessions, and `--all` ends everyone's. From code, use `Sessions::signOutEverywhere($user)` and `SessionRegistry::revokeEveryone()`. Either also ends an [impersonation](impersonation.md) of the user, and ending the impersonator's own sessions ends theirs on its next request. See [For Administrators](devices-and-sessions.md#for-administrators). |

#### V7.5 Defenses Against Session Abuse

| | Level | | What to Do |
|---|---|---|---|
| 7.5.1 Re-authentication before changing sign-in details | 2 | Met by default | `changes_middleware` is `keyring.fresh:15m`. Don't empty it: the conformance suite checks it when a factor can be enrolled. A user who confirms with an identity provider re-authenticates there, with `max_age=0` (and `prompt=login` where it's taken) and a new `auth_time`: that's the default [`freshness`](sso.md#freshness) for OpenID Connect providers and Microsoft. Google and GitHub can't be relied on to re-authenticate, so by default their sign ins never count as fresh, and the confirm page only offers them toward a level, such as AAL2, never for `keyring.fresh`. A provider you opt into `round_trip` is a round trip that counts as fresh when the user comes back, as its sign ins do, which doesn't meet this requirement for its users. That's a [known limitation](security.md#known-limitations) ([Single Sign-On](sso.md#step-up)). For an attribute of your own that affects recovery, such as a phone number, put `keyring.fresh` on the route that changes it. Signing in counts as fresh, so adding a second factor or linking an identity provider to an account with none established also takes the [current password](authenticators.md#the-password-for-a-first-second-factor), and for 7 days after a sign-in method is added, established ones can't be removed, renamed or replaced, and established recovery codes can't be replaced. See [Frozen Sign-In Methods](authenticators.md#frozen-sign-in-methods). |
| 7.5.2 Users can see and end their sessions | 2 | Met by default | `GET /user/sessions` lists every session. `DELETE /user/sessions/{id}` and `DELETE /user/sessions` end one session, or all the others, behind a fresh verification, whatever features are on. Keep `changes_middleware`. Build the page. |
| 7.5.3 Further authentication before highly sensitive operations | 3 | Yours | Put `keyring.fresh:5m`, `keyring:aal2`, or `keyring:aal3` on those routes. See [Step-Up](step-up.md). |

#### V7.6 Federated Re-authentication

| | Level | | What to Do |
|---|---|---|---|
| 7.6.1 Session lifetime between your app and an identity provider behaves as documented | 2 | Yours | Keyring reads nothing from the provider after sign in, and its own timeouts apply to the session. If the provider's limits must be honoured, your app has to arrange that. |
| 7.6.2 A session is only created by the user's action | 2 | Yours | A sign in through Keyring is a POST that carries a proof. The three ways a session starts or carries on without one are described in 6.3.4: "remember me", registration with `registration.reveal_taken`, and your own `Auth::login()`. With [single sign-on](sso.md), a sign in only starts from the user following a provider's link, and the callback only finishes a request that the same browser's session started. |

### The Other Chapters

ASVS's other chapters are about your whole application. The rows below are the requirements in them that Keyring's own code and routes bear on. Where a row says Keyring meets one, that applies to Keyring's routes and what it stores. The rest of your app is yours.

| | | What It Means for Your App |
|---|---|---|
| 1.2.2 URLs are built with untrusted data encoded | Met | Server side, links are built from named routes. The browser package encodes every factor key and ID it puts in a path. A route you override with `configureRoutes()` is used as written, so [encode in yours](frontend.md#changing-routes). |
| 2.4.1 Anti-automation controls | Met by default | The [rate limits](security.md#rate-limiting), and the `keyring`, `keyring-pages`, and `keyring-login-options` limiters on the other forms. All of these are options, and you can redefine the limiters. Only a password minimum under 8, a sent code under six digits or over ten minutes, and a TOTP window over one step are refused. An RSA floor under 2048 bits is raised to 2048. |
| 2.4.2 Flows require realistic human timing (Level 3) | Yours | Keyring has no bot check and no minimum time on a form. Where a CAPTCHA or a challenge goes is in [Bot Checks](security.md#bot-checks). |
| 3.3.1, 3.3.3 `Secure` cookies with a `__Host-` or `__Secure-` prefix | Met by default | Keyring's two cookies, over HTTPS. A name you set yourself (`devices.cookie`, `sessions.remember_cookie`) is used as written, so the prefix is yours to add. Laravel's session cookie is yours to name and secure. See [Secure Cookies](security.md#secure-cookies). |
| 3.4.1 `Strict-Transport-Security` on every response | Yours | Keyring sends none, because it would only cover its own routes. See [HTTPS and HSTS](security.md#https-and-hsts). |
| 3.4.3 A `Content-Security-Policy` | Yours | Keyring renders through your layout, so what a policy must allow is yours to say. See [A Content Security Policy](security.md#a-content-security-policy). |
| 3.4.4, 3.4.5 `nosniff` and a referrer policy on every response | Met by default | On every Keyring response. Taking `AddSecurityHeaders` out of `keyring.middleware` removes them. Your other responses are yours. |
| 3.4.6 `frame-ancestors` so pages can't be framed | Yours | Keyring sends `X-Frame-Options: DENY` on its own responses, which keeps its pages out of frames. The requirement asks for `frame-ancestors` in a content security policy, on every response, and that policy belongs to your app. |
| 3.4.8 A `Cross-Origin-Opener-Policy` on every page (Level 3) | Met by default | `same-origin-allow-popups` on every Keyring response. A site that opens one of Keyring's pages keeps no handle on it, while a window the page opens itself, for a social login say, still answers to it. A response that already has the header keeps its own. Taking `AddSecurityHeaders` out of `keyring.middleware` removes it, and your other pages are yours. |
| 3.5.1 Cross-origin requests to sensitive functionality are checked | Met by default | Keyring's routes are in the `web` group, so Laravel's CSRF check covers them. Don't except Keyring's paths from it, and keep it if you replace `keyring.middleware`. |
| 4.1.3 Headers an intermediary sets can't be overridden by the user | Met by default | Keyring reads the client's address from Laravel's request, which follows your trusted proxies. `HeaderLocator` trusts request headers, so only use it behind a proxy that sets them and can't be bypassed. |
| 8.2.4 Adaptive controls from contextual attributes (Level 3) | Partly | The [risk signals](risk.md) that the published provider starts with look at failure history at sign in, and at the browser a running session is in. The ones that go by the device (`NewDevice`, `InactiveAccount`) need `Features::devices()`. The ones that go by place need a locator you supply. `CredentialStuffing`, off until you turn it on, goes by the failures on other accounts from the request's IP address. An app without the published provider has none until it picks some. |
| 10.1.1 Tokens only go to components that need them | Met | [Single sign-on](sso.md)'s tokens stay on the server. Keyring swaps the code for them, reads who signed in, and keeps none of them. |
| 10.1.2 The client only takes the code and ID token from a flow this session started, with secrets bound to it | Met | Each request's `state`, `nonce` and PKCE verifier are 32 random bytes, kept encrypted in that browser's session, for one provider, and used once. |
| 10.2.1 The code flow is protected against request forgery | Met | Every request carries PKCE (S256) and a `state`. |
| 10.2.2 Mix-up attacks are defended against | Met | A callback has to be finished at the provider it was started for, and one whose `iss` parameter (RFC 9207) names another issuer is refused before its code is sent anywhere. |
| 10.2.3 Only the required scopes are asked for (Level 3) | Met by default | `openid`, `email` and `profile`, or `read:user` and `user:email` for GitHub. A provider's `scopes` option replaces them. |
| 10.5.1 ID token replay is prevented | Met | The ID token's `nonce` has to be the request's. |
| 10.5.2 The user is identified by `sub` | Met | By the issuer and `sub` together, never the email address. |
| 10.5.3 A malicious server can't impersonate another through its metadata | Met | A discovery document has to name exactly the configured issuer, and is only cached once it does. An issuer elsewhere can't name plain HTTP endpoints, nor a token endpoint or key set on a private or local address other than its own host, unless its `private_endpoints` option says it may. |
| 10.5.4 The ID token's audience is this client | Met | `aud` has to include the `client_id`, and `azp`, which has to be there when there are several audiences, has to be it too. |
| 10.5.5 Back-channel logout is protected against forced logout | N/A | Keyring doesn't take back-channel logout. |
| 11.1.1 A key management policy | Yours | Keyring derives a key per purpose from `APP_KEY` and never uses it directly ([Keys](security.md#keys)). Who holds `APP_KEY`, how often it rotates, and how it's destroyed are your organisation's policy. |
| 11.2.2 Algorithms and keys can be replaced | Partly | The password hash, `APP_KEY`, the cipher, the WebAuthn algorithms, and the TOTP digest can all be changed. The keyed hash (HMAC-SHA-256) and the token hash (SHA-256) are fixed in code, and stored hashes carry no tag saying which scheme made them. See [Changing an Algorithm](security.md#changing-an-algorithm) for what a change would take. |
| 11.2.3 At least 128 bits of security | Met by default | Until you add RS256 to `webauthn.algorithms` (112 bits at 2048), turn on `requireAttestation()`, whose makers' certificates may be RSA-2048, or register `SingleSignOn` with a provider that signs with RSA-2048, as Google and Microsoft do. All three are opt-in. |
| 11.3.2 Approved ciphers and modes | Yours | Encryption is Laravel's, using your `app.cipher`. The default, AES-256-CBC with a MAC, is a legacy mode in ASVS's Appendix C. Set `app.cipher` to `aes-256-gcm` for an approved one. |
| 11.4.1 Approved hash functions | Deviates | TOTP codes are made with HMAC-SHA-1 by default. That's a legacy algorithm in Appendix C, but it's the only digest every authenticator app makes. Give the factor [another digest](factors.md#authenticator-apps-totp) if your users' apps support it. |
| 11.4.2 Passwords stored with an approved, costly function | Yours | Keyring calls Laravel's `Hash`, and rehashes at sign in when your settings change. The algorithm and its cost are yours to choose. Laravel's defaults meet Appendix C, and Keyring doesn't check what you set. |
| 11.6.1 Approved signature algorithms | Met by default | ES256 and EdDSA. RS256 and attestation chains signed with RSASSA-PKCS1-v1_5, which Appendix C doesn't approve, are both opt-in. So are identity providers' RS256 ID tokens, which [single sign-on](sso.md#security-notes) accepts because Google and Microsoft sign with nothing else. |
| 12.2.1 TLS for every connection (all of V12) | Yours | Your web server's. Keyring's outbound calls, the breached-password lookup and an identity provider's endpoints, are over HTTPS with certificate verification on. A provider may only be plain HTTP on `localhost`. |
| 13.3.1 Secrets kept out of source code | Yours | Keyring holds no secret of its own. Everything derives from your environment. |
| 14.2.1 Sensitive data in the body or headers, never the URL | Deviates | Every request that proves or changes something carries its password, code, token, or signature in the body. An emailed link is the exception. It has to carry its token in the URL of the page it opens, once. See [Tokens in Emailed Links](security.md#tokens-in-emailed-links). So does an identity provider's callback, which OAuth's code flow sends with a code and a state in its query. The code is no use without the PKCE verifier in the session. |
| 14.2.2 Sensitive data isn't cached | Met by default | `Cache-Control: no-store, private` on every Keyring response, from the same middleware as 3.4.4. |
| 14.2.3 Sensitive data isn't sent to untrusted parties | Met by default | The breached-password lookup sends five characters of a SHA-1 hash, never the password. `passwords.uncompromised => false` turns the call off. |
| 14.2.7 Sensitive data is deleted on a schedule | Met by default | Keyring schedules `keyring:prune` daily. It needs your scheduler running. `prune_at => null` leaves scheduling to you. |
| 15.1.2 An inventory of third-party libraries | Yours | Keyring declares its dependencies by version range and ships no lock file, as any library does. The resolved list is your `composer.lock`. |
| 15.3.2 Outbound calls don't follow redirects | Partly | The one call Keyring makes itself is the breached-password lookup with `passwords.refuse_unchecked`, and that call follows none. Without that option, the lookup is Laravel's verifier and not Keyring's, and it follows redirects as Laravel's HTTP client does. Bind an `UncompromisedVerifier` of your own if that matters to you. |
| 15.3.4 The client's IP address comes from trusted fields | Yours | Configure Laravel's [trusted proxies](security.md#trusted-proxies). Keyring uses the address Laravel gives it for limits and logs. |
| 16.2.2 Timestamps in UTC or with an offset | Partly | An entry written to your app's log carries its time with an offset. The `keyring_events` table keeps `created_at` in your `app.timezone`, which has no offset. Leave that at UTC, Laravel's default. See [Times](security-log-and-emails.md#times). |
| 16.3.3 Security events and attempts to bypass controls are logged | Deviates | Refused links, signatures, tokens, records, and pipeline steps are logged, and so is a refusal by a rate limit. Form validation failures aren't, on purpose, because a missing field is an ordinary mistake. Laravel's CSRF refusals are the framework's. |
| 16.4.2 Logs are protected and shipped elsewhere | Yours | Keyring writes to your database or your log channel. Who can read and change them, and where they're copied, is yours to decide. |
| 16.5.2 Works securely when an outside service fails | Deviates | When Have I Been Pwned can't be reached, a new password is let through, leaving only the bundled list of common passwords, so an outage doesn't stop registrations. `passwords.refuse_unchecked` refuses such passwords instead. |
| 16.5.3 Fails securely | Deviates | The breach check in 16.5.2 lets a password through on an error, which is this requirement's own example. The per-minute limits, their locks, and risk locks are in the cache, so clearing the cache lifts them. The cap on failures in a row, which is what ends guessing, is in the database. See [Rate Limiting](security.md#rate-limiting). |

The rest of those chapters either doesn't apply to an authentication package, or it's your app's and its deployment's responsibility. That covers file handling, the OAuth authorization server and resource server requirements, WebRTC, TLS configuration, your own forms' validation, and your own pages' output.

## NIST SP 800-63B-4

Keyring is built on Revision 4 of NIST SP 800-63B, and its assurance levels take their names from NIST. The document is written for a credential service provider, which is your app and your organisation together, so no library can follow all of it. This section explains what Keyring's levels do mean, and what's left for you.

### What Keyring's Levels Mean

A session's level comes from what it has proved, and when it proved it ([Assurance Levels](policies.md#assurance-levels)).

| Level | What the Session Proved | What Keyring Holds It To | What Your App Supplies |
|---|---|---|---|
| AAL1 | One authentication factor: a password, usually. | A password of 15 characters or more when it's the account's only factor (Sec. 3.1.1.2). A session that ends 30 days after sign in (Sec. 2.1.3), and after two hours unused, which NIST doesn't ask for at this level. | Nothing more. Keep `sessions.absolute` at 30 days or under, and `passwords.min_without_mfa` at 15. |
| AAL2 | Two factors of different kinds, one of them something the user has (Sec. 2.2.1): a password and an authenticator app's code, or a passkey that verified the user. An emailed code isn't a factor (Sec. 3.1.3.1), and neither is a biometric without the authenticator it unlocks (Sec. 3.2.3). | The level lapses after an hour unused, or 24 hours (Sec. 2.2.3). Getting it back takes every factor again, which is more than NIST asks. By default, the session then carries on as AAL1. | A second factor, registered and [required](policies.md#requiring-a-second-factor). A phishing-resistant option on offer (Sec. 2.2.2): register passkeys or security keys. `keyring:aal2` on what needs the level, or `sessions.end_on_lapse` if nothing may be reached below it, and no "remember me" checkbox (Sec. 5.1). |
| AAL3 | A phishing-resistant key that can't leave its device, and that was added with a verified attestation, with its own user verification or a password (Sec. 2.3.1 and 2.3.2). A passkey that syncs never reaches it. | The level lapses after 15 minutes unused, or 12 hours (Sec. 2.3.3). | [`requireAttestation()`](passkeys.md#requiring-attestation) and the root certificates you trust. Authenticators validated to FIPS 140, limited to those models with [`allowOnly()`](passkeys.md#allowing-only-certain-models), and server cryptography validated the same way. Keyring can't supply or check either of those. `sessions.end_on_lapse`. Keep `sessions.levels.aal3.absolute` at 12 hours or under. |

A session Keyring calls AAL3 has met NIST's rules for the authentication itself. Whether your service is AAL3 also depends on the validated hardware and cryptography above, and on the rest of the document.

### Section by Section

The table below covers where Keyring doesn't meet a section whatever you configure. Sections that aren't listed are met, or they cover things Keyring doesn't make, such as authenticator hardware, biometric sensors, identity proofing, and federation. If you write an SMS code factor, Sec. 3.1.3.3 and 3.2.9 become yours too.

| Section | | What It Means for Your App |
|---|---|---|
| 2.1.3 A definite overall timeout at AAL1, 30 days at most | Met by default | `sessions.absolute` is 30 days. A longer one is accepted. |
| 2.2.1 AAL2 takes a physical authenticator | Met | `Requirement::aal2()` needs a possession factor. A factor of your own that reports only inherence leaves a session at AAL1. `Requirement::factors(2)` accepts any two kinds, and isn't AAL2. |
| 2.2.2 A phishing-resistant option is offered at AAL2 | Yours | Passkeys and security keys ship with Keyring. A default install registers only the password, so offer one. |
| 2.2.3 AAL2 lapses after an hour idle or 24 hours | Met by default | `sessions.levels.aal2`. Longer limits are accepted. |
| 2.3.2 AAL3 authenticators and verifier cryptography are validated to FIPS 140 | Yours | Everything a library can check about the key is checked. The validation is yours to buy and to run on. |
| 2.3.3 AAL3 lapses after 12 hours at most | Met by default | `sessions.levels.aal3`. A longer `absolute` is accepted, and breaks the rule. |
| 2.4 Security controls, records retention, privacy and redress | Yours | [What Keyring Keeps](security.md#what-keyring-keeps) lists what's stored and for how long. Use it to write your own policy. |
| 3.1.1.1 No composition rules | Met by default | Don't add any to your published action. |
| 3.1.1.2 A password used alone is at least 15 characters | Met by default | `passwords.min_without_mfa`. Anything from 8 up is accepted, and under 15 breaks the rule. |
| 3.1.1.2 Passwords of at least 64 characters are permitted | Deviates | Bcrypt stops at 72 bytes, so 64 characters of multi-byte text may not fit. See ASVS [6.2.9](#v62-password-security). Use argon2id. |
| 3.1.1.2 A change is forced on evidence of compromise | Needs setup | Passwords never expire. Keyring holds a user until they choose a new password when your app calls `Keyring::requirePasswordChange()`. It also does so by itself when the `BreachedPassword` signal finds the password used at sign in in a breach. That signal makes a network call at every sign in, so it's [off until you turn it on](risk.md#requiring-a-new-password). |
| 3.1.1.2 New passwords are compared against a blocklist | Met by default | The common list and the context words can't be turned off. The breach check can be turned off (`passwords.uncompromised`). When the service is down, it lets a password through unless you set `passwords.refuse_unchecked`. |
| 3.1.1.2 Guidance on choosing a password, password managers and paste allowed | Yours | Keyring ships no pages, and its validation accepts any string. Its refusal messages say what to do instead. |
| 3.1.1.2 A keyed hash or encryption under a separately stored key (recommended) | Deviates | Not built in. The hash column is shared with the rest of your app, where the key lives is your infrastructure's decision, and rotating it locks everyone out. [Peppering Passwords](security.md#peppering-passwords) shows how to add one. |
| 3.2.2 No more than 100 failures in a row on one authenticator | Met by default | `limits.consecutive`. A higher number, or `null`, is accepted. A factor of your own that overrides `limits()` without the default list loses the cap. `Keyring::unlock()` switches a disabled authenticator back on without binding it again, which NIST doesn't provide for. See [At the Cap](security.md#at-the-cap). |
| 4.1.2.1 A new authenticator is bound at the highest level the account can reach | Met by default | `changes_middleware`. Emptying it fails the conformance suite and nothing else. Keyring always asks for the highest level the account can reach, where NIST would also accept the level the new authenticator will be used at. |
| 4.1.2.1 The subscriber is told when an authenticator is added | Met by default | `authenticator_added`, one of Keyring's own notices. It isn't sent if the app sets it to `null`. |
| 4.2.1.1 A used recovery code is replaced with a new one | Deviates | Keyring uses the code up and doesn't issue another by itself. A new code is only worth something once its owner has seen and saved it. `shouldReplaceRecoveryCodes()` says when a set has had one used. Send the user to [make a new set](authenticators.md#recovery-codes). Until your app does, this rule isn't met. |
| 4.2.1.1 A replacement recovery code is announced | Met by default | `recovery_codes_generated`. |
| 4.2.1.2 A code sent by email lasts 24 hours at most | Yours | Reset links come from Laravel's broker: `auth.passwords.*.expire`, which is 60 minutes in a new app. Keyring doesn't cap it. |
| 4.2.1.2 At least two verified recovery addresses | Yours | Keyring has one, the `email` attribute. A second address, verified before it's used, is your app's to build. See [Known Limitations](security.md#known-limitations). |
| 4.2.3 Account recovery is announced | Met by default | `password_changed` after a reset, and `recovery_code_used`. |
| 4.3 A compromised authenticator is suspended or invalidated promptly | Yours | Keyring refuses a sign in whose key counter went backwards, and logs `clone_suspected`. It removes nothing by itself. Act on `Keyring\Events\CloneSuspected`, and on a user's report, by removing the authenticator. |
| 4.6 At least two notification addresses, and every notice sent to all of them | Yours | Keyring mails your user model as Laravel does, at one address. Return more from `routeNotificationForMail()`. See [A Support Contact](security-log-and-emails.md#a-support-contact). |
| 4.6 A notice says who to contact | Needs setup | Set [`support_contact`](security-log-and-emails.md#a-support-contact), and Keyring's notices end with it. It's `null` until you do. |
| 5.1 A cookie isn't used instead of authentication | Deviates | "Remember me" brings a browser back signed in, with nothing proved, after its session idled out. Keyring binds it to the session it was ticked for, lets it work once, and gives the session it resumes no level. As a result, anything behind `keyring:aal1`, `keyring:aal2`, or `keyring.fresh` asks again. Routes behind `auth` alone are reachable on the cookie. Leave the checkbox off your login form, or set `sessions.end_on_lapse`, if you follow this section. |
| 5.1 Requests that change something carry a CSRF token | Met by default | Laravel's, on the `web` group. |
| 5.1.1 Session cookies are `Secure` and narrowly scoped | Met by default | Keyring's own, which hold only random identifiers. Laravel's session cookie is `Secure` once you set `SESSION_SECURE_COOKIE`. |
| 5.2 A session ends when its inactivity or overall timeout passes | Deviates | By default, a session past its level's limits carries on at the lower level. Sec. 5.1 allows that, and it keeps the session inside AAL1's own limits. `sessions.end_on_lapse` ends it instead. See [Ending a Session With Its Level](devices-and-sessions.md#ending-a-session-with-its-level). |

## The OWASP Cheat Sheets

Keyring follows these OWASP cheat sheets: Authentication, Session Management, Multifactor Authentication, Forgot Password, Password Storage, Credential Stuffing Prevention, Cross-Site Request Forgery Prevention, Logging, and Passkey Security. [Standards](security.md#standards) says which choice comes from which one. The table lists the recommendations that depend on your setup, or that Keyring doesn't follow:

| Cheat Sheet | Recommendation | | What It Means for Your App |
|---|---|---|---|
| Authentication | Verify an email address used as a username | Met by default | New users sign in once they've verified theirs. `registration.reveal_taken` signs them in first. |
| Authentication | Password length, characters and no composition rules | Met by default | As ASVS 6.2.1 to 6.2.9. Use argon2id for 64 characters of any script. |
| Authentication | A password strength meter | Yours | Your registration page's. |
| Authentication | Don't get in the way of password managers | Yours | Your forms'. |
| Authentication | Re-authenticate for sensitive features | Met by default | `changes_middleware`. |
| Authentication | Re-authenticate after a risk event | Met by default | The risk signals in the published provider. |
| Authentication | Registration doesn't say an ID is in use | Met by default | Until you set `registration.reveal_taken`. |
| Authentication | Throttle logins per account, with growing lockouts | Met by default | The numbers are options. |
| Authentication | A CAPTCHA after failed attempts | Yours | See [Bot Checks](security.md#bot-checks). |
| Session Management | Session ID names that aren't descriptive | Met by default | Keyring's cookies are `known_device` and `remembered_session`. Laravel's session cookie is yours to name. |
| Session Management | Store only a hash of a session token | Deviates | The registry keeps its IDs as they are. See [Storage](security.md#storage) for why one alone signs nobody in. That holds while Laravel encrypts cookies, as the `web` group does. Don't list Keyring's cookies under `encryptCookies(except:)`. |
| Session Management | Idle and absolute timeouts on the server | Met by default | `sessions.idle => null` removes Keyring's idle limit. |
| Session Management | `no-store` on sensitive responses, `Clear-Site-Data` at sign out | Met by default | On Keyring's routes, through `keyring.middleware`. |
| Session Management | Bind the session to client properties and notice changes | Met by default | The `SessionFingerprintChanged` signal in the published provider. |
| Multifactor Authentication | Offer TOTP, and require MFA where you can | Needs setup | A default install has the password alone. Pick a second sign-in method. See [Level 2](#level-2). |
| Multifactor Authentication | Tell the user when a second factor fails after the right password | Met by default | The "was this you?" alert, and the `second_factor_failed` email once there's a second sign-in method. A default install has no second factor to fail. |
| Multifactor Authentication | Re-authenticate and notify when a factor changes | Met by default | `changes_middleware`, and the `authenticator_added` and `authenticator_removed` emails. Emptying the first, or setting the emails to `null`, undoes it. |
| Multifactor Authentication | No fallback from a phishing-resistant factor to a weaker one | Met by default | `noDowngrade()`, in the policy the installer writes. A policy of your own has to say it. Recovery codes stay on offer. A key counts once it's [established](authenticators.md#established-authenticators), 7 days after it's added. |
| Password Storage | Argon2id, or bcrypt for legacy systems | Yours | Your `hashing.driver`. Laravel's default is bcrypt. |
| Password Storage | A pepper kept apart from the database | Deviates | Not built in. See [Peppering Passwords](security.md#peppering-passwords). |
| Forgot Password | Rate limit reset requests per account | Yours | Laravel's broker `throttle`, which is on in a new Laravel app and which Keyring doesn't set. Keep it. The conformance suite fails without one. See [Resetting the Password](protected-changes.md#resetting-the-password). |
| Forgot Password | After a reset: no automatic sign in, sessions ended, the user emailed | Met by default | The email is `password_changed`, one of Keyring's own notices. |
| Credential Stuffing Prevention | Per-IP limits that aren't the only defence | Met by default | The numbers are options. |
| Credential Stuffing Prevention | Metrics from each defence | Partly | Keyring dispatches an event and writes a log entry for each. Counting them is a listener of yours. See [Events](events.md). |
| Credential Stuffing Prevention | Find leaked passwords | Met by default | `passwords.uncompromised`. |
| Credential Stuffing Prevention | Tell users of unusual events, show recent sign ins and sessions | Met by default | The signals in the published provider, Keyring's own notices, and `GET /user/sessions`. The pages are yours. |
| Cross-Site Request Forgery Prevention | The framework's protection on every request that changes state | Met by default | Laravel's, on the `web` group. |
| Cross-Site Request Forgery Prevention | Client code doesn't build request targets from untrusted input | Met | The browser package encodes what it puts in a path. |
| Logging | Log sign ins, failures, refusals and input validation failures | Deviates | Everything except validation failures, as ASVS 16.3.3 above. |
| Logging | Logging can't be used to exhaust resources | Met by default | `security_log.refusals => null` removes the cap. |
| Passkey Security | Attestation off by default; when on, check the chain and its status | Deviates | Off by default. With `requireAttestation()`, the chain is checked against your roots, and no revocation list is fetched. To withdraw trust, remove the root. |
| Passkey Security | Generic errors, even timing, no silent fallback | Met by default | `noDowngrade()`, as above. |
| Passkey Security | A managed list of credentials, with when each was created and last used | Met | A factor's `present()` method gives `createdAt` and `lastUsedAt`. The page is yours. |

## What Is Left to Your App

Whatever you aim for, these are outside what a package can do:

- **TLS everywhere**, with `SESSION_SECURE_COOKIE=true` and trusted proxies configured, so that rate limits see real addresses.
- **Your pages.** Keyring ships none. Masked password fields, paste and password managers left alone, a visible sign-out button, and warnings about the risks of a weaker factor all belong in your templates.
- **Headers on your own pages.** Keyring's responses send `Cache-Control: no-store, private`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin` (`no-referrer` on the pages emailed links open), `X-Frame-Options: DENY`, and `Cross-Origin-Opener-Policy: same-origin-allow-popups`. A content security policy and the rest are yours, for every page.
- **Your mail provider.** Verification links, reset links, and security notices are only as private and as prompt as the mail that carries them. Its bounce and delivery reports sit outside the request, where Keyring can't make two answers look alike.
- **Your session and cache stores.** A server-side session driver, and a rate limiter store that doesn't lose its keys. The per-minute limits, their locks, sent codes, answered WebAuthn challenges, and which request ended an impersonation are kept there. Failures in a row are in your database.
- **Your documentation.** ASVS asks for your password word list, your session timeouts, and your sign-in pathways in writing.
- **Your administrators.** Who may run `keyring:sign-out`, send reset links, remove a lost authenticator, or [impersonate](impersonation.md) a user (`Keyring::allowImpersonationWhen()`), and what a user must prove first.
- **A second address.** NIST asks for two notification addresses and two recovery addresses. Keyring has the one on your user model.
- **Bot checks.** A CAPTCHA or a challenge in front of your forms, if you want one.
- **Identity providers.** Registering your app with them and keeping its secrets, and anything about the provider's own session. Keyring's [single sign-on](sso.md) takes the sign in from there.
