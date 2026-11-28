# Security

- [Introduction](#introduction)
- [Guarantees](#guarantees)
    - [Signing In](#signing-in)
    - [Rate Limiting](#rate-limiting)
    - [Single-Use Codes](#single-use-codes)
    - [Second Factors and Step-Up](#second-factors-and-step-up)
    - [Sessions and Devices](#sessions-and-devices)
    - [Account Changes](#account-changes)
    - [Links and Headers](#links-and-headers)
    - [Request Input](#request-input)
    - [Storage](#storage)
    - [Logging](#logging)
- [What Keyring Keeps](#what-keyring-keeps)
- [What Your App Must Provide](#what-your-app-must-provide)
    - [HTTPS and HSTS](#https-and-hsts)
    - [Trusted Proxies](#trusted-proxies)
    - [Secure Cookies](#secure-cookies)
    - [A Content Security Policy](#a-content-security-policy)
    - [Headers on Your Other Responses](#headers-on-your-other-responses)
    - [Bot Checks](#bot-checks)
- [Cryptography](#cryptography)
    - [Keys](#keys)
    - [Algorithms](#algorithms)
    - [Random Values](#random-values)
    - [Changing an Algorithm](#changing-an-algorithm)
    - [Peppering Passwords](#peppering-passwords)
- [What a Request Costs](#what-a-request-costs)
- [Standards](#standards)
- [Known Limitations](#known-limitations)
    - [Where Keyring Departs From a Standard](#where-keyring-departs-from-a-standard)
    - [Other Limits](#other-limits)

## Introduction

Keyring is built on OWASP ASVS 5.0.0, OWASP's cheat sheets on authentication, and NIST SP 800-63B-4. Its assurance levels follow NIST SP 800-63B-4 as far as a library can check. This page lists what Keyring promises, so you can check your setup against it. It also shows where Keyring stops. The [Standards](#standards) section says where each choice comes from, and [Known Limitations](#known-limitations) covers the places where Keyring does something other than a standard says.

The [conformance suite](testing.md#the-conformance-suite) tests several of these guarantees against your own configuration. The [OWASP ASVS and NIST SP 800-63B](owasp-asvs.md) page goes through ASVS 5.0.0 requirement by requirement. It says what to turn on for each of its levels, and what your app has to supply for each of NIST's requirements.

Guarantees about a [feature](quick-start.md#adding-features), such as devices or email changes, apply once you turn that feature on.

## Guarantees

### Signing In

- A wrong password and an unknown account get the same error, on the same field, with the same status code.
- A sign in succeeds only for a user whom Keyring's guard can load back through its provider. A passkey that belongs to another model, such as a staff member when the guard signs in users, fails like an unknown one, even when the IDs match.
- Every refused verification takes at least `timebox` (500ms by default). Unknown accounts still run a password hash, so timing doesn't reveal which accounts exist. A hash for a name with no account is made at today's cost, while an account's hash is checked at the cost its stored hash was made with. The wait covers that difference, but only while `timebox` is [longer than a hash takes](configuration.md#pending-logins-timebox-and-rate-limits). A refused password reset is held for the same time. The timebox wraps the whole pipeline, including the rate limits, the proof, the risk checks and whatever listens for a failure, so a `429` waits it out too. That includes a correct password turned down by a risk lock or a risk response, which answers like a wrong one.
- A password longer than its stored hash can check (72 bytes for bcrypt) fails like a wrong one. It gets the same error, timing and throttling wherever Keyring checks a password. That covers signing in, step-up, removing the last second factor, and the current password on a change. The over-long value never reaches the hasher.
- Keyring puts passwords into Unicode's NFC form before it measures, hashes or checks them. A password set on a device that composes characters one way still works on a device that composes them another.
- A pending login is stored as encrypted JSON in the session, never with `serialize()`, and it expires after `pending_logins.keep_for`. It also ends as soon as the user's password or email address changes. It ends too when a sign-in method they've already proved is removed from the account, whether by its owner or by an undone email change. And it ends when `keyring.guard` is no longer the guard they started under. An emailed code could have gone to an address the account no longer has, so an email change and its undo both end a sign in that was waiting for one.
- Keyring regenerates the session ID, and destroys the old one, when a user proves a factor by signing in or stepping up. It does the same when a user changes their password or signs out everywhere else. As a result, a copied session cookie stops working, and someone who planted a session ID before the password step doesn't share the pending login. On Laravel's `cookie` session driver, nothing on the server can be destroyed, so the old copy is signed out through its registry record instead.
- A password reset never signs anyone in, so your policy still applies at the next sign in.
- Registration doesn't reveal whether an address has an account, unless you set `registration.reveal_taken`. A free address, a taken one, one reserved for its previous owner and one whose account you keep out all get the same response, status, cookies and session. They also get the same validation, take at least `timebox`, and cost one password hash each. Every email is sent after the response. Nobody is signed in by registering. Keyring decides whether an address is taken, not your action, so the guarantee holds however your action is written, as long as the action doesn't check for itself. A password the hasher can't take is refused for every address, whatever your action's rules say. Anything else that `create()` throws is reported and answered like the rest. See [Registration](sign-in-flow.md#without-revealing-who-has-an-account).
- With that registration, an account can't sign in until its address is verified. Until then, a correct password gets the same answer as a wrong one. Verifying takes the emailed link and the password together. That way, neither someone who registered an address they can't read mail for, nor the address's owner who never chose that password, ends up with a verified account. A followed link is kept under a new session ID, so it only lets in the browser that followed it, even if someone else also held that session ID. A finished password reset also verifies the address.
- Checking a password can rehash it under the app's current settings. The new hash is only saved over the one that was checked, under a row lock, so a sign in that overlaps a reset can't write the old password back. Any device trust that overlapping sign in was given is withdrawn when its session is ended.
- A sign in with an [identity provider](sso.md) finds the user by the provider's issuer and subject, never by an email address. Nobody is signed up or linked by their address, and an account nobody linked gets the same error as a wrong password. The callback only finishes a request this browser started, once, with PKCE and, for OpenID Connect, a nonce, and every ID token's signature, issuer, audience and times are checked. See [Security Notes](sso.md#security-notes).
- A login attempt can't sign the owner out. Risk responses at login never revoke sessions, change the "remember me" token or stop trusting devices. That holds even for a custom responder.

### Rate Limiting

Every factor has its own limits. Keyring checks them in the pipeline before it looks at the proof:

- **Per account**: `limits.per_account` attempts a minute (5). The account is the user. Keyring finds out whose account a typed username belongs to before it counts, so every way of typing it shares one limit. Guesses at login and when confirming count together. Two accounts never share a count, however alike their usernames look. Browsers the account has signed in from before carry one of its device cookies, and they count in a bucket of their own. That way, someone guessing from elsewhere can't lock the owner out. The idea comes from the OWASP Community page on device cookies. All of those browsers share that one bucket. A device cookie is made at every sign in from a new browser, so someone who could once sign in may hold any number of them. With a bucket each, they would get the account's full allowance of guesses once per cookie. A browser stops counting as known when a password reset or change, or a sign-out everywhere, takes the account back. It stays that way until it signs in again.
- **Per typed username**: a sign in that names its account is also counted under the name as typed, with the same numbers. This happens whether or not anyone has that name. Only this count says so when it refuses, with a `429`. The account's own limit refuses quietly: the attempt gets the same answer as a wrong password, in the same time, and the password isn't looked at. A name is therefore answered from its own history. Locking an account under one name doesn't reveal which other names belong to it, or which names have an account at all. Nothing that happens to the account changes what its name answers, either. After a password reset, a new password or `Keyring::unlock()`, a refused name keeps being refused to anyone without the password, in the same way a name with no account would be. The owner still gets in. Behind a refused name, the account's own limits decide whether the password is looked at. The right password signs in, and a wrong one is answered as the name was. Only a factor that finds its user by the username counts under it. A passkey goes by its credential, so a username sent along with one counts against nobody.
- **Per IP address**: `limits.per_ip` attempts a minute (20), shared by every account on that address. A browser carrying the account's device cookie counts per IP address for that account alone. This means others on a shared address can't hold it up. An attacker who holds several of the account's device cookies still gets one count. Behind a load balancer, configure Laravel's [trusted proxies](#trusted-proxies). Otherwise, every user shares the balancer's address.
- **In a row**: `limits.consecutive` failures (100, the most NIST SP 800-63B-4 allows, Sec. 3.2.2) on one of an account's authenticators, however slowly they come. Each authenticator app, security key and set of recovery codes has a count of its own, and so does the password. The counts live in the database, so clearing the cache doesn't start them over. At the cap, the authenticator is refused for the account until that's dealt with, and nothing brings it back by itself. See [At the Cap](#at-the-cap). Setting `null` turns the cap off. Without a cap, guessing at a rate that stays under the per-minute limit would never stop. With `Features::devices()` on, browsers the account hasn't signed in from may make only `limits.consecutive_elsewhere` (80) of those failures. The rest are kept for the owner's own browsers. That way, someone guessing from elsewhere can't use up the whole cap, and the two never add up to more than the cap.

How they count:

- Keyring counts each attempt before it verifies it. Overlapping requests therefore can't all slip under the limit while they're being checked.
- Routes that spend session state take Laravel's session lock (`->block()`). Those routes are sign in, the challenge pages and verifications, enrollment, and renaming and removing an authenticator, which can spend a [frozen change's](authenticators.md#making-a-change-with-an-established-key) challenge. The lock stops parallel requests in one session from reusing a WebAuthn challenge, or from running two verifications of one pending sign in at once. Your cache store must support locks, as the database, Redis, file and array stores do. A sent code doesn't depend on that lock. It's [used up in the cache](#single-use-codes) instead.
- When failures reach an account's limit, that key is locked. Each lock lasts twice as long as the one before it: one minute, then two, then four, and so on. The longest lock is a day (`limits.longest_lock`). The count of lockouts resets a day after the first one.
- The per-IP limit locks in the same way, but a lock never lasts longer than 15 minutes (`limits.longest_ip_lock`). If one person fails behind a shared address, such as carrier-grade NAT or an office network, the others wait a quarter of an hour at most. Someone spraying passwords from one address still slows to about `limits.per_ip` guesses every 15 minutes. A browser carrying the account's device cookie isn't held up, and an attempt the address refuses doesn't count against the account. With `Features::devices()` off, everyone on the address waits.
- A success clears the account's per-minute count. It also clears the failures in a row that its own kind of browser had made. So when the owner signs in from a browser they've used before, whoever is guessing elsewhere doesn't get their guesses back. On the per-IP count, a success only takes back its own attempt. People signing in from one office address don't use up its limit. An attacker also can't reset either limit by signing in to an account of their own between guesses, even one whose username differs from the victim's by an accent.
- A completed password reset clears the account's failures in a row, its per-minute counts, its locks and its lockout count. This applies to the factors that can start a sign in. It also clears those for each of the account's known devices, so the owner can sign in straight away. A name someone typed is counted apart and isn't cleared, so it stays refused to anyone without the password. The owner still gets in with the right password, as the per typed username bullet above describes. A new password chosen by a signed-in user does the same, since guesses at the old password say nothing about the new one. Second factors keep their counts and locks. A reset only proves control of the mailbox, and a reset could otherwise be repeated to keep guessing a code. The `password_reset` log entry records the reset. Per-IP limits stay in place, so a reset can't be used to get around them.
- Requests that don't name an account, such as usernameless passkey sign ins, only get the per-IP limit. That way, junk requests can't fill a bucket that every user shares.
- A factor checked inside another request counts the same way: the password typed to add a first second factor or to remove the last one, and a key or code that [proves a change while sign-in methods are frozen](authenticators.md#making-a-change-with-an-established-key). A wrong one is a failure in a row, and dispatches `FactorFailed`. One the limits refuse gets the same answer and `Lockout` event as a sign in would, and one that reaches the cap on the password dispatches `AccountLocked`. The count is kept before any change is made, so a refused change doesn't take it back.

Keyring keeps the per-minute counts, their locks and each typed name's own failures in the cache store that Laravel's rate limiter uses. That's `cache.limiter`, or your default store. It keeps [sent codes and answered WebAuthn challenges](#single-use-codes) there too, and which request ended an [impersonation](impersonation.md#going-back), and it keeps [risk locks](risk.md#actions) in `risk.store`. A count that has gone reads as no attempts. So if the store loses its keys, those limits start over and those locks lift. `php artisan cache:clear` and `optimize:clear` empty the default store, and a store that evicts under memory pressure can drop keys one at a time. The locks are short, a day at the longest. What a cleared cache can't reach is what ends the guessing: the failures in a row and the locks that are held are in the `keyring_failure_counts` table. Where the per-minute limits and risk locks must hold too, point `cache.limiter` and `risk.store` at a persistent store of their own. It should not evict, and your deploys shouldn't clear it. A database or Redis store is the right choice. Octane's in-memory store isn't. See [Octane's Cache Store](#octanes-cache-store).

#### At the Cap

An authenticator that has failed `limits.consecutive` times in a row is disabled for that account, as NIST SP 800-63B-4 asks (Sec. 3.2.2). It stays disabled until it's set up again. What that takes depends on the factor:

- **One that can start a sign in** (the password or a passkey). It's cleared by a completed password reset, by a new password chosen while signed in, or by `Keyring::unlock($user)`. The sign-in form tells the user to reset the password (`keyring::keyring.locked`). Keyring dispatches `AccountLocked` and logs `account_locked`. The [`account_locked` notice](security-log-and-emails.md#email-types), which Keyring sends by default, emails the owner. The owner may not have been the one guessing.
- **A second factor**. The user signs in another way, with another factor or a recovery code. Then they remove the factor and add it again. The challenge page says so (`keyring::keyring.factor_locked`, with a `429`). Each refused attempt dispatches `Lockout` with a `retryAfter` of `null`. A password reset doesn't bring the factor back, since a reset only proves the mailbox.

From a support tool of your own, you may call `Keyring::unlock($user, 'totp')`. It clears one factor's failures and locks, whichever kind of factor it is:

```php
use Keyring\Facades\Keyring;

Keyring::unlock($user);            // the password and passkeys, and the risk lock
Keyring::unlock($user, 'totp');    // every authenticator app the user has
```

NIST's rule is that a disabled authenticator is bound again, not switched back on. That means `unlock()` goes further than the standard does. Use it only once you've checked who you're unlocking it for. For a second factor, nothing else stands between whoever has the password and another round of guesses.

Before the cap, a success clears the count, and only for its own kind of browser. A password reset, a new password and `Keyring::unlock()` clear it for the factors that can start a sign in. Nothing else does. The rows are never pruned, because a row is what keeps an authenticator refused. They go with the authenticator or the user.

> [!WARNING]
> **What this costs.** Someone who knows a username can guess at its password from elsewhere until their share is used up. That's 80 wrong passwords, which takes about 20 minutes at four a minute, slow enough never to meet a lock. Someone who runs into every lock needs a day and a half instead. From then on, the password is refused from every browser the account hasn't signed in from, until its owner resets it. The owner's own browsers keep working, because the last 20 failures can only be made from them, and those failures are theirs alone to use up. This is the price of a disabled authenticator not coming back by itself. With `Features::devices()` off, no browser is known, so the whole 100 belongs to anyone. That's 25 minutes, and then the password is refused everywhere until it's reset.

A typed username that nobody has can't be counted in the database, because there's no account to count it against. So each name's own failures in a row are also counted in the cache, whoever has the name, for `limits.remember_names_for` (30 days). That count is the only one the sign-in form answers from. A name with an account, a second name for an account at the cap, and a name with no account each get a `429` after the same number of their own failures. The account's count refuses quietly, like a wrong password. A guess costs the database the same statements either way. If the cache loses a name's count, the name goes back to "wrong password", while the account's password stays refused.

#### Locking Until a Reset

By default, every lock lifts by itself. The longest one lasts a day, and it takes the cap to stop the guessing. To stop someone who guesses fast sooner, set `limits.lock_after`:

```php
'limits' => [
    'lock_after' => 5,
],
```

Once an account has been locked that many times within a day, on a factor that can start a sign in, it's refused in the same way it would be at the cap. This holds however few failures that took. Locks double. With the default one-minute window, the fifth lock comes after about a quarter of an hour of steady guessing, and at most eleven fit in a day, so a `lock_after` above 11 never holds anything. The sign-in form tells the user to reset the password (`keyring::keyring.locked`) rather than counting down. Keyring dispatches `AccountLocked` and logs `account_locked`. The [`account_locked` notice](security-log-and-emails.md#email-types) emails the owner that the account is locked, and that resetting the password unlocks it. It's sent unless the app sets `account_locked` to `null`.

The lock ends with a completed password reset, a new password chosen while signed in, or `Keyring::unlock($user)`. It's kept in the database beside the failures in a row, so neither the passing of time nor a cleared cache lifts it.

This lock follows the same rules as the other limits. Browsers the account has signed in from before are locked and held apart from everyone else, so the owner isn't locked out of a browser they already use. A name nobody has locks in the same way. It gets the same answer, from the cache, for `limits.remember_names_for`. After that, a held name is answered like a wrong password, while the account stays locked. Second factors are never held, because a password reset wouldn't clear them, so they keep the cap. That includes security keys, which only ever come second. A name is only told that it's held for lockouts made under that name. A hold reached under another name of the same account lands on the account's own limit. So does one placed by wrong passwords on a confirm page in a signed-in session. The sign-in form refuses that quietly. There, the right password is answered as wrong, with no hint that a reset would help. So tell the user through the `account_locked` notice, or from `AccountLocked` yourself.

It's off by default. The cap ends the guessing either way. This setting only brings a fast guesser to that point sooner: in a quarter of an hour instead of a day and a half.

You can set your own limits for a factor by overriding its `limits()` method. A factor that leaves out what the default `limits()` returns also leaves out the cap on failures in a row. So add to that list rather than replacing it. A reset only clears the keys that the default `limits()` builds. A factor with its own per-account keys should clear them in a `PasswordReset` listener. Other routes use Laravel's throttle middleware with the named `keyring` limiter. These routes are registration, password reset requests, resets, password changes, email change requests, enrollment confirmations, removing an authenticator, verification emails, and the buttons on the pages that emailed links open. Those buttons confirm or undo an email change, report "this wasn't me", or verify an address. All of them share 6 requests a minute per user, or per IP address for guests. Opening one of those pages has its own limiter, `keyring-pages`, at 60 a minute per IP address. That way, a mail scanner that follows the link doesn't use up the six. Usernameless passkey options have a third limiter, `keyring-login-options`, at 60 requests a minute per IP address. The login page fetches them on every load for autofill. A request that any of them refuses is logged as `rate_limited`, once for each wait. You may redefine each limiter. See [Rate Limits](configuration.md#pending-logins-timebox-and-rate-limits). Each account can be sent three codes per factor every 10 minutes (`limits.codes` and `limits.codes_per`), however many sign ins, step-ups or enrollments ask for them.

Mail that isn't a guess at anything has a count of its own. A sign in that succeeds is never counted, and the form limiter only counts the sender. An account is sent each kind of [security notice](security-log-and-emails.md#security-emails) five times an hour at most (`limits.notices` and `limits.notices_per`). Every event still goes into the security log. An account can ask to change its email address that often. A typed address is mailed about a change that often too, whichever accounts ask. Registration also mails an address that often. That covers the verification link, another one for an account that never verified, and the notice that someone tried to register with it. This holds however many times the form is sent. No security notice goes to a `MustVerifyEmail` user whose address isn't verified, because whoever registered typed that address, so it may belong to anyone. The notice of a finished password reset is the exception, since the reset link went to that address.

#### Octane's Cache Store

Under Octane on Swoole, Laravel has an `octane` cache store. It's a Swoole table in the server's memory. It's fast, but it's the wrong place for Keyring's limits. Keep `cache.limiter` and `risk.store` on a database or Redis store. Here's what a test run with them on the `octane` store found:

- **Keys hold 63 bytes.** Keyring's keys fit. Everything it counts or remembers there is kept under a short prefix and a hash. That's true whatever the factor is called, and however long a username or an ID is.
- **Rows aren't freed when they expire.** A table made for the default 1,000 rows was full after a couple of hundred failed sign ins for made-up names. From then on, every sign in that needed a new row answered `500`. If you use the store at all, size `octane.cache.rows` generously. Size it for everything your app caches there, not only Keyring's keys.
- **Counts aren't atomic across workers.** When 48 wrong passwords were sent at once against a limit of 5, 8 got through. The database store never let more than 5 through. Anything that has to happen once, such as a sent code, an answered WebAuthn challenge or an enrollment's confirmation, relies on the store taking one of two writes.
- **"Forever" is one year, and a restart loses everything.** The marks Keyring keeps for good, such as when an account's limits were last cleared, run out after a year in this store. Every count, lock, sent code and mark is gone when the server restarts.
- **Laravel's session lock needs another store.** If `CACHE_STORE=octane` is your default store, set `session.block_store` to a store that supports locks. Keyring's sign in, challenge and enrollment routes take the session lock, and this table has no locks to give.

Either way, the failures in a row and the locks held until a reset are in your database. So the cap on guessing holds whatever the cache does. The per-minute limits, sent codes and risk locks are only as good as the store they're in.

### Single-Use Codes

- TOTP codes can't be reused. Each authenticator stores the last time step it accepted, and it updates that under a database row lock. So two requests with the same code can't both pass.
- A TOTP code is accepted for one 30 second step either side of now at most. With a [window of zero](factors.md#authenticator-apps-totp), it's accepted only during its own step. No wider window can be set.
- Each recovery code works once, and it's used up under the same kind of row lock. If two different codes are used at the same time, both stay valid until they're used.
- A set that has had a code used says so until it's replaced, which you can check with `shouldReplaceRecoveryCodes()`. Your app can then send the user to make a new set. Keyring doesn't issue one by itself. See [Known Limitations](#where-keyring-departs-from-a-standard).
- Email codes are random and, by default, eight digits long. They're shown as two groups of four, such as `1234 5678`, and spaces are ignored. By default, each code expires after 10 minutes and allows five wrong guesses per pending attempt. `EmailCode::asExtraStep()` takes a `length`, `expireAfter` and `maxGuesses` to change these. Any newer code replaces it. A newer code doesn't reset the count. At the limit, the user has to start signing in again. A sent code only verifies the authenticator it was sent to.
- No factor that sends codes can be registered with codes shorter than six digits, or with codes that last longer than ten minutes. That applies to the built-in email codes and to [one of your own](factors.md#writing-a-code-factor). If you try, Keyring throws a `LogicException` instead.
- A sent code works once on every session driver. Its state isn't kept in the session. Instead, the code waiting to be typed (as a keyed hash), the wrong guesses at it and the fact that it was used are kept in the cache store the rate limits use, `cache.limiter`. They're filed under the pending sign in, step-up or enrollment the code was sent for. A right code is used up the moment it's checked, even when a later step refuses the sign in. If two requests send it together, one is refused. A newer code ends the one before it, and the guesses stay counted, whichever copy of the session the browser sends. This holds for every code factor, at sign in, step-up and enrollment. If that cache store is cleared, pending codes go with it, and the user has to ask for another.
- An enrollment adds its sign-in method only once. The fact that it was confirmed is remembered in the same cache store until it would have expired. That way, an earlier copy of the session can't confirm it again and bring back recovery codes that have since been replaced or used.
- WebAuthn challenges are random 32 byte values. They're kept in the session, with the sign in, step-up or enrollment they belong to. The first answer uses a challenge up, whether that answer is right or wrong. The challenge is taken out of the session. The fact that it was answered is remembered in the cache store the rate limits use (`cache.limiter`) until it would have expired. So a signed answer can't be sent a second time on any session driver. That covers an earlier copy of the session that still holds the challenge, which a browser can send back on Laravel's `cookie` driver. It also covers two requests that answer one challenge together, where one of them is refused. This matters most for a synced passkey, whose signature counter stays at zero and would otherwise let the same answer through twice. The rule applies to every ceremony: a usernameless sign in, a second factor, a step-up, adding a key, and proving a key to [make a change while sign-in methods are frozen](authenticators.md#making-a-change-with-an-established-key). A passkey that verifies on the second-factor step has used its challenge up, even when a later check, such as a risk lock, refuses the login. A challenge only completes the ceremony it was issued for. One from the usernameless login options can't finish a second factor or a step-up. One issued to prove a frozen change is kept apart from all of those, with the change (removing one authenticator, renaming one to a given name, or replacing one factor's) and the account it's for. It can't finish anything else, and nothing else can stand in for it. Answering it for another change, or renaming to another name, uses it up. Keyring claims it on the server with its first answer, in `cache.limiter`, so that holds for a factor of your own that proves a change too, whatever its `verify()` remembers. Each challenge also runs out on the server, whatever the browser's timeout. A usernameless challenge runs out after `webauthn.login_options_for` (5 minutes). A second factor's or a step-up's challenge runs out with its pending login (10 minutes). A new key's challenge runs out with its enrollment (15 minutes). A frozen change's challenge runs out like a usernameless one.
- A passkey's signature counter is checked and saved under the same kind of row lock. So two assertions can't both pass against one stored count, and a slower request can't lower it.

### Second Factors and Step-Up

- Policies count distinct categories, so two factors of the same kind are never treated as multi-factor. AAL2 also needs one of the two factors to be something the user has (NIST SP 800-63B-4, Sec. 2.2.1). A password beside a factor that is only a biometric makes an AAL1 session.
- Assurance levels follow NIST SP 800-63B-4 as far as a library can check. A passkey that syncs reaches AAL2. AAL3 needs a phishing-resistant key with three properties. First, it reports on every sign in that it can't leave its device. Second, it was added with a verified attestation. Third, it either verified the user itself or was used with a password. Another built-in authenticator's user verification never counts beside it. A factor of your own that reports only inherence does count beside an attested key. NIST's "or a biometric comparison" allows this (Sec. 2.3.1). A key that nothing vouches for stays at AAL2. A policy or route can still ask for one with `deviceBound()`.
- NIST's AAL3 also needs authenticators and verifier cryptography validated to FIPS 140. Keyring can't supply or check either one. So a session that Keyring calls AAL3 has met NIST's rules for the authentication, and nothing more.
- Email codes are opt-in, through `EmailCode::asExtraStep()`. NIST doesn't accept email as an authenticator, and the inbox can also reset the password. A code is a step at sign in, never a factor. A password and an emailed code make an AAL1 session. That session doesn't pass `keyring:aal2` or `keyring.enrolled`, doesn't earn a trusted device, and can't stand in for a possession factor the account has.
- A passkey or security key only counts as inherence when it actually verified the user that time.
- The first recovery codes are shown only to a session that has proved two factors. Confirming a new sign-in method takes proving it, and the session counts that proof from the same response (NIST SP 800-63B-4, Sec. 3.1.2.1). Later sets need a fresh verification of both factors.
- With `noDowngrade()`, users with a passkey or security key can't be offered a weaker way in. Recovery codes stay on offer as the way back in, unless you pass `except: []`. Only a key the account has had for 7 days counts (`authenticator_changes.established_after`). So a key added from a stolen session doesn't stop the owner's other factors from working.
- With `ifEnrolled()`, a policy the user can't fully meet still asks for the strongest version they can give. So a user with a second factor never signs in with only one factor. Only authenticators the account has had for 7 days decide how much that is. A newer one counts toward it when it's used, but doesn't add a kind of factor to what's asked, and doesn't count as phishing resistant, device bound or attested. So a key added from a stolen session can't make a `factors(3)`, `phishingResistant()`, `deviceBound()` or `aal3()` policy with `ifEnrolled()` ask the owner for a factor they don't have. An account with an established password and no established second factor is the exception: adding one takes the password, so its new factors are asked for at once, as factors. A factor added without the password being checked for it, before the account had one or while its only one was new, never is, whatever password the account has since. A requirement asked for outright, by a policy without `ifEnrolled()` or by middleware such as `keyring:aal3`, takes any key that meets it.
- Adding, removing or changing sign-in methods, revoking devices, changing the password and starting an email change all need a fresh verification. That verification uses the strongest combination the account can give, and at least what signing in would ask (NIST SP 800-63B-4's rule for binding authenticators, Sec. 4.1.2.1). Users with a possession factor always use one. Users with a key that can't leave its device use that key. So a stolen session plus a phished password and code isn't enough, once the session is no longer fresh from signing in. A recovery code with the password stands in for a lost key, as NIST's account recovery allows. At a step-up, a recovery code never counts on its own. An account with nothing but a set of codes beside its password confirms with the password. Only keys the account has had for 7 days are asked for, so the owner can remove a key someone else added with what they had before.
- Adding a second factor to an account with no established one takes the current password in that request. A recent sign in doesn't count for it, so a copied session can't give a password-only account a factor its owner doesn't have. A wrong password counts against the password's rate limits. A first password set from a session, with no current one to type, isn't established for 7 days, so it isn't asked for here, and isn't asked for at sign in, until then.
- An account's sign-in methods are [frozen](authenticators.md#frozen-sign-in-methods) for 7 days after one is added, a first password set from a session included, and after an established one or an established set of recovery codes is removed or replaced. While they're frozen, an established authenticator can't be removed, renamed or replaced, and established recovery codes with codes left can't be replaced. A newer authenticator can always be removed. This is checked in `AuthenticatorChanges`, so JSON clients and your own code get it too, under the same row lock as the other removal checks. The owner can make one change anyway by proving, in that change's own request, a passkey or security key (or a phishing-resistant factor of your own) the account has had for 7 days and since before the session signed in. A sign in or step-up never counts for it, so a copied session cookie can't. An authenticator app only counts with `authenticator_changes.skip_with_totp`. Recovery codes, an emailed code and the password never do.
- The fresh window is fixed from the moment of verification. It doesn't slide with activity.
- Users can't add a sign-in method until their email is verified, with `MustVerifyEmail`. That way, someone who registers an address first can't plant a factor that survives the real owner's password reset. With registration on, a user model that can't verify its email can't add sign-in methods at all.
- Users can't remove authenticators below what they need to sign in, even when they remove several at once.

### Sessions and Devices

- Every signed-in Keyring route checks Keyring's guard (`auth:{guard}`). The step-up middleware reads the user from that guard too, so a user of another guard can't stand in.
- Every signed-in session is in Keyring's registry. Keyring checks it on every `web` request, unless you've set `sessions.middleware` to `false`, and on any other group you add `keyring.session` to. So revoking a session takes effect on its next request, whichever session driver you use. Timeouts and revocations only reach routes that run that middleware. The [conformance suite](testing.md#the-conformance-suite) fails for a signed-in route that doesn't.
- An account can have 100 sessions at once (`sessions.max`). A sign in beyond that ends the session that's been unused longest. It's never refused, so holding an account's sessions can't keep its owner out. See [How Many Sessions](devices-and-sessions.md#how-many-sessions).
- A session ends after two hours unused (`sessions.idle`), and 30 days after sign in at the latest (`sessions.absolute`). Those limits are counted on the session's registry record, so they don't depend on your session driver or `session.lifetime`. Each assurance level lapses on NIST SP 800-63B-4's clock. For AAL2 that's 1 hour idle or 24 hours. For AAL3 it's 15 minutes idle or 12 hours. The lapse holds until the user verifies again. A session past its level's limits is treated as the lower level, and it stays signed in. That's Keyring's reading of Sec. 5.1, and it departs from Sec. 5.2. With `sessions.end_on_lapse`, the session ends instead, when the level it signed in at runs out, as Sec. 5.2 words it. "Remember me" brings nothing back in that case.
- A browser that ticked "remember me" is the one deliberate exception to the two hours. It may stay away for 14 days (`sessions.remember_idle`) and be signed back in, all within the same 30 days. After two hours unused, the session holds no level. So anything behind `keyring:aal2` or `keyring.fresh` asks the user to verify again. See [Inactivity and "Remember Me"](devices-and-sessions.md#inactivity-and-remember-me).
- "Remember me" can't outlast the session it was ticked for. Laravel's cookie alone signs nobody in. The browser also holds a Keyring cookie that names that session's registry record. Coming back carries the session on, with the limits it started with and nothing proved. Once the record has timed out, been revoked or been ended by a risk response, both cookies are refused. That holds even for a client that kept them after being told to delete them.
- A "remember me" cookie works once. Coming back moves the session to a new record and gives the browser a new cookie. So a copy of the pair brings back nothing that the browser it was taken from hasn't already had. If a used cookie is sent again, or a browser is still signed in on the record it named, then two browsers held the same pair. In that case the session ends for both, with a `RememberMeReused` event and a `remember_me_reused` log entry. There's one exception. The same browser's other requests in the few seconds after (`sessions.remember_grace`) join the session the first one resumed. Those requests can't start another session, and sending the cookie again doesn't make those seconds any longer.
- A resumed session's device, IP address and browser are those of the request that resumed it, kept on the resumed session's own record. A browser still on the record from before is never compared with them.
- A user can always see their sessions. They can end any one of them, or all the others, at `/user/sessions`, whatever features are on. Ending a session needs a fresh verification, but looking at the list doesn't. A user can only find their own sessions.
- A session's registry ID, which its "remember me" cookie carries, is never sent to a page. The sessions list names each session by a keyed hash of that ID. The hash can't be turned back into the ID, or used as a cookie.
- If a session's registry record has gone missing, the session is signed out rather than started over.
- An administrator can end one user's sessions, or everyone's, with the `php artisan keyring:sign-out` command. "Remember me" brings none of them back. See [For Administrators](devices-and-sessions.md#for-administrators).
- [Impersonation](impersonation.md) is off, and refused for everyone until your app says who may. Starting is a `POST` behind two factors proved in the last 15 minutes. The impersonated session is a registered session of its own, on a new session ID, that proved nothing and can't step up, and it ends by itself after an hour. Keyring's own security changes are refused while it lasts. Who may impersonate whom is asked again on every request, so taking the right away ends one that's running. Going back takes the impersonator's own session still being good, never just their ID, and the browser's session still being the impersonation it started. Their session is kept from lapsing while they were busy (a gap between requests past a level's idle limit still lapses it), but they come back at AAL1 at most, or are signed out under `sessions.end_on_lapse` when their session signed in above that, with nothing counting as fresh, so a page of the user's that sends the stop can't then act as an administrator who proved a second factor: `keyring:aal2`, `keyring.fresh` and other step-ups ask again. Put admin routes behind `keyring:aal2` rather than `auth` alone. Their session moves to a new record as they come back, on every session driver, so a copy of the session from while they impersonated leads nowhere: a cookie session's copy, or a request that overlapped the stop. Both accounts' security logs record the start and the end.
- An account that your app stops letting sign in is refused wherever a session starts or carries on. That's controlled by [`allowSignInWhen()`](sign-in-flow.md#who-may-sign-in). The first request that's refused ends every session the account has, along with its "remember me" cookies and trusted devices. Until one of its sessions makes a request, those sessions stay on record. So call `Sessions::signOutEverywhere()` as you set your flag, to end them then and there.
- Signing a user out everywhere and a session moving to a new record take turns. So a "remember me" cookie that comes back at that moment can't carry a session past the sign-out.
- A request that saves a stale copy of its session can't undo a revocation.
- Laravel's session ID is never stored by Keyring or written to the security log.
- Devices are recognised by a random, httpOnly cookie, which is stored as a hash. A device is never a factor. It's only an input to your policy and risk signals.
- Keyring's two cookies, the device cookie and the "remember me" one, are httpOnly and `SameSite=Lax`. Once the app is served over HTTPS, meaning `APP_URL` is `https` or `session.secure` is on, they're always `Secure`. They carry the `__Host-` prefix, or the `__Secure-` prefix when your cookies are shared with subdomains or kept to a path. See [Keyring's Cookies](devices-and-sessions.md#keyrings-cookies).
- Signing out everywhere also stops trusting the other devices, and it cancels pending email changes. So whoever had the account can't skip the second factor on a device they trusted, or finish a change they started.
- A device is only trusted after a login that reached AAL2. Trust is never granted after the password alone, or with an emailed code. An account's device never takes a cookie value that the browser sent. The first sign in from a browser, a login that reaches AAL2 and any grant of trust each give the device a new value. So being recognised, like being trusted, can't rest on a cookie placed in the browser before the user signed in. Whoever placed that cookie isn't recognised as the account's browser from their own.
- Every device stops being trusted when the password changes, when an authenticator is removed, when an email change is applied, or when a signed-in request places a risk lock. A lock placed by a login attempt doesn't do this (see [Signing In](#signing-in)).

### Account Changes

- With `Features::updatePasswords()` and `Features::emailChanges()` on, `password` and `email` can only change through Keyring's flows. Getting around that needs `Keyring::withoutProtection()`, which is announced and logged. Without those features, your app changes those attributes itself.
- An email change needs three things. It needs a fresh verification, confirmation from the new address, and confirmation from the current address. The last one can be skipped only when the session proved a second factor that the account has had for at least a week (`email_changes.established_after`) and already had when the session signed in. A recovery code doesn't count.
- An email change never reveals whether the new address has an account. That holds for its answer, its timing and the pending change it shows. Its emails, like the reset email, are sent after the response.
- An email change only applies if the address is still the one it was requested from.
- Emailed links, for email verification, email change confirmation and revert, and "this wasn't me," only act on a button press, which is a POST. So mail scanners that open links change nothing. No `GET` route of Keyring's changes state, apart from the three that [single sign-on](sso.md) needs, since a provider sends the user there and back with `GET`s: the sign in redirect, the confirm redirect (`GET /confirm/sso/redirect`) and the callback. The callback only finishes a request that this browser's session started, which its state has to name, so a link from anywhere else can't finish anything through it. The two redirects only start a request in the browser's own session, but a link from anywhere else can start one. A confirm redirect opened from another site, while a confirm is in progress (which opening any page behind `keyring.fresh` starts), sends the user to their provider. With a provider whose `freshness` is `reauthenticate`, they have to sign in there again. With one opted into `round_trip` that lets them straight through, the session comes back with a fresh verification without them doing anything. That's the [known limitation](#other-limits) of `round_trip`. A `never` link isn't offered for a fresh verification, so its confirm redirect answers `404` there. Toward a level, it's a round trip that counts no more than signing in through the provider again would, and never as fresh. The page posts the link's token or signature in the body, to a URL that doesn't include it, as the password reset does. That way, the request that acts doesn't leave the token in access logs a second time.
- A password reset with a bad token gets the same answer for every address. Password rules, whose minimum length is lower for accounts with MFA, only run once the token checks out.
- Reverting an email change does several things. It signs out every session, ends any sign in still waiting for its second factor, and closes later changes. It also removes sign-in methods that weren't established when the change was asked for. It removes the recovery codes too when none of what's left is a factor they could recover. Cancelling a change doesn't stop its revert link from working.
- While an email change can be reverted, nobody else can take the address it replaced. So the revert always has somewhere to put the address back.
- A password reset gives the same answer for every address. It signs out every session, cancels pending email changes, unlinks every identity provider, and lifts risk locks and sign in lockouts.
- A password change takes the current password as well as a fresh verification. Keyring checks both itself, rather than leaving that to your action. A user with no password yet sets one with the fresh verification alone. The new password is only saved over the one that was checked. That happens under a row lock, and only while the session is still signed in. So a change that overlaps a reset can't replace the password the reset set.
- Password changes cancel pending email changes. So someone who knew the old password can't finish one.
- Every change to how someone signs in can end their other sessions. A password reset and a reverted email change end every session. A password change and an applied email change end the others, unless you tell them not to. To do that, use `sign_out_others` on the request, or `email_changes.sign_out_others` in the config. Adding or removing an authenticator, or making new recovery codes, ends the others when the request asks for it, using `sign_out_others`. The "sign out everywhere else" route (`DELETE /user/sessions`) is always registered, whatever features are on.
- New passwords need at least 8 characters when the user has a second factor, and at least 15 when they don't. Neither minimum can be configured below 8. Any characters are accepted, and there are no composition rules.
- New passwords are checked against the 10,000 most common passwords of 8 characters or more, and against the 3,000 most common of 15 characters or more. This happens in every environment. Passwords are also checked against your app's name, the words you list in `passwords.context`, and the user's own name and email address. Look-alike characters are read as letters. The whole password is compared, as NIST SP 800-63B-4 Sec. 3.1.1.2 requires. A password made up of those words is refused. A passphrase that only has one of them in it is not.
- In production, new passwords are also checked against breach lists from Have I Been Pwned. If that service can't be reached, the check lets the password through. You can change that by setting `passwords.refuse_unchecked`.
- New passwords are refused rather than silently cut short by bcrypt. With bcrypt, that limit is 72 bytes. To accept every password up to `passwords.max`, hash with argon2id. A new password that bcrypt can't hash at all, one with a NUL byte, is refused along with the other rules. So registration, a change and a reset all answer it with a validation error.
- Passwords never expire. A user is held until they choose a new one when there's evidence that their password is compromised (NIST SP 800-63B-4, Sec. 3.1.1.2). That evidence can come from your app, from a risk response of yours, or from Keyring's own response. Keyring's response applies when the `BreachedPassword` signal finds the password the user signed in with in a breach. That signal is off until you turn it on. The hold outlasts signing out and clearing the cache. It ends with a password change or reset, and it's never placed on an account without a password.

### Links and Headers

- Every Keyring response is sent with `Cache-Control: no-store, private` and `X-Content-Type-Options: nosniff`. Signing out also sends `Clear-Site-Data`. The referrer policy and the frame header are covered below.
- Every emailed link (password reset, email change, email verification and "this wasn't me") is built from `APP_URL`, and so is the callback URL Keyring sends identity providers. It's never built from the request that caused the email. That means neither its `Host` header nor an `X-Forwarded-Prefix` that your proxy passed on is used.
- Signed links are signed over the path and query only. They're checked with `keyring.signed:relative`, which is Laravel's `signed` middleware with refused links logged. So a forged `Host` header can't redirect them.
- Pages opened from emailed links (password resets, email verification, email changes and "this wasn't me") have the link's token or signature in their URL. So they're sent with `Referrer-Policy: no-referrer`. That means nothing the page loads is told its URL, including your own assets and analytics. A failed form still finds its way back, because Keyring notes the page in the session.
- The page a user was going to when Keyring sent them to enroll or to choose a new password is kept in the session, with the user it's for and when it was saved. It's only saved for a top-level navigation or an Inertia visit, never an image, a `fetch()` or a prefetch. It's only handed back on the app's own origin, to that same user, within an hour, and signing in forgets it. The redirect after a held password change is then a same-site navigation to a URL the user's own earlier navigation chose, as `url.intended` is after signing in. That only matters to an app with `GET` routes that change something.
- Every other Keyring response sends `Referrer-Policy: same-origin`. That way, other sites never see its URL, while your own app still does.
- A site that opens one of Keyring's pages in a new window keeps no handle on that window. Each response is sent with `Cross-Origin-Opener-Policy: same-origin-allow-popups`, unless it already has that header. A window the page opens itself, such as a social login's window, still answers to the page.
- No Keyring response may be shown in a frame. Each one is sent with `X-Frame-Options: DENY`. That covers the pages that act on one press of a button, such as confirming an email change, undoing one, reporting a device or verifying an address. It also covers the sign in, challenge and confirm pages. A page on another site could load those invisibly and line its own button up over them. A response that already says who may frame it is left as it is. That applies to a response with an `X-Frame-Options` of its own, or with a `Content-Security-Policy` that has a `frame-ancestors` directive. See [A Content Security Policy](#a-content-security-policy).
- An Inertia app keeps the policy of the page it first loaded. So when the form on an emailed link's page succeeds, Keyring answers Inertia with a full page visit (a `409` with `X-Inertia-Location`). The next page then comes with its own policy. Otherwise, every page after it would send no `Referer` either, whether the user is signed in or not.

#### Emailed Links

An app on several domains may need to start its links somewhere other than `APP_URL`, such as the tenant the user belongs to:

```php
Keyring::linkRootUsing(fn () => tenant()->url);
```

Work the root out from something the server knows. The request's `Host` header is whatever the sender says. A link built from it would send a real reset token to the sender's site. The signature covers the path and query, so links keep working under any root.

A frontend that Laravel doesn't serve sets the root to its own URL, and serves a page at each of Keyring's paths. Its pages then need `Referrer-Policy: no-referrer` and `Cache-Control: no-store` of their own, since Keyring's headers only reach Laravel's responses. See [Headless Frontends](headless.md#emailed-links).

#### Tokens in Emailed Links

An emailed link has to carry whatever makes it work, so its token or signature appears in the URL of the page it opens. OWASP ASVS 5.0.0 (14.2.1) asks for nothing sensitive in a URL, and for these links Keyring can't meet that. Keyring does what it can, as described above. The page changes nothing and posts the token in the body of the request that acts. The page is sent with `Referrer-Policy: no-referrer` and `Cache-Control: no-store`. Every link expires. A reset link stops working once it's used, or after `auth.passwords.*.expire`, which is 60 minutes in a new app. An email change's confirming links last 24 hours (`email_changes.confirmable_for`), and its undo link lasts a week (`revertable_for`). Each of them works once. A verification link lasts `auth.verification.expire`, which is 60 minutes. A "this wasn't me" link lasts a week (`devices.report_link_for`).

The reset link also carries the account's email address, as Laravel's own reset link does, and Keyring keeps it that way. Laravel's broker finds a reset by its address. Its table is keyed by the address and holds the token as a password hash, which can't be looked up. So the form has to post the address. Without it in the link, the user has to type the address into a field. Most reset pages, Laravel's starter kits among them, show that field filled in and read-only. The address is also less of a secret than the token, since it's only who the email was sent to. If you want to keep the address out of the URL all the same, build the link yourself, and have your page ask for the address. Keyring leaves a callback of yours alone:

```php
use Illuminate\Auth\Notifications\ResetPassword;
use Keyring\Support\Url;

ResetPassword::createUrlUsing(fn (User $user, string $token) => Url::route('password.reset', ['token' => $token]));
```

`Url::route()` builds the link from `APP_URL`, as Keyring's own link does. The `reset-password` page then receives an empty `email`.

### Request Input

A URL ends up in places that a request's body doesn't, such as access logs, proxies and the browser's history. Laravel's `$request->input()` reads the query string as well as the body. So a password sent as `POST /login?password=...` would work, and it would be logged.

- Keyring reads anything that proves something from the body alone, whether it's a form or JSON. That covers passwords (when signing in, confirming, changing, resetting, registering or removing the last second factor), codes, WebAuthn credentials, the reset token, and the tokens and signatures that the pages of [emailed links](#links-and-headers) post.
- Sign in, challenges, step-up, enrollment and password resets validate against the body. So a required field that appears only in the query string fails as missing. That includes a factor of your own, whose `rules()` are checked the same way.
- Your `CreatesNewUsers`, `ResetsUserPasswords` and `UpdatesUserPasswords` actions receive the body, not the query string.
- A `GET` request has no body. So a sign in that you start from a `GET` route with `Keyring::attempt()`, such as an identity provider's callback, is read from the query string. The callback carries the provider's code and state in its URL too, which OAuth needs. The code is no use without the PKCE verifier, which never leaves the session.
- Fields that prove nothing can still come from either the body or the query string. These are `remember`, `trust`, which authenticator to show, `sign_out_others`, and the new address of an email change.

### Storage

- TOTP secrets are encrypted with `APP_KEY`. The [Cryptography](#cryptography) section lists every algorithm and key.
- Recovery codes and email codes are stored as keyed hashes (HMAC-SHA-256). A recovery code is only stored if it has 112 random bits or more. Keyring's own codes have 128 bits, and codes imported from Fortify have 119. No other form is stored or accepted. A sent code is far shorter, so its hash is kept in your cache for ten minutes at most, and it allows five guesses by default.
- Keyed hashes never use `APP_KEY` directly. Each kind of hash has a key of its own. The kinds are recovery codes, one-time codes, reserved addresses, WebAuthn user handles and session handles. Each key is derived from `APP_KEY` with HKDF. So a hash made for one kind can't pass as another, and no hash is made with the key that Laravel encrypts and signs with.
- Email change tokens are stored as SHA-256 hashes, and the addresses in a pending change are encrypted.
- Device tokens are stored as SHA-256 hashes.
- A session's registry ID is stored as it is. See [Algorithms](#algorithms) for why an ID read from the database signs nobody in.
- WebAuthn credential IDs longer than 512 characters are refused rather than cut short.
- WebAuthn user handles are an HMAC of the user's model and ID. They're never the ID or the email itself. So two user models with the same ID don't share one.

### Logging

- Out of the box, Keyring records sign ins, failed factors, lockouts, session starts and ends, sessions that "remember me" carried on, and every change to how an account signs in. A session that your own code starts with `Auth::login()` isn't recorded. The entries go in the [security log](security-log-and-emails.md) table, which is on by default. If you turn the table off, they go in your app's log instead. There's no setting that records nothing. Text in an entry's details that isn't valid UTF-8 is cleaned up so the entry is still written. For example, an authenticator's name may have been stored before Keyring refused it. If an entry's details can't be kept at all, the entry is written without them, and the reason is reported. Authenticator names are kept as valid UTF-8 whenever they're saved through the model.
- Refused requests are recorded too. That covers a request for someone else's authenticator, device or verification link. It covers a sign-in method that wasn't added, and a removal that would have left the account unable to sign in. It also covers an emailed link with a wrong, ended or expired token or signature, a request the form rate limiter turned away, and a verification the pipeline's final gate turned away. None of this changes the answer the requester gets.
- No entry holds a password, code, token, signature, session ID or request body, in the table or in the app's log. Form validation errors aren't logged.
- Every entry carries a severity and the time, and the ID of the request that wrote it while `security_log.context_key` is set. That's `trace_id` by default, and with it set to `null` entries have no request ID. In the table, the time is in your `app.timezone`, which is UTC unless you've changed it. In your app's log, the time is written with its offset. See [Times](security-log-and-emails.md#times).
- A refused request can't fill the log. A lock is logged once when it starts, not once for each request it refuses. Refusals are also capped per account or IP address. When the cap is reached, a single entry says where the log stopped. See [Refusals That Repeat](security-log-and-emails.md#refusals-that-repeat).
- A log write that fails never fails the sign in, so a refused attempt stays refused. There's one exception. `Keyring::withoutProtection()` doesn't run unless its entry was written.
- Old entries, devices, ended email changes, ended sessions and old sign-in changes are deleted every day. A task that Keyring schedules itself does the deleting. The records of a force deleted user go with them.

## What Keyring Keeps

This section covers everything Keyring stores about a person. It describes how that data is protected, how long it stays and who can read it. The list is built from the migrations, so a table that you've added columns to holds whatever you put there as well.

| Where | Personal Data | Protected By | Kept For |
|---|---|---|---|
| `keyring_authenticators` | The name the user gave it, stored as plain text. TOTP secrets and recovery codes are in `secret`. A passkey's or security key's credential ID, public key, AAGUID and transports are stored too. So is the address an email code goes to, when a factor keeps one. | `secret` is encrypted with `APP_KEY`, and the recovery codes are keyed hashes inside it. Credential IDs and public keys are stored as plain values. They're public by design, and they're useless without the key itself. `secret`, `public_key` and `credential_id` are hidden when the model is serialised. | Until the user removes it, an email change is undone, or the user is force deleted. |
| `keyring_devices` (with `Features::devices()`) | IP address, user agent, a name, and the [location](devices-and-sessions.md#locations) that your locator returned, including the country, region, city and coordinates. | The device cookie's token is a SHA-256 hash, hidden when serialised. The rest is plain. | 30 days after it's signed out (`devices.keep_revoked_for`), a year after it was last seen (`devices.keep_unseen_for`), or until it's the oldest device past `devices.limit`. Deleted with a force deleted user. |
| `keyring_sessions`, or your cache with the `cache` driver | The user's ID, IP address, user agent, whether "remember me" was ticked, and when they signed in and were last active. | The ID is Keyring's own random one, never Laravel's session ID. The rest is plain. | Until the session expires or is revoked, then the next daily prune. A record "remember me" replaced stays until it would have expired. Cache records expire on their own. |
| `keyring_pending_changes` (with `Features::emailChanges()`) | The new and the old email address. | Both addresses are encrypted with `APP_KEY`. A keyed hash of the old address lets Keyring find the change by it. The three tokens are SHA-256 hashes. All of them are hidden when serialised. | 30 days after the change ended (`email_changes.keep_ended_for`). Deleted with a force deleted user. |
| `keyring_events` (with `Features::securityLog()`) | IP address, user agent, the device's ID, and in `meta` an authenticator's name or a device's description. | Plain. Never a password, code, token, signature, session ID or request body. | 180 days (`security_log.keep_for`). Deleted with a force deleted user. |
| `keyring_failure_counts` | Nothing beyond whose it is. That's the user's ID, the factor, the authenticator's ID, and two counts of failures in a row. | Plain. | Until a success, a password reset or `Keyring::unlock()` clears it, or its authenticator is removed. Never pruned, because a row is what keeps an authenticator refused [at the cap](#at-the-cap). Deleted with a force deleted user. |
| `keyring_password_holds` | That the user has to choose a new password, and the reason your app or a risk response gave. Write nothing personal there. | Plain. | Until the password changes or the hold is called off. Deleted with a force deleted user. |
| `keyring_sign_in_changes` | Nothing beyond whose it is, when the account last removed or replaced an established sign-in method or its recovery codes, and when a first password was set from a session. | Plain. | Until it no longer [freezes](authenticators.md#frozen-sign-in-methods) anything (`authenticator_changes.established_after`), then the next daily prune. Deleted with a force deleted user. |
| Your app's log (without `Features::securityLog()`) | The same as `keyring_events`, one line per event. | Whatever protects that log channel. | Whatever that channel keeps (`days` on a `daily` channel). |
| The session | A sign in waiting for its second factor. An enrollment in progress, including the secret being set up. What a form or Inertia response hands the next page, such as that secret or new recovery codes. And what the session has verified. | Encrypted with `APP_KEY` inside the session, whichever session driver holds it. | 10 minutes for a pending login (`pending_logins.keep_for`), 15 for an enrollment (`enrollments.keep_for`), otherwise the session's life. |
| The rate limiter's cache store | Counts of attempts, keyed by a SHA-1 of the factor with the account, the typed username or the IP address. The store also holds hashes of sent codes, marks for answered WebAuthn challenges, marks for impersonations that have ended, keyed by a SHA-1 of the impersonated session's handle, and enrollments under way. It holds risk locks too, in `risk.store`, keyed by a SHA-1 of the user's model and ID. | Hashed keys, so the store holds no names or addresses to read back. A risk lock's key is an unkeyed hash of the user's model and ID, so anyone who knows an ID can work it out. | A minute for counts, up to 24 hours for locks, 30 days for the failures in a row counted under a typed username (`limits.remember_names_for`). |
| Laravel's own tables | The reset token and address in `password_reset_tokens`, and `remember_token` on your users table. | Laravel hashes the reset token. | Laravel's `auth.passwords.*.expire`. Keyring deletes a user's reset tokens when they're deleted or their address changes. |

If you want to store less of an address, or none at all, see [What's Stored](security-log-and-emails.md#whats-stored). `Keyring::recordIpsUsing()` applies to devices, sessions and the log alike. Security emails pass the IP address and a description of the browser to the user they're about.

**Who can read it.** Keyring has no admin screens, and no route returns another person's records. A signed-in user can read their own. [`GET /user/devices`](devices-and-sessions.md#listing-and-revoking-devices) lists their devices, with IP address and location. ["was this you?" alerts](security-log-and-emails.md#was-this-you-alerts) show the type, time and IP address of entries about their account. [`Keyring::activity($user)`](security-log-and-emails.md#showing-recent-activity) returns their entries, leaving out the types in `security_log.unlisted`, if you build a page for them. Everything else is reached only by your own code, and by whoever can read your database, cache and logs. So those are what to restrict. Treat `keyring_events` and the log channel as you would any audit log.

**Deleting someone.** Force deleting a user deletes their authenticators, devices, pending changes, security log entries, failure counts, password holds and reset tokens. It also revokes their sessions, and the next prune removes those. A soft deleted user is signed out everywhere and their reset tokens are forgotten, but they keep the rest, in case they're restored, until each record's own time is up.

## What Your App Must Provide

Keyring sets the headers and cookies on its own responses. The rest of what a browser needs belongs to your app and your server, because it covers every response, not only Keyring's. This is what Keyring expects to be in place, what it does about each item, and what happens without it.

| Your App Provides | Keyring Does | Keyring Doesn't |
|---|---|---|
| HTTPS on every request, and HSTS | Builds emailed links from `APP_URL`, and keeps its own cookies to HTTPS once `APP_URL` is `https` | Redirect HTTP to HTTPS, or send `Strict-Transport-Security` |
| Trusted proxies, behind a load balancer | Reads the client's address and scheme from the request Laravel gives it | Work out which proxies to trust |
| `SESSION_SECURE_COOKIE=true` | Makes its own two cookies `Secure` and gives them the `__Host-` prefix | Change the flags or name of Laravel's session, CSRF or "remember me" cookies |
| A `Content-Security-Policy`, with `frame-ancestors` | Sends `X-Frame-Options: DENY` on its own responses, unless yours already say who may frame them | Send a policy. Your layout and assets decide what one has to allow. It doesn't stop your other pages being framed |
| `X-Content-Type-Options: nosniff` on your own responses | Sends it, with `Cache-Control: no-store`, `X-Frame-Options: DENY`, a `Referrer-Policy` and a `Cross-Origin-Opener-Policy`, on every Keyring response | Add headers to routes that aren't Keyring's |
| A bot check, if your forms need one | Limits how often anything can be tried, and makes every refusal take as long as the next | Tell a person from a script. There's no CAPTCHA, no challenge and no minimum time to fill in a form |

### HTTPS and HSTS

Serve the whole app over HTTPS. Redirect plain HTTP to HTTPS, and send `Strict-Transport-Security`, so that a browser which has visited once never tries HTTP again. That's your web server's or load balancer's job, and it applies to every response.

Set `APP_URL` to your `https://` address. Keyring takes that as a sign that the app is served over HTTPS. `APP_URL` is where emailed links start, and it's the origin that passkeys are bound to. It also decides whether [Keyring's cookies](devices-and-sessions.md#keyrings-cookies) are `Secure` and prefixed.

Without HTTPS, passwords, codes and session cookies cross the network in the clear. Browsers also refuse passkeys and security keys altogether, except on `localhost`.

> [!NOTE]
> Keyring still works over plain HTTP for local development. It uses unprefixed cookies that aren't forced `Secure`.

### Trusted Proxies

Behind a load balancer or CDN that ends TLS, tell Laravel which proxies to trust, using `trustProxies()` in `bootstrap/app.php`. Until you do, every request looks like plain HTTP from the proxy's address, and that has three effects:

- every user shares one address for the [per-IP rate limit](#rate-limiting), so one person's failures hold everyone up,
- the IP addresses in the security log and on the devices page are the proxy's,
- Laravel only marks its own cookies `Secure` on a request it knows came over HTTPS, so if `SESSION_SECURE_COOKIE` is unset, they're sent without it.

Keyring's own cookies don't depend on this, because they go by `APP_URL`. Only trust proxies that you run. A trusted proxy's `X-Forwarded-For` header is believed. That means a client that can reach the app directly could choose its own address. `X-Forwarded-Prefix` and the `Host` header never reach an [emailed link](#links-and-headers), whether or not you trust proxies.

### Secure Cookies

Set `SESSION_SECURE_COOKIE=true` in production. Laravel then marks its session cookie, its CSRF cookie and its "remember me" cookie as `Secure` on every response, whatever the request looked like. Keyring reads the same setting, along with `APP_URL`, to decide about its own cookies.

Keyring's two cookies need nothing from you. Over HTTPS, they're `Secure`, httpOnly and `SameSite=Lax`. They're named `__Host-known_device` and `__Host-remembered_session`. If `SESSION_DOMAIN` shares your cookies with subdomains, or `SESSION_PATH` isn't `/`, the prefix is `__Secure-` instead. See [Keyring's Cookies](devices-and-sessions.md#keyrings-cookies). If you set your own names, with `devices.cookie` or `sessions.remember_cookie`, they're used exactly as written. The prefix is then yours to add.

The session cookie belongs to Laravel, and you choose its name. Give it the prefix as well:

```ini
SESSION_SECURE_COOKIE=true
SESSION_COOKIE=__Host-session
```

A `__Host-` cookie needs `SESSION_PATH=/` and no `SESSION_DOMAIN`, which are Laravel's defaults. If you set a `SESSION_DOMAIN`, use `__Secure-` instead. Laravel names its "remember me" cookie itself (`remember_web_...`), so that one can't be prefixed. That cookie signs nobody in without Keyring's cookie beside it. See ["Remember Me"](devices-and-sessions.md#remember-me).

Keep `SESSION_SAME_SITE` at `lax` or `strict`, and leave `SESSION_HTTP_ONLY` on. With [Single Sign-On](sso.md), keep it at `lax`: with `strict`, the browser leaves the session cookie off the user's return from the provider, so every sign in, link, and confirm through one fails. Keyring's routes use the `web` middleware group, so Laravel's CSRF check covers every route that changes anything. Don't exempt Keyring's paths from it. And if you replace `keyring.middleware`, keep the CSRF check in the list.

### A Content Security Policy

Keyring renders its pages through your app, as Inertia components or Blade views in your own layout. Which scripts, styles and fonts a policy has to allow depends on that layout. So Keyring sends no `Content-Security-Policy`, and your app must send one.

Whatever else your policy says, include `frame-ancestors`:

```
Content-Security-Policy: frame-ancestors 'none'
```

Use `'self'` if your app frames its own pages. Without it, another site can load a page in an invisible frame and line one of its own buttons up over yours. The CSRF token doesn't help there, because the press really does come from your page. `SameSite=Lax` cookies aren't sent to a framed page on another site. That stops the signed-in cases in current browsers. A page that works signed out is still exposed, though.

Keyring's own pages are covered without it. Every Keyring response is sent with `X-Frame-Options: DENY`, and that matters most for these pages:

- the login, challenge and confirm pages, where someone types a password or a code,
- the pages that emailed links open (`reset-password`, `email-verification`, `email-change`, `device-report`). Three of those do their work with one press of a button, and they work signed out.

That header is Keyring's default, and your own policy can take its place. When a Keyring response already carries a `Content-Security-Policy` with `frame-ancestors`, or an `X-Frame-Options` of its own, Keyring adds nothing, because your app has already decided. Keyring's middleware sees the headers that whatever runs inside it has set. That's the route itself, plus any middleware listed after it in `keyring.middleware`. A policy added further out, such as in your `web` group, in global middleware or in your web server, arrives after Keyring has added `DENY`. Browsers then go by `frame-ancestors` and ignore `X-Frame-Options`. So a policy of `'self'` still lets your app frame those pages. Two different `X-Frame-Options` headers on one response are read as `DENY`. So if your web server sends `SAMEORIGIN` everywhere, and you do want to frame Keyring's pages, send it from inside as well, or say so with `frame-ancestors`.

Keyring doesn't add anything to your other pages. So send the policy on every HTML response, with `X-Frame-Options: DENY` (or `SAMEORIGIN`) beside it for older browsers.

### Headers on Your Other Responses

Keyring's middleware (`Keyring\Http\Middleware\AddSecurityHeaders`) only runs on Keyring's routes. You should send `X-Content-Type-Options: nosniff` on the rest of your app too. That way, a browser never treats a response as a type that it doesn't say it is. You should also decide your own `Referrer-Policy` and `Cache-Control` for pages that show account details. A small middleware on your `web` and `api` groups, or your web server's config, can cover all of this.

If you remove Keyring's middleware from `keyring.middleware`, its responses lose `no-store`, `nosniff`, `X-Frame-Options`, their opener policy and their referrer policy, unless your own setup sends them. The pages that emailed links open have a token in their URL, so they need `Referrer-Policy: no-referrer`.

### Bot Checks

Keyring slows guessing down with [rate limits](#rate-limiting). It doesn't try to tell a person from a script. It has no CAPTCHA, no challenge, and no minimum time between showing a form and taking its answer. OWASP ASVS 5.0.0 asks for realistic human timing at Level 3 (2.4.2). OWASP's Authentication Cheat Sheet suggests a CAPTCHA after failed attempts. Which service to use, when to show it, and what to do for the people it gets wrong are your app's decisions. So the check is yours to add.

For signing in, you add the check as a [pipeline step](sign-in-flow.md#writing-a-step) of your own. Put it before the limits, so that a request that fails it is never counted as an attempt on anyone's account:

```php
namespace App\Keyring;

use Closure;
use Illuminate\Validation\ValidationException;
use Keyring\Pipeline\Context;

class CheckForBots
{
    public function __construct(
        protected BotCheck $bots,
    ) {}

    public function handle(Context $context, Closure $next): Context
    {
        // Where a sign in starts. A challenge page only comes after a right password.
        if ($context->identifying && ! $this->bots->passes($context->request)) {
            throw ValidationException::withMessages(['captcha' => __('Please confirm you are not a robot.')]);
        }

        return $next($context);
    }
}
```

```php
// app/Providers/KeyringServiceProvider.php
use Keyring\Pipeline\Steps;
use Keyring\Pipeline\Steps\EnsureNotThrottled;

Keyring::pipeline(fn (Steps $steps) => $steps->before(EnsureNotThrottled::class, CheckForBots::class));
```

`BotCheck` stands in for whatever you use. That might be a CAPTCHA's server-side verification, or a signed timestamp from your form that says how long ago it was shown. The step runs inside the timebox, so a refusal takes as long as any other refusal.

Registration, password reset requests and the other forms don't go through the pipeline. For those, add a middleware of your own to [`keyring.middleware`](configuration.md#routes). It should check the routes you name, such as `register.store` and `password.email`.

## Cryptography

This section covers everything Keyring does with a key or an algorithm, and where it does it. Keyring adds no cipher or hash of its own. Each one listed below belongs to PHP, to Laravel or to a library.

### Keys

| Key | Where It Lives | Used For |
|---|---|---|
| `APP_KEY`, and `APP_PREVIOUS_KEYS` for what was made before a rotation | Your environment | Laravel's encrypter and signed URLs, directly. Keyring never uses it as a key of its own. |
| Five purpose keys, one each for recovery codes, one-time codes, reserved addresses, WebAuthn user handles and the handles a page knows sessions by | Nowhere. They're derived on each use from `APP_KEY` (and each previous key) with HKDF-SHA-256, using the purpose's name as the label | Keyring's keyed hashes. A hash made for one purpose can't pass as another. No hash is made with the key that encrypts. |
| Each authenticator app's TOTP secret, 160 random bits | `keyring_authenticators.secret`, encrypted | Making and checking that app's codes. |
| Each passkey's or security key's public key | `keyring_authenticators.public_key`, as the key sent it | Checking that key's signatures. The private key never leaves the authenticator. |
| Attestation root certificates | Your `webauthn.attestation_roots`, or your `TrustsAuthenticators` | Deciding which makers' keys a factor with `requireAttestation()` takes. |
| The password hash | Your `users` table | Laravel's hasher: see below. |

If you rotate `APP_KEY` and keep the old key in `APP_PREVIOUS_KEYS`, encrypted values, signed links, recovery codes and reserved addresses keep working. See [Known Limitations](#known-limitations) for the short-lived values that rotation ends.

### Algorithms

| Algorithm | Where | What It Protects |
|---|---|---|
| Laravel's encrypter, with your `app.cipher`: AES-256-CBC with an HMAC-SHA-256 tag by default, or AES-256-GCM | The `secret` of an authenticator, which holds TOTP secrets, the set of recovery code hashes, and whatever a code factor of yours keeps there. Also `value` and `previous_value` of a pending change, which hold both addresses. Also pending logins, enrollments and the results flashed for a page in the session, whatever the session driver | Secrets and addresses at rest. |
| Laravel's cookie encryption, the same cipher | The device cookie and the "remember me" pairing cookie, when your `web` group encrypts cookies, as it does by default | Tokens in the browser. |
| HMAC-SHA-256 under a purpose key | Recovery codes; emailed codes, and those of your own code factors, while they wait in the cache to be typed; the lookup hash of an address an email change holds; the WebAuthn user handle; the handle a page knows a session by | Values that are only ever compared or looked up, never read back. |
| SHA-256, unkeyed | Device tokens and email change tokens (confirm, current address, revert) | Long random tokens, so a copy of the table can't be used as one. Each has well over 128 bits, which is why a plain hash is enough. |
| SHA-256, unkeyed | The mark a pending login keeps of the user's password hash and address, inside the encrypted session | Noticing that either changed. Not a secret. |
| None: stored as it is | A session's registry ID, in `keyring_sessions` or the cache | Nothing, on purpose. The ID isn't a credential by itself. It only does anything from inside a Laravel session. That session is kept on the server or, with the `cookie` driver, in a cookie encrypted with `APP_KEY`. The ID also works from inside the "remember me" cookie, which is encrypted the same way and only works beside Laravel's own cookie. Someone who can read the table can make none of those without the key. Laravel keeps its own session IDs and `remember_token` the same way. |
| HMAC-SHA-1, or HMAC-SHA-256 or HMAC-SHA-512 where the factor is [set up with one](factors.md#authenticator-apps-totp) | TOTP codes (RFC 6238), six digits every 30 seconds | A legacy algorithm in OWASP ASVS 5.0.0's Appendix C (requirement 11.4.1). It's kept as the default, because every authenticator app makes it, and several ignore a request for another. |
| Laravel's hash manager, with your `hashing.driver`: bcrypt by default, or Argon2id | Passwords, the hash an unknown account spends, and the reset tokens Laravel's broker stores | Keyring calls `Hash` and never picks the algorithm or its cost. |
| ECDSA with P-256 and SHA-256 (ES256), Ed25519 (EdDSA), and RSASSA-PKCS1-v1_5 with SHA-256 (RS256, off by default, 2048 bits at least) | Signatures from passkeys and security keys, limited to [`webauthn.algorithms`](passkeys.md#signature-algorithms) | Proof of holding the key. SHA-256 also hashes the client data and the relying party ID, as WebAuthn defines. |
| X.509 path validation: ECDSA, Ed25519, Ed448 or RSASSA-PKCS1-v1_5 signatures over SHA-224 or longer, RSA keys of 2048 bits at least, never SHA-1 | Attestation chains, only for a factor with [`requireAttestation()`](passkeys.md#requiring-attestation) | Which maker's key this is. The algorithms are whatever the maker signed its certificates with. So this accepts RSA with PKCS #1 v1.5 padding, which ASVS doesn't approve. Several makers' roots use it (requirement 11.6.1). Off by default. |
| HMAC-SHA-256 with `APP_KEY`, by Laravel's URL signing | The email verification link and the "this wasn't me" link | That the link was made by your app, for that route, and hasn't expired. |
| SHA-1, unkeyed | The address in Laravel's email verification link; shortening the cache keys of the rate limits, sent codes and enrollments; and the breached-password lookup, where Have I Been Pwned's API is asked by the first five characters of a SHA-1 | Nothing rests on it. The link is signed as above, a cache key isn't a secret, and the lookup is the API's own format, whether Laravel makes it or Keyring does (`passwords.refuse_unchecked`). |

### Random Values

Every random value comes from the operating system's generator, through PHP's `random_bytes()` and `random_int()`. `Str::random()` is built on `random_bytes()`. Nothing uses `rand()`, `mt_rand()` or `uniqid()`.

| Value | Made With | Size |
|---|---|---|
| Recovery codes | `random_bytes(16)` | 128 bits each |
| WebAuthn challenges | `random_bytes(32)` | 256 bits |
| TOTP secrets | `random_int()`, 32 base32 characters | 160 bits |
| Device tokens | `Str::random(40)` | About 238 bits |
| Session registry IDs, one of which is the "remember me" pairing | `Str::random(40)` | About 238 bits |
| Pending login IDs, enrollment IDs and the reference a sent code is kept under | `Str::random(40)` | About 238 bits |
| Email change tokens | `Str::random(48)` | About 285 bits |
| Laravel's "remember me" token, when Keyring replaces it | `Str::random(60)` | About 357 bits |
| WebAuthn user handles | HMAC-SHA-256 of the user's model and ID under a purpose key, not random | 256 bits, and not guessable without `APP_KEY` |
| Emailed codes | `random_int()` | Eight digits, about 27 bits. Short on purpose: they last 10 minutes and allow five guesses. |
| The password an unknown account's hash is spent on | `Str::random(32)` | Thrown away. |

### Changing an Algorithm

| To Change | How | What Happens to Stored Values |
|---|---|---|
| The password hash or its cost | `hashing.driver` and its options | Nothing to re-make. Each password is rehashed the next time its owner signs in. |
| `APP_KEY` | Set the new key, with the old one in `APP_PREVIOUS_KEYS` | Encrypted values are read with the old key and written with the new one as they're next saved. Recovery codes and reserved addresses are found under either. A sent code waiting to be typed stops working, and the user asks for another. |
| The cipher | `app.cipher` | Laravel only reads what the current cipher wrote. So every authenticator secret and pending change has to be decrypted and saved again, in a migration of your own, before the old cipher goes. Pending logins and enrollments end. |
| The WebAuthn algorithms | `webauthn.algorithms` and `webauthn.minimum_rsa_bits` | Adding one changes nothing stored. Removing one refuses the keys that sign with it, so their owners have to add a new key. A key's algorithm can't be changed. |
| The TOTP digest | The factor's `algorithm` | Only apps added afterwards use it. An authenticator keeps the digest it was set up with, so moving everyone means each user adding their app again. |
| The keyed hash (HMAC-SHA-256) or how its keys are derived | Fixed in code | A new release would have to re-make them. Reserved address hashes can be recomputed from the encrypted address. Recovery codes can't be, since only the hash is kept, so they would be issued again. A WebAuthn user handle stays for as long as the user has a key that knows it. |
| The token hash (SHA-256) | Fixed in code | Tokens can't be rehashed, since only the hash is kept. Device cookies and pending email change links would be issued again. |

Those last two are where Keyring falls short of OWASP ASVS 5.0.0's requirement 11.2.2, which says that any algorithm can be swapped. Keyring's stored hashes carry no tag saying which scheme made them. So a release that changed one couldn't keep the old and the new side by side. It would have to re-make what can be re-made, and issue the rest again, as the table says. A tag is only worth having on the day of such a change. Neither algorithm has a weakness to move away from, so Keyring doesn't carry one yet.

### Peppering Passwords

NIST SP 800-63B-4 recommends (Sec. 3.1.1.2) that, beyond the salted hash, you add a keyed hash or encryption of it. The secret used for that should be kept apart from the database. That's often called a pepper. OWASP's Password Storage Cheat Sheet suggests the same. Keyring doesn't build one in, for three reasons. First, the password hash is your `users.password` column and Laravel's hasher. Everything else in your app that checks a password shares them. So a pepper that only Keyring knew about would break those checks. Second, a pepper is only worth having when its key lives somewhere the database's attacker can't reach. Where that is, such as an HSM, a secrets manager or at least a separate environment variable, is your infrastructure's decision. Third, losing or rotating a pepper locks out every user at once. So it needs a plan, and that plan belongs to whoever runs the app.

Keyring checks and sets passwords through Laravel's `Hash`. So a pepper added there covers every flow, including signing in, confirming, password changes, resets and the rehash at sign in. Register a driver that wraps the one you use now:

```php
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Support\Facades\Hash;

class PepperedHasher implements Hasher
{
    public function __construct(
        protected Hasher $hasher,
        #[\SensitiveParameter] protected string $pepper,
    ) {}

    public function make(#[\SensitiveParameter] $value, array $options = []): string
    {
        return $this->hasher->make($this->pepper($value), $options);
    }

    public function check(#[\SensitiveParameter] $value, $hashedValue, array $options = []): bool
    {
        return $this->hasher->check($this->pepper($value), $hashedValue, $options);
    }

    public function info($hashedValue): array
    {
        return $this->hasher->info($hashedValue);
    }

    public function needsRehash($hashedValue, array $options = []): bool
    {
        return $this->hasher->needsRehash($hashedValue, $options);
    }

    // Base64, because a raw HMAC can hold a NUL byte, where bcrypt stops reading.
    protected function pepper(#[\SensitiveParameter] string $value): string
    {
        return base64_encode(hash_hmac('sha256', $value, $this->pepper, true));
    }
}

// In a service provider's boot().
Hash::extend('peppered', fn () => new PepperedHasher(
    Hash::driver('argon2id'),
    config('services.password_pepper'),
));
```

Then set `hashing.driver` to `peppered`. Three things need settling first:

- **Existing passwords.** A hash made without the pepper won't match once the pepper is added. You can either have `check()` fall back to the bare hasher and report `needsRehash()` for those hashes, so that each one moves over at its owner's next sign in. Or you can add the pepper before there are any users.
- **Rotation.** Changing the pepper means changing every hash. Keep the old pepper to check against, and rehash on sign in, as above.
- **Length.** The HMAC is 44 characters whatever was typed. So bcrypt's 72 byte limit no longer cuts a long password short. Keyring's [password rules](protected-changes.md#password-rules) follow `hashing.driver`. So with a driver other than `bcrypt`, they stop refusing passwords over 72 bytes. A password over 72 bytes is still refused at sign in while its stored hash is a bcrypt one. That's because Keyring can't tell a peppered bcrypt hash from a plain one. So wrap Argon2id rather than bcrypt, or keep new passwords to 72 bytes with a rule of your own.

## What a Request Costs

The operations below are the expensive ones. For each, the table shows what stops a stranger from running it without limit. All of it happens inside a request. Keyring starts no background work, apart from the emails noted below.

| Operation | When | What Bounds It |
|---|---|---|
| One password hash (bcrypt or Argon2id, at your cost setting) | Every password attempt the limits let through, including for a name with no account, which spends a hash on a random password so both take the same time | The [rate limits](#rate-limiting) are checked first. That's 5 a minute per account and per typed name, and 20 a minute per IP address, with locks that double. An attempt that the IP address's limit refuses hashes nothing. An attempt that the account's own limit refuses quietly still spends a hash, so it takes as long as a wrong password does. An attempt that a typed name's limit refuses with a `429` does the same. Behind a refused name, the password is either checked or a hash is spent in its place. So the `429` costs the same whether the name has an account, and whether that account's limits were cleared since. The IP address's limit bounds how many of those one address can ask for. Hashing a new password on registration, a change or a reset is behind the `keyring` limiter, at 6 a minute. |
| A worker held for `timebox` (500ms) | Every refused verification, a `429` included | It's a sleep rather than CPU work. But it does hold a PHP worker, and Keyring doesn't bound how many workers that is. A rate-limited request waits like any other refusal, or the limits would show in the timing. What bounds it sits in front of PHP. That's the connection and request limits of your web server or load balancer, and the size of the worker pool. Lowering `timebox` gives each worker back sooner, but it makes timing less even. |
| The breached-password lookup, an HTTPS request to Have I Been Pwned | Setting a password, in production by default (`passwords.uncompromised`). Also at every password sign in, if you add the `BreachedPassword` risk signal, which isn't on by default | Behind the `keyring` limiter for new passwords, and behind the sign in limits for the signal. Laravel's verifier gives up after 30 seconds and then lets the password through. So an outage slows these requests rather than failing them. With `passwords.refuse_unchecked`, Keyring makes the request itself. It gives up after 10 seconds and refuses the password. If that's too long to hold a worker, turn the check off. Or bind an `UncompromisedVerifier` of your own with a shorter timeout. |
| WebAuthn verification: decoding the response and checking one signature | Adding a key, and every sign in or step-up with one | At sign in, the factor's rate limits, which are checked before the response is read. Adding a key is behind the `keyring` limiter and a fresh verification. Usernameless options are limited to 60 a minute per IP address. An RSA key is bounded to 16,384 bits by the library, since the work grows with the key size. |
| Attestation: a certificate chain of at most six, checked against each root you list for the model | Adding a key to a factor with `requireAttestation()` | The `keyring` limiter on enrollment, the cap on chain length, and nothing being fetched: no revocation lookups, no metadata download. |
| Mail | A reset link, an email change, a verification link, an emailed code, a security notice | Reset and email change mail is sent after the response. A verification link and an emailed code are sent during the request, unless you queue those notifications. A code is limited to three per factor every 10 minutes per account (`limits.codes`), and the routes that send one (a challenge, a confirmation, or enrolling a code factor) aren't behind the `keyring` limiter. The other routes that ask for mail are. The security notices are queued after the commit, and they're limited to five of a kind an hour per account (`limits.notices`). |
| The risk signals' lookups: a few indexed queries on the security log, the account's devices and its sessions | A sign in that gets its first factor right, for the signals the published provider turns on, and one comparison of browser names on each signed-in request | They run after a correct first factor, and the rate limits bound that. Each signal is a line in your provider that you can take out. |
| Calls to an identity provider: its discovery document and keys, the token endpoint, and for GitHub its API, each with a 5 second connect and a 10 second timeout | Sending a user to a provider, and the callback that brings them back | The redirect route is behind the `keyring-login-options` limiter, 60 a minute per IP address, and starting a link is behind a fresh verification. The callback calls nothing until it has found a request its own session started, which it uses up, and a browser keeps five at most. Discovery documents and keys are cached for `sso.cache_for`, and read again for a key Keyring hasn't seen at most once a minute per provider. No redirect is followed. Before calling a token endpoint or key set on another host than the issuer's, Keyring looks its name up (`HostResolver`, once a host per request) to check it isn't inside your network. A lookup has no timeout of its own: it waits as long as the server's resolver does, and one that fails counts as resolving to nothing. |
| A session lock | Sign in, challenge, enrollment and single sign-on routes | Requests in one session wait for each other, for up to Laravel's 10 seconds. A request that waits that long fails. One session can't hold up another. |

## Standards

Keyring's code and config show what each thing does. This section explains where the choices come from. If a row says Keyring departs from a requirement, the reason is under [Known Limitations](#known-limitations). The [OWASP ASVS and NIST SP 800-63B](owasp-asvs.md) page works the other way round. It lists every requirement, and what Keyring does about each one.

| What Keyring Does | From |
|---|---|
| **Assurance levels and sessions** | |
| Assurance levels, and what reaches AAL2 and AAL3, as far as a library can check. AAL2 takes two kinds of factor, one of them something the user has. AAL3 takes an attested key that can't leave its device, with its own user verification or a password. Validated authenticators and verifier cryptography, which NIST AAL3 also needs, are yours to supply | NIST SP 800-63B-4, Sec. 2.2.1, 2.3.1, 2.3.2 and Appendix B |
| Each level lapsing after idle and overall limits (AAL2: 1 hour, 24 hours; AAL3: 15 minutes, 12 hours). The session carries on at the level that's left, or ends with `sessions.end_on_lapse` | NIST SP 800-63B-4, Sec. 2.2.3, 2.3.3, 5.1 and 5.2. Carrying on departs from Sec. 5.2 |
| An idle and an absolute timeout on every session, kept on the server, with a longer idle one for "remember me" as a stated decision | OWASP ASVS 5.0.0, 7.3.1 and 7.3.2, and OWASP's Session Management Cheat Sheet. "Remember me" departs from NIST SP 800-63B-4, Sec. 5.1 |
| A new session ID, and the old session ended, on every sign in and step-up | OWASP ASVS 5.0.0, 7.2.4 |
| A session that is signed out, revoked or timed out can't be used again | OWASP ASVS 5.0.0, 7.4.1 |
| A deleted user's sessions end with them, and an account the app keeps out loses all of its sessions the first time one of them makes a request | OWASP ASVS 5.0.0, 7.4.2 (for ending them sooner, see [Who May Sign In](sign-in-flow.md#who-may-sign-in)) |
| A stated number of sessions per account, and what happens at it | OWASP ASVS 5.0.0, 7.1.2 |
| The option to end other sessions after any change to a sign-in method | OWASP ASVS 5.0.0, 7.4.3 |
| A command for administrators to end one user's sessions or everyone's | OWASP ASVS 5.0.0, 7.4.5 |
| Users seeing their sessions, and ending any or all of them after verifying again | OWASP ASVS 5.0.0, 7.5.2 |
| A "remember me" cookie that works once, with a used one ending the session | Refresh token rotation with reuse detection (RFC 9700, Section 4.14.2), applied to a cookie, and OWASP's Session Management Cheat Sheet for revoking every rotated ID of a session together |
| **Rate limits** | |
| A cap of 100 failures in a row on each of an account's authenticators, kept in the database, after which it's refused until it's set up again. A lower number for browsers the account hasn't signed in from is one of the additional, risk-based techniques NIST allows for keeping an attacker from locking the owner out. `Keyring::unlock()` switches an authenticator back on without binding it again, which NIST doesn't provide for | NIST SP 800-63B-4, Sec. 3.2.2 |
| Locks that double each time, and a count of its own for the browsers the account has signed in from | OWASP's Authentication Cheat Sheet (exponential lockout) and the OWASP Community page "Slow Down Online Guessing Attacks with Device Cookies", adapted: known browsers share one bucket, and the cookie is a random token stored hashed |
| Limits per account, per typed username and per IP address on every factor, and a limiter on the other forms | OWASP ASVS 5.0.0, 2.4.1 and 6.3.1, and OWASP's Credential Stuffing Prevention Cheat Sheet |
| **Passwords** | |
| Password lengths of 8 with a second factor and 15 without, with no setting below 8 | OWASP ASVS 5.0.0, 6.2.1, and NIST SP 800-63B-4, Sec. 3.1.1.2 (15 for a password used alone, 8 as part of multi-factor) |
| A password change taking the current password as well as the new one | OWASP ASVS 5.0.0, 6.2.3 |
| Refusing the most common passwords: the top 10,000 of 8 characters or more and the top 3,000 of 15 or more | OWASP ASVS 5.0.0, 6.2.4 (at least the top 3,000 that fit the policy) |
| No composition rules, and any characters accepted | OWASP ASVS 5.0.0, 6.2.5, and NIST SP 800-63B-4, Sec. 3.1.1.2 |
| Passwords of at least 64 characters allowed and never silently cut short. The limit is `passwords.max` with argon2id, or 72 bytes with bcrypt | OWASP ASVS 5.0.0, 6.2.9, and NIST SP 800-63B-4, Sec. 3.1.1.2. Met with `HASH_DRIVER=argon2id`, not with bcrypt |
| Refusing passwords made up of the app's name, the words in `passwords.context`, or the user's name and email address, comparing the whole password | OWASP ASVS 5.0.0, 6.2.11, with 6.1.2 for the list, which is yours to fill in; NIST SP 800-63B-4, Sec. 3.1.1.2, for comparing the whole password |
| Refusing breached passwords, in production by default | OWASP ASVS 5.0.0, 6.2.12, and NIST SP 800-63B-4, Sec. 3.1.1.2 |
| Passwords of any Unicode characters, normalised to NFC before hashing | NIST SP 800-63B-4, Sec. 3.1.1.2. This departs from the letter of OWASP ASVS 5.0.0, 6.2.8 (verified exactly as received): nothing is truncated or has its case changed, but the bytes are normalised |
| Passwords never expiring, and a user held until they choose a new one on evidence of compromise: when your app says so, and by default when the `BreachedPassword` signal finds the password used in a breach | NIST SP 800-63B-4, Sec. 3.1.1.2 |
| **Factors and codes** | |
| Passkeys and security keys as a phishing-resistant option | NIST SP 800-63B-4, Sec. 2.2.2 and 3.2.5 |
| Email codes being opt-in, and counting toward no level: a password and an emailed code is AAL1 | NIST SP 800-63B-4, Sec. 3.1.3.1, which doesn't accept email as an authenticator, and OWASP ASVS 5.0.0, 6.3.6 |
| Two factors of the same kind not counting as two, and no weaker fallback for a user with a phishing-resistant factor | OWASP's Multifactor Authentication Cheat Sheet |
| Making everyone add a second factor with `keyring.enrolled`, which the installer sets up once a second factor is picked | OWASP ASVS 5.0.0, 6.3.3 |
| Proving the strongest combination the account can give before adding a sign-in method, whatever the sign-in policy asks | NIST SP 800-63B-4, Sec. 4.1.2.1 |
| A recent verification before changing how someone signs in | OWASP's Authentication Cheat Sheet, and OWASP ASVS 5.0.0, 7.5.1 |
| Single-use codes: random, short-lived, limited guesses, stored hashed, a resend replacing the last, and bound to the sign in they were sent for | OWASP's Multifactor Authentication Cheat Sheet (One-Time Password Handling and Storage), and OWASP ASVS 5.0.0, 6.6.2 and 6.6.3 |
| TOTP codes, recovery codes and sent codes that work once, whatever the session driver | OWASP ASVS 5.0.0, 6.5.1 |
| Recovery codes with at least 112 random bits, which is what lets them be kept as keyed hashes rather than salted password hashes | OWASP ASVS 5.0.0, 6.5.2 |
| Sent codes of at least six digits, that last ten minutes at most | OWASP ASVS 5.0.0, 6.5.4 and 6.5.5 |
| TOTP codes accepted one time step either side of now, and no further | RFC 6238, Section 5.2 (one step back for delay) and Section 6 (a limit on drift either way). This default departs from OWASP ASVS 5.0.0, 6.5.5 (a 30 second maximum), which a window of zero meets |
| A passkey challenge of 32 random bytes that runs out on the server and is answered once | OWASP's Passkey Security Cheat Sheet, and OWASP ASVS 5.0.0, 6.7.2 |
| A sign-in method presented with when it was added and last used | OWASP's Passkey Security Cheat Sheet |
| ES256 and EdDSA signatures by default, and RS256 only when asked for, with keys of 2048 bits at least | OWASP ASVS 5.0.0, 11.2.3 and 11.6.1, and RFC 8812, Section 2 |
| **Notices and risk** | |
| The emails Keyring sends about changes: password changed, sign-in method added or removed, recovery code used, new recovery codes, and with `Features::emailChanges()`, email address changed and an email change undone | NIST SP 800-63B-4 (Sec. 4.1.2.1, 4.2.1.1, 4.2.3, 4.5 and 4.6), OWASP's Forgot Password, Multifactor Authentication and Passkey Security Cheat Sheets, and OWASP ASVS 5.0.0, 6.3.7 |
| The emails it sends about suspicious attempts. These cover a failed second factor, a sign in after several failures or a long quiet period, a sign in from an address where other accounts failed (with the `CredentialStuffing` signal), an account locked, what the risk signals add up to, and, with `Features::devices()`, a new device | OWASP ASVS 5.0.0, 6.3.5, and OWASP's Multifactor Authentication and Credential Stuffing Prevention Cheat Sheets |
| A line saying who to contact in every security notice, the emailed code and the email change notice, once `support_contact` is set | NIST SP 800-63B-4, Sec. 4.6 |
| Risk signals in the published provider, at sign in and on every request. These cover failure history and a session changing browser as installed, and, with `Features::devices()`, the device signals | OWASP ASVS 5.0.0, 8.2.4, and OWASP's Authentication and Session Management Cheat Sheets |
| A second factor asked for when a correct password comes from an IP address where several other accounts have just failed, with the `CredentialStuffing` signal, which is off until you turn it on | OWASP's Credential Stuffing Prevention Cheat Sheet (asking for MFA from "an IP address that has tried to login to multiple accounts") |
| **Account changes and registration** | |
| Registration that answers the same for every address | OWASP ASVS 5.0.0, 6.3.8 |
| Password resets: the same answer for every address, links built from `APP_URL`, no automatic sign in, every session signed out, second factors left as they are | OWASP's Forgot Password Cheat Sheet, and OWASP ASVS 5.0.0, 6.4.3 |
| The conformance suite failing an app whose password broker has no `throttle` | OWASP's Forgot Password Cheat Sheet (rate limiting per account) |
| Email changes confirmed from both addresses, and not trusting an address that has recently changed | OWASP's Authentication Cheat Sheet (changing a registered email address) and Forgot Password Cheat Sheet (recovery after suspected compromise) |
| **Headers, cookies and links** | |
| Never caching auth pages and responses | OWASP's Session Management Cheat Sheet |
| `X-Content-Type-Options: nosniff` and a referrer policy on every Keyring response | OWASP ASVS 5.0.0, 3.4.4 and 3.4.5 |
| `X-Frame-Options: DENY` on every Keyring response, unless the app's own policy says who may frame it | OWASP's Clickjacking Defense Cheat Sheet. OWASP ASVS 5.0.0, 3.4.6, asks for `frame-ancestors` in a content security policy, which is your app's to send |
| `Secure` cookies with the `__Host-` prefix | OWASP ASVS 5.0.0, 3.3.1 and 3.3.3, and OWASP's Session Management Cheat Sheet |
| Cookie names that say what the cookie is for and not what set it (`known_device`, `remembered_session`) | OWASP's Session Management Cheat Sheet, on session ID name fingerprinting |
| No referrer from pages whose URL holds a token | OWASP's Forgot Password Cheat Sheet |
| Emailed links that only act on a `POST`, with the token or signature in its body | OWASP ASVS 5.0.0, 3.5.3, and 14.2.1 for the request that acts (the emailed link itself still has to carry its token in the URL once), and OWASP's Cross-Site Request Forgery Prevention Cheat Sheet |
| Passwords, codes, credentials and tokens read from the body, never the query string of a `POST` | OWASP ASVS 5.0.0, 14.2.1 and 15.3.7 |
| The browser package encoding what it puts in a URL path | OWASP ASVS 5.0.0, 1.2.2 |
| Keyring's own breached-password lookup following no redirect (the default lookup is Laravel's, which follows them) | OWASP ASVS 5.0.0, 15.3.2 |
| A `Cross-Origin-Opener-Policy` on every Keyring response | OWASP ASVS 5.0.0, 3.4.8 |
| **Logging and storage** | |
| Logging sign ins, failures, lockouts, sessions "remember me" carried on and session ends by default, and what was refused. That covers someone else's record, a link's token or signature, a rate-limited form and a skipped pipeline step | OWASP ASVS 5.0.0, 16.3.1 to 16.3.3 |
| A severity and a request ID on every entry, no secrets in any, and a cap on entries a refused request can cause | OWASP's Logging Cheat Sheet |
| A list of what's stored and how it's protected, deleted on a schedule Keyring sets up itself | OWASP ASVS 5.0.0, 14.1 and 14.2.7 |

## Known Limitations

### Where Keyring Departs From a Standard

Each of these is a choice. The reason is given once, here, and the [requirement-by-requirement page](owasp-asvs.md) says what each means for an app that has to meet the requirement.

- **A default install doesn't require a second factor.** Keyring starts with the password, and it leaves the rest for you to turn on. So with the installer's default answers, there's nothing to require, and OWASP ASVS 5.0.0's requirement 6.3.3 (Level 2) isn't met. You choose which second factor your users get. If you pick one, the installer requires it of everyone, unless you say otherwise. The published provider has each one commented out, for an app that adds it later.
- **Not every suspicious sign in is announced out of the box.** OWASP ASVS 5.0.0's requirement 6.3.5 lists a sign in from an unusual client or place among them. Keyring only knows about a new device and a long quiet period with `Features::devices()`. It only knows about a place with a locator that you supply. So a default install announces neither. A sign in after several failures is announced from the start. A failed second factor is announced once there is one.
- **Passwords are normalised before they're hashed.** OWASP ASVS 5.0.0 requirement 6.2.8 has a password verified exactly as received. Keyring cuts nothing short and changes no case. But it does put every password in Unicode's NFC form first, as NIST SP 800-63B-4 recommends (Sec. 3.1.1.2). The same "é" is one code point on some keyboards and two on others. Without this step, a password set on one device could fail on another.
- **Bcrypt stops passwords at 72 bytes.** It's Laravel's default hasher, and it ignores everything after the first 72 bytes. So with bcrypt, Keyring refuses a longer password. That's 72 plain characters, but as few as 18 emoji, whatever `passwords.max` says. OWASP ASVS 5.0.0 requirement 6.2.9 asks for at least 64 characters, of any kind, to be allowed. NIST SP 800-63B-4 recommends the same (Sec. 3.1.1.2). To meet that, set `HASH_DRIVER=argon2id`. Keyring doesn't pre-hash passwords to make them fit. Doing so would leave hashes that Laravel's own hasher can't check. See [Passwords](configuration.md#passwords).
- **By default a TOTP code works for longer than OWASP ASVS allows.** ASVS 5.0.0 requirement 6.5.5 gives a time-based one-time password a maximum lifetime of 30 seconds. Keyring accepts a code one time step either side of now, unless you say otherwise. So one code can work for up to about 90 seconds. As shipped, Keyring doesn't meet that requirement. The default follows RFC 6238. That RFC recommends accepting one earlier step, to allow for the time a code takes to arrive (Section 5.2). It also allows a limit on clock drift either way (Section 6). With no window, a code typed near the end of its 30 seconds fails. So does every code from a phone whose clock is half a minute out. A code still works only once. To meet 6.5.5 exactly, register the factor with [a window of zero](factors.md#authenticator-apps-totp). A window wider than one step is refused.
- **TOTP codes are made with HMAC-SHA-1.** OWASP ASVS 5.0.0 lists it as a legacy algorithm (Appendix C, requirement 11.4.1). It's the default because it's the only digest that every authenticator app makes. Several apps ignore a request for another digest without saying so. That would leave their users with codes that never work. Where you know your users' apps, [set the factor up with SHA-256 or SHA-512](factors.md#authenticator-apps-totp).
- **Windows Hello keys that only sign RS256 aren't taken by default.** RS256 isn't an algorithm that OWASP ASVS approves. So `webauthn.algorithms` leaves it out. On a machine whose Windows Hello makes nothing else, a passkey can't be created with it. See [RS256 and Windows Hello](passkeys.md#rs256-and-windows-hello) for who that affects and how to turn it on. Turning it on takes Keyring outside ASVS's requirements 11.2.3 and 11.6.1, and so does requiring attestation, whose makers sign their certificates the same way.
- **ID tokens signed with RS256 are accepted from identity providers.** Google and Microsoft sign with nothing else, so [single sign-on](sso.md#security-notes) takes RS256 as well as PS256, ES256 and EdDSA, though OWASP ASVS 5.0.0 (11.6.1) doesn't approve its padding. It only applies once you register the `SingleSignOn` factor.
- **Attestation is off unless you ask for it, only covers hardware keys, and checks no revocation list.** By default, any WebAuthn authenticator is accepted, and AAGUIDs aren't verified. So no session reaches AAL3. A factor set up with `requireAttestation()` checks `packed` and `fido-u2f` attestation against root certificates that you list. It can then be limited to certain models. Platform formats (`tpm`, `android-key`, `apple`) aren't read. OWASP's Passkey Security Cheat Sheet also expects a verifier to check a chain's status. Keyring fetches nothing while a key is being added. So a maker's certificate that has been revoked is still accepted, until you take its root out of your list. See [Attestation and AAGUIDs](passkeys.md#attestation-and-aaguids).
- **A used recovery code isn't replaced automatically.** NIST SP 800-63B-4 (Sec. 4.2.1.1) calls for a new code to be issued after each use. Keyring uses the code up and stops there. A new code is only worth something once its owner has seen and saved it, and a sign in isn't the place to show it. The set reports that a code has been used, through `shouldReplaceRecoveryCodes()`. The rule is met once your app sends the user to [make a new set](authenticators.md#recovery-codes).
- **"Remember me" signs a browser back in without a factor.** NIST SP 800-63B-4 (Sec. 5.1) doesn't accept a cookie in place of authentication. A browser that ticked "remember me" comes back signed in after its session has idled out, for up to 14 days (`sessions.remember_idle`). That's what the checkbox is for. Keyring ties the cookie to the session it was ticked for, and it lets the cookie work once. The session it resumes gets no assurance level. So routes behind `keyring:aal1`, `keyring:aal2` or `keyring.fresh` ask the user again. A route behind `auth` alone, however, is reached on the cookie. If you follow that section of NIST, leave the checkbox off your login form, or set `sessions.end_on_lapse`. See [Inactivity and "Remember Me"](devices-and-sessions.md#inactivity-and-remember-me).
- **A session outlives its assurance level.** NIST SP 800-63B-4 (Sec. 5.2) ends a session when its inactivity or overall timeout passes. By default, Keyring lowers the session's level instead. A session that signed in with two factors stops being AAL2 after an hour idle, or after 24 hours, and carries on as AAL1. It stays under the limits that every session has. Sec. 5.1 allows a session to be treated as a lower level. Ending the session would sign out people who set up a second factor after an hour away, while leaving everyone else signed in for 30 days. Set `sessions.end_on_lapse` to end it instead. See [Ending a Session With Its Level](devices-and-sessions.md#ending-a-session-with-its-level).
- **An account has one email address.** NIST SP 800-63B-4 asks for at least two addresses to send notices to (Sec. 4.6). It also asks for two to recover an account through (Sec. 4.2.1.2). Keyring knows the one in your user model's `email` attribute. That's where reset links, emailed codes and security notices go. A library with one attribute to read can't supply a second. To send every notice to more than one address, return them from `routeNotificationForMail()`. [A Support Contact](security-log-and-emails.md#a-support-contact) shows how. A second address that can recover the account, and that is verified before it's used, is yours to build.
- **A notice doesn't say who to contact until you say where.** NIST SP 800-63B-4 (Sec. 4.6) expects a notice to carry contact information. Keyring's notices include that line, but they leave it out while [`support_contact`](security-log-and-emails.md#a-support-contact) is `null`. Only you know where your support is.
- **No pepper.** NIST SP 800-63B-4 (Sec. 3.1.1.2) and OWASP's Password Storage Cheat Sheet recommend one. See [Peppering Passwords](#peppering-passwords) for why it isn't built in and how to add it.
- **The breach check fails open by default.** Laravel's check lets a new password through when Have I Been Pwned can't be reached, leaving only the bundled list of common passwords, so that an outage elsewhere doesn't stop registrations. OWASP ASVS 5.0.0's requirement 16.5.3 counts a check that passes on an error as failing open. Requirement 16.5.2 asks that the app stays secure when an outside service fails. To refuse the password instead, set `passwords.refuse_unchecked`. The cost is that no new passwords can be set while the service is unreachable. Outside production, the check doesn't run at all unless `passwords.uncompromised` is `true`.
- **The per-minute limits are kept in the cache.** Clearing the limiter's cache store starts the per-minute counts over. It also lifts their locks and risk locks. OWASP ASVS 5.0.0's requirement 16.5.3 counts that as failing open. A count on every attempt belongs somewhere fast. What ends guessing doesn't depend on that cache, though. The failures in a row and the locks held until a reset are in your database. See [Rate Limiting](#rate-limiting).
- **An emailed link carries its token in its URL.** It has to, and OWASP ASVS 5.0.0's requirement 14.2.1 doesn't allow for that. See [Tokens in Emailed Links](#tokens-in-emailed-links) for what Keyring does about it, and for why the reset link carries the address too.
- **Stored hashes don't say which scheme made them, and session registry IDs aren't hashed.** See [Changing an Algorithm](#changing-an-algorithm) and [Algorithms](#algorithms).
- **Form validation failures aren't logged.** OWASP ASVS 5.0.0's requirement 16.3.3 and OWASP's Logging Cheat Sheet list them among what to log. A missing field or a malformed address is an ordinary mistake. It says nothing about an attempt on an account. Logging each one would bury the entries that do matter. Everything Keyring refuses for a reason is logged.
- **The log table's times have no offset.** OWASP ASVS 5.0.0's requirement 16.2.2 wants UTC or an explicit offset. `keyring_events.created_at` is a plain timestamp in your `app.timezone`, as every Laravel timestamp is. So leave `app.timezone` at UTC, its default. See [Times](security-log-and-emails.md#times).
- **A disabled account's sessions end when one of them is next used.** OWASP ASVS 5.0.0's requirement 7.4.2 asks for them to end when the account is disabled. Keyring doesn't know that moment, because the flag is your app's. So call `Sessions::signOutEverywhere()` as you set it. See [Who May Sign In](sign-in-flow.md#who-may-sign-in).
- **No bot check.** See [Bot Checks](#bot-checks).

### Other Limits

- **A fresh session can still add a sign-in method, and make one change.** Signing in counts as a fresh verification for 15 minutes. Whoever has a copy of the session cookie in that time can add a passkey or authenticator app of their own, without proving anything, to an account that already has an established second factor. A password-only account, or one whose second factors are all new, needs [the password](authenticators.md#the-password-for-a-first-second-factor) for it. Before the owner notices, that factor signs in like any other. It doesn't make `noDowngrade()` ask for a passkey for 7 days. The owner can remove it while it's new, whatever else is frozen, as long as they can still sign in and pass a fresh verification with what they had. Once it's established, removing it is like removing any other. Nothing established can be removed or replaced while it's there, unless the request proves an established key, which the copy doesn't have. If the account had nothing new, the copy can make one change first: remove one established authenticator that isn't the last second factor, or replace established recovery codes. That freezes everything else for 7 days. While nothing is frozen it can rename sign-in methods too, which freezes nothing, so a settings page should show when each was added. An owner with an established passkey or security key can still put things right during that time, by proving it for each change. An owner without one waits. A new authenticator that the owner doesn't remove becomes established after 7 days, so the [security emails](security-log-and-emails.md) for a new sign-in method and new recovery codes matter. Set [`authenticators_url`](configuration.md#account-changes-and-enrollment) so they link to where the owner can remove it. Keyring can't tell a copied cookie from the real one. Binding a session to its device, as Device Bound Session Credentials do, is up to the browser or your app.
- **A proof for new recovery codes is kept with their enrollment.** The codes are shown when they're begun, so that's where the proof goes, and the password for a first second factor too. The enrollment remembers it, and the confirm that saves them needs nothing more. A copy of the session taken between the two could confirm that one enrollment, saving the codes the owner was shown, before the owner did. It can't see them, and it can't use the proof for anything else.
- **`skip_with_totp` lets a phished code make a change.** With it on, a code from an established authenticator app can make one change while the account is frozen. Whoever phishes a code from the owner as it's typed, and holds the session, could use it that way. That's why it's off.
- **A new account has nothing established.** Every authenticator on an account set up in the last 7 days is new, so any of them can be removed while the account is frozen. That includes the owner's. The freeze only protects what the account has had for a while. Adding another second factor to such an account takes the password, so a copy of the session can't add one unless the account has no password.
- **An account without a password can't be asked for one.** One that signs in with a passkey alone, or with an identity provider, or an app without the `Password` factor, adds a second factor on the fresh verification, as before. While its own passkey is new, a copy of a session that just signed in could add one too, and Keyring can't tell them apart. Once the owner's key is established, a session's new key can't freeze it out. Under an `ifEnrolled()` policy, a factor added without the password being checked for it isn't asked for at sign in until it's established, and that holds after a password reset gives the account a password, so one a copy added can't shut the owner out either. The copy can also set the account's first password, since there's none to type. That password isn't established for 7 days: it freezes the account, it isn't asked for at sign in, and adding a factor doesn't take it, so a factor added with it is no more asked for than one added without. A reset, which unlinks every identity provider, makes the owner's new password established. Once 7 days pass without the owner noticing, the copy's password and anything added with it count like the owner's, so the [security emails](security-log-and-emails.md) for a new sign-in method and a changed password matter here too.
- **The owner's own new key isn't asked for at first.** For 7 days after a passkey or security key is added, `noDowngrade()`, an `ifEnrolled()` policy and a fresh verification don't ask for it, so the owner's password and authenticator app keep working. An `ifEnrolled()` policy doesn't ask for any other new factor beside an established second factor either. That's the same rule that keeps a key added from a copied session from shutting the owner out.
- **The undo link for an email change trusts the old mailbox.** It has to, since it's there for an owner who has nothing else left. So someone who can read the old mailbox can undo a change that the owner made. That undo also removes sign-in methods added in the week before the change, or since the session that asked for it signed in. The attacker can then reset the password by email. A second factor older than that survives. See [Reverting](protected-changes.md#reverting) for why the line sits there and how to move it.
- **The `cache` session registry is as good as its store.** A session's record says whether it was revoked or replaced. A key beside it says so too, so losing either one leaves the session ended. The list of a user's sessions is one key, though. A store that drops that key leaves those sessions out of the sessions list, and out of a sign-out everywhere, until they next expire. This happens with Redis or Memcached evicting under memory pressure, or with a replica promoted without its latest writes. Use a store that doesn't evict, or the `database` driver, which is the default.
- **Lockouts still reach new browsers.** Someone who knows a user's email can keep that account locked. They do it by guessing faster than the per-minute limit. After 80 wrong passwords in a row, which takes 20 minutes at the quickest, the password is refused from every browser the account hasn't signed in from. It stays refused until its owner resets it. See [At the Cap](#at-the-cap). Suppose the attacker guesses under one of the account's names, and the owner types another. The owner is then told the password is wrong, not told to wait. Saying more would tell a stranger that the two names belong to one account. With `Features::devices()` on, browsers the owner has signed in from before keep their own limit, and they keep working. Without devices, the lock reaches every browser while the guessing goes on, and so does the cap. A password reset clears the password's counts and locks, but it doesn't clear a second factor's.
- **Which browsers are known is kept in the cache.** A browser stops counting as known when the account is taken back. That fact is recorded in the limiter's cache store, along with the mark that a reset replaces. If the store loses its keys, a browser from before the reset counts as known again. It still can't get past the cap, because known browsers and everyone else share it.
- **A run of failures can begin with a few at once.** Once a kind of browser (the account's own, or everyone else's) has failures on record, each of its attempts is counted before its proof is looked at. The first attempts aren't counted in advance, so that an ordinary sign in writes nothing. As many as the per-minute limit lets through at once (`limits.per_account`, 5) can be checked together. Each one is counted when it fails. With the defaults, that can't pass the cap. It could, if `limits.consecutive_elsewhere`, or what's left of `limits.consecutive` above it, were set lower than `limits.per_account`.
- **No clone detection for synced passkeys.** Their counters usually stay at zero, so there's nothing to compare.
- **Protection only covers Eloquent saves.** Query builder updates and `saveQuietly()` skip the protected attribute check.
- **Changing `APP_KEY` invalidates short-lived data.** Pending email codes stop working. A user's first passkey after the change gets a different user handle, though later passkeys reuse the handle their keys already have. Recovery codes and reserved email addresses keep working when the old key is in `APP_PREVIOUS_KEYS`. So do encrypted values such as TOTP secrets.
- **Signing out ends "remember me" in every browser.** Laravel has one remember token per user. So signing out, revoking any device or signing out other sessions ends every remembered browser. A session that times out, one that the user ends from their [sessions list](devices-and-sessions.md#listing-and-ending-sessions), or one that Keyring ends for another reason, only ends its own.
- **A copied "remember me" pair is only caught when both holders use it.** Whoever comes back first gets the session. The session ends when the other holder turns up, either with the used cookie or while still signed in on the old record. A copy made from a browser that never comes back isn't noticed. It lasts until the session's `absolute` limit. Inside `sessions.remember_grace`, a copy sent from what looks like the same browser joins the session instead. It's caught the next time either of them comes back. A browser that never received the response carrying its new cookie looks like a copy the next time. It has to sign in again.
- **"Remember me" expects one session store per browser.** Two apps that share the cookies and the registry but keep separate Laravel sessions would each see the other's return as a used cookie.
- **Laravel's `cookie` session driver can't destroy an old session.** The session lives in the cookie, so nothing on the server can delete a copy of one. Keyring ends copies through the registry instead. A sign in, a step-up, a password change, signing out everywhere else and an applied email change all move the session to a new registry record, and revoke the old one. Signing out revokes it too. So a copy made before any of those is signed out on its next request. Three things remain. First, a copy keeps working until the next of those events happens, or until the session is revoked or times out. Until then, it's the same cookie as the original. Second, the copy is only turned away where the [session middleware](devices-and-sessions.md#the-session-middleware) runs. Third, a sign in that isn't finished has no record to swap. So the ID changes between its steps leave an earlier copy holding the pending login as it was. The next entry covers that. A server-side session driver has none of the three.
- **The `cookie` session driver lets a browser send back what its session held.** With that driver, the session lives in the browser. So the browser can send an earlier copy of its own cookie, and a pending login or enrollment is kept in the session. Nothing that must happen only once depends on it. TOTP steps and recovery codes are used up in your database. A sent code, its wrong guesses, the code that replaced it, each enrollment's one confirmation and each WebAuthn challenge's one answer are kept in your cache. The limits on attempts per account and per IP address, and on codes sent, are kept there too. Failures in a row are counted in your database. Two things remain. First, an earlier copy returns a pending sign in or step-up to an earlier point. That only means proving a factor again. A WebAuthn challenge it still holds was either never answered, and is as good as it was, or was answered, and is refused. Second, what the cache remembers lasts only as long as the cache does. If the rate limiter's store is cleared or drops keys, an answered challenge that hasn't yet expired (5 to 15 minutes from when it was issued) is forgotten. Whoever holds both an earlier copy of the session and the signed answer that the key gave could then send that answer again. A key that counts its signatures still refuses it, because the count hasn't moved on. A synced passkey, whose count stays at zero, would be accepted. The same goes for a used code and a confirmed enrollment. So keep that store somewhere [your deploys don't clear](#rate-limiting). A server-side session driver has neither of these problems, because the challenge is gone from the one session there is.
- **A request overlapping a session ID change can undo or lose it.** Laravel saves the session when each request ends. So a request that's still running when the ID changes can save the old session again, and a copied cookie would then keep working. A request sent with the old ID right after the change finds no session. That browser then has to sign in again.
- **Location signals need trustworthy data.** `HeaderLocator` trusts request headers. So only use it behind a proxy that sets them, and that can't be bypassed.
- **A provider you opt into `round_trip` counts as fresh when the user comes back.** By default, no sign in with an identity provider counts toward `keyring.fresh` on the strength of an old session there. A provider whose [`freshness`](sso.md#freshness) is `reauthenticate` (any OpenID Connect provider, and Microsoft) counts a sign in from its `auth_time`, so one the provider let straight through on an old session isn't fresh, and one without `auth_time` never is. Keyring asks for `auth_time` on a sign in where the provider takes the `claims` parameter. A confirm through it asks for a new sign in (`max_age=0`, and `prompt=login` where it's taken) and needs an `auth_time` from after the user was sent there. Google and GitHub can't be relied on for that, so they're `never`: their sign ins never count, and nor do their confirms, which the confirm page only offers toward a level, as signing in again would count. A user whose only way in is such a link can't make protected changes until they [reset their password](sso.md#users-whose-only-way-in-is-never-fresh). A provider you set to `round_trip` counts a sign in from when the user came back, and so does a confirm, which the confirm page offers as a plain round trip to the provider: someone at a browser still signed in there gets a fresh verification without typing anything. A link from another site can start that confirm too, so the session can become fresh without the user doing anything at all. See [Step-Up](sso.md#step-up).
- **No single logout.** Signing out of Keyring doesn't sign the user out at their identity provider, and the provider ending its session doesn't end Keyring's. Keyring reads nothing from the provider after the sign in.
- **Session guards only.** Pending logins and step-up live in the session, so stateless API clients and mobile apps can't use the sign in flow directly.
- **Not production-tested yet.** Keyring is new, and until 1.0 a minor release may change the public API (see [What's Stable](../README.md#whats-stable)).
