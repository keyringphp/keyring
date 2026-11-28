# Protected Changes

- [Introduction](#introduction)
- [Routes](#routes)
- [Protected Attributes](#protected-attributes)
- [Bypassing Protection](#bypassing-protection)
- [Changing the Email Address](#changing-the-email-address)
    - [Requesting a Change](#requesting-a-change)
    - [Confirming](#confirming)
    - [The Emailed Links](#the-emailed-links)
    - [Reverting](#reverting)
    - [The Old Address Is Reserved](#the-old-address-is-reserved)
    - [Checking and Cancelling](#checking-and-cancelling)
- [Changing the Password](#changing-the-password)
- [Requiring a Password Change](#requiring-a-password-change)
    - [Carrying On Afterwards](#carrying-on-afterwards)
- [Password Rules](#password-rules)
    - [Context-Specific Words](#context-specific-words)
- [Resetting the Password](#resetting-the-password)
- [Email Verification](#email-verification)
- [Events](#events)

## Introduction

Whoever controls the email address and password controls the account. That's why Keyring's flows for changing them check who's asking, tell the owner, and can be undone. Each one is a feature you can turn on:

```php
'features' => [
    Features::resetPasswords(),
    Features::updatePasswords(),
    Features::emailChanges(),
    Features::emailVerification(),
],
```

Once Keyring handles password changes with `updatePasswords()`, or email changes with `emailChanges()`, that attribute is [protected](#protected-attributes). From then on, it can only change through Keyring's flow. Without the feature, your application may change it however it likes.

## Routes

| Method | URI | Name | Middleware |
|---|---|---|---|
| `POST` | `/user/email` | `keyring.email.store` | `auth`, `changes_middleware`, limited |
| `GET` | `/user/email` | `keyring.email.show` | `auth` |
| `DELETE` | `/user/email` | `keyring.email.destroy` | `auth` |
| `GET` | `/email-changes/{change}/confirm/{token}` | `keyring.email.confirm` | limited by `keyring-pages` |
| `POST` | `/email-changes/{change}/confirm` | `keyring.email.confirm.store` | limited |
| `GET` | `/email-changes/{change}/revert/{token}` | `keyring.email.revert` | limited by `keyring-pages` |
| `POST` | `/email-changes/{change}/revert` | `keyring.email.revert.store` | limited |
| `PUT` | `/user/password` | `user-password.update` | `auth`, `changes_middleware`, limited |
| `GET` | `/forgot-password` | `password.request` | guest |
| `POST` | `/forgot-password` | `password.email` | guest, limited |
| `GET` | `/reset-password/{token}` | `password.reset` | guest |
| `POST` | `/reset-password` | `password.update` | guest, limited |
| `GET` | `/email/verify` | `verification.notice` | `auth` |
| `GET` | `/email/verify/{id}/{hash}` | `verification.verify` | signed, limited by `keyring-pages` |
| `POST` | `/email/verify/{id}/{hash}` | `verification.verify.store` | `auth`, signature in the body, limited |
| `POST` | `/email/verification-notification` | `verification.send` | `auth`, limited |

In this table, `auth` means `auth:{guard}`, which uses Keyring's guard. "Limited" means the `keyring` [rate limiter](configuration.md#pending-logins-timebox-and-rate-limits), which allows 6 a minute by default. The three `GET` routes that emailed links open use the looser `keyring-pages` limiter instead, which allows 60 a minute per IP address, so opening a link doesn't use up the tries its button gets. The email routes exist only with `Features::emailChanges()`. The password route needs `Features::updatePasswords()`, the reset routes need `Features::resetPasswords()`, and the verification routes need `Features::emailVerification()`.

## Protected Attributes

`Features::updatePasswords()` protects `password`, and `Features::emailChanges()` protects `email`. You may list any others in the `protected` configuration option:

```php
'protected' => ['phone'],
```

With the `HasKeyring` trait in place, changing a protected attribute on a user model outside Keyring's flows throws a `Keyring\Exceptions\ProtectedAttributeException`:

```php
$user->update(['email' => 'new@example.com']); // throws
```

That includes your own profile forms. If `Features::emailChanges()` is on, remove `email` from them and use the email change flow instead. Setting these attributes when a user is created isn't affected.

The check runs on the model's `updating` event. Changes that skip Eloquent events, such as query builder updates or `saveQuietly()`, aren't caught.

## Bypassing Protection

For trusted admin tooling, such as a support agent fixing an address, you may use `Keyring::withoutProtection` to make a change for a single callback:

```php
use Keyring\Facades\Keyring;

Keyring::withoutProtection(
    fn () => $user->update(['email' => 'new@example.com']),
    reason: 'Support ticket 42',
);
```

Each use dispatches a `Keyring\Events\ProtectionBypassed` event with the reason. It also logs a `protection_bypassed` entry against the signed-in user who made the change, not against the user being changed. The method returns whatever your callback returns.

## Changing the Email Address

Whoever controls the address can reset the password, so the safeguards in this flow aren't optional. The new address always has to confirm. The old address can always revert the change for a while, and it stays reserved in the meantime. You choose the timings (`email_changes.confirmable_for` and `email_changes.revertable_for`), the validation in your `ValidateEmailChange` action, the emails, and the pages.

### Requesting a Change

To ask for a change, send `email` to `POST /user/email`. The request needs a [fresh verification](step-up.md#fresh-verification). Your `ValidatesEmailChanges` action validates the request and returns the new address. It's published to `app/Actions/Keyring/ValidateEmailChange.php`, so this is where you add your own rules, such as allowing only your company's domain. Don't check whether the address is taken in there, since Keyring handles that without revealing it. The response is always the `email-change-requested` [status response](sign-in-flow.md#status-responses), whatever happens next. It never reveals whether the new address already has an account.

Keyring then does the following:

1. It cancels any change the user already has waiting.
2. It stores a pending change with hashed, single-use tokens. The change is valid for `email_changes.confirmable_for`, which is 24 hours by default.
3. It emails the **new** address a link to confirm.
4. It emails the **current** address a notice with a link to revert, and a link to confirm as well when it's needed (see below).

If the new address belongs to another account, everything the account can see stays the same: the response, the pending change, and the notice to the current address. Only the email to the new address differs. That email says someone tried to use the address, and it carries no link. The change can therefore never be confirmed, and it expires like any other. Asking for the current address does nothing.

Keyring sends all of these emails after the response, using Laravel's `defer()`, so the time a request takes doesn't reveal which case it was.

A `MustVerifyEmail` user whose address isn't verified yet is refused with the `keyring::keyring.verify_email_to_change` message. The change would have to wait for a confirmation from that address, and nobody has shown they can read it yet. Each request emails two addresses, so an account can ask five times an hour (`limits.notices` every `limits.notices_per`). After that, it gets a `429`. No address is emailed more often than that, whichever accounts ask for it. Once an address has used up its share, requests for it are answered and stored the same way, but nothing more is sent to it.

### Confirming

The new address must always confirm. The current address must confirm too, unless this session proved a possession factor, other than a recovery code, that the account has had for `email_changes.established_after` (7 days by default), and has had since before this session signed in. A newer factor doesn't count. That way, whoever got into the account can't add a factor and then use it to skip the check, whether in the same session or by signing in again with it. Another account's factor doesn't count either, so an impersonated or switched session can't skip the check with the admin's factor.

The change applies once every required confirmation is in. When it's time to apply it, Keyring checks that the address is still the one the change was requested from, and that nobody else has taken the new address in the meantime. If either has changed, the pending change is cancelled. Applying the change also sets `email_verified_at`, when the model has that attribute loaded, and stops trusting the user's devices.

Applying the change also signs out the account's other sessions and changes the "remember me" token, in the same way as `Sessions::signOutEverywhere` does. Set `email_changes.sign_out_others` to `false` to keep them. Devices stop being trusted either way. The browser that confirmed keeps its session, under a new ID, only if it was signed in as this account. With `email_changed` and `email_change_reverted` turned on (see [Security Emails](security-log-and-emails.md#email-types)), both addresses are told when the change applies and when an applied change is reverted.

### The Emailed Links

Mail scanners open links on their own, so the emailed links open a page with a button. Only the button changes anything:

- `GET /email-changes/{change}/confirm/{token}` and `.../revert/{token}` render the `email-change` page, with `action` (`confirm` or `revert`), `url` (where the button posts), and `token`. These routes change nothing.
- A `POST` to `url`, with `token` in the body, makes the change.

The link has to carry its token in the URL, but the request that acts doesn't. That keeps `url` as `/email-changes/{change}/confirm` or `.../revert`, without the token, so the token isn't written to access logs and proxies a second time. Post it as a form field:

```html
<form method="POST" action="{{ $url }}">
    @csrf
    <input type="hidden" name="token" value="{{ $token }}">
    <button>{{ $action === 'confirm' ? 'Confirm the change' : 'Undo the change' }}</button>
</form>
```

With Inertia, post `{ token }` to `url`. A token that's missing, wrong, already used, or expired gets the `email-change-invalid` status as its answer. A link for a change that doesn't exist is a `404`, and `LinkRefused` records it with the reason `unknown`.

Keyring builds these links from `APP_URL`, never from the request's `Host` header. They also work when the user is signed out, since they may open in another browser.

After confirming, the user is redirected to `home` if they're signed in, or to the login page if they aren't. The `status` is set to `email-changed` when the change has applied, `email-change-confirmed` while it's still waiting for the other address, or `email-change-invalid`.

### Reverting

The current address can revert the change while it's pending, and for `email_changes.revertable_for` after it applies (7 days by default). Reverting does the following:

- puts the old address back, even when a later change is what moved it away,
- cancels any later email changes, so links from them can't move the address away again,
- deletes every authenticator that wasn't established when the change was requested. That means anything added within `email_changes.established_after` before the change, or since the session that asked for it signed in. Keyring deletes them one at a time, dispatching `AuthenticatorRemoved` for each. Accounts at [identity providers](sso.md) linked in that time are unlinked the same way. This can include one the owner added that week, which they're free to add again. When none of what's left is a factor that recovery codes can recover, the codes go too, the same as when a user removes their last second factor. That dispatches an `AuthenticatorRemoved` of its own,
- signs out every session, and changes the "remember me" token.

These removals aren't held back by [frozen sign-in methods](authenticators.md#frozen-sign-in-methods), and don't start the freeze over. The undo comes from the old mailbox's link, never from a session, so a copy of a session can't set it off, and what it removes is what a session could have added.

After that, the user is redirected to the forgot password page, or to the login page when password resets are off, with `status` set to `email-change-reverted`. That's because whoever made the change may also know the password. Reverting doesn't change the password itself.

**Who the undo trusts.** The link is for an owner who has lost everything but their old mailbox. For example, someone got into the account, added a passkey of their own, and moved the address. So the link asks for nothing but the link itself, and it takes away the sign-in methods that are too new to be surely the owner's. That works both ways, because whoever can read the old mailbox can press it. Suppose the change was the owner's own, and they're moving away from a mailbox someone else can read. That person can undo the change, which removes any second factor the owner added in that window. A password reset through the same mailbox then signs in without one. Keyring can't tell the two people apart, because each holds exactly the old mailbox.

`established_after` is where the line sits. A sign-in method the account has had for longer than that, added before the session that asked signed in, survives an undo. So a second factor set up a week or more before changing address is safe from it. When the change had applied, the new address is told it was undone, so the owner hears about it there.

If your users are more likely to lose their mailbox than to have their session taken over, shorten `revertable_for` and `established_after`. If it's the opposite, lengthen them.

### The Old Address Is Reserved

While a change can still be reverted, nobody else can take the address it replaced. Otherwise, someone who changed the address could register a new account with the old one, and the owner's revert would have nowhere to put it back.

This also covers lookalikes. An address that differs only in case, accents, letter width, or characters that don't show is held back too. That's because MySQL's and MariaDB's default collations treat those as the same address, and their unique index would refuse to give it back. Another account that asks to move to a reserved address gets the same "address in use" email as for any taken address. [Registration](sign-in-flow.md#registration) counts it as taken too, so it's answered like any address that has an account.

If your own code creates users or gives them a new address, such as an admin screen or an import, the `Keyring\Rules\UnreservedAddress` rule refuses a reserved one with Laravel's "has already been taken" message. Use it alongside `Rule::unique()`:

```php
'email' => ['required', 'string', 'email', 'max:255', Rule::unique(User::class), new UnreservedAddress],
```

With the `HasKeyring` trait, saving a user with a reserved address in any other way throws a `Keyring\Exceptions\ReservedAddressException`. That holds even inside `Keyring::withoutProtection`. As with [protected attributes](#protected-attributes), the check runs on Eloquent events, so query builder inserts aren't caught. To check an address yourself, use `app(Keyring\Changes\ReservedAddresses::class)->has($address)`. The lookup uses a keyed hash, made with a key derived from `APP_KEY` and from each of `APP_PREVIOUS_KEYS`, because the change stores the address encrypted.

### Checking and Cancelling

`GET /user/email` returns the pending change, if there is one:

```json
{
  "pending": {
    "email": "new@example.com",
    "confirmed": false,
    "needsCurrentConfirmation": true,
    "expiresAt": "2026-11-09T13:00:00+00:00"
  }
}
```

`confirmed` tells you whether the new address has confirmed. `DELETE /user/email` cancels the change and responds with `email-change-cancelled`.

A password reset or a password change cancels any pending change. Whoever knew the old password shouldn't keep a change they started with it. Signing out everywhere else cancels it too, as does anything else that goes through `Sessions::signOutEverywhere`.

However a change is cancelled, the old address's "this wasn't me" link keeps working until the change would have expired. Whoever asked for the change can cancel it too. That shouldn't take away the owner's way to remove what was added and sign everything out. The exception is a change that can't be applied any more, because the address has moved or the new one is taken. It's cancelled when its confirmation tries to apply it, and its link stops working straight away.

## Changing the Password

`PUT /user/password` needs a [fresh verification](step-up.md#fresh-verification). If the user has a password, it also needs their current one. Keyring checks both before it passes the request to your `UpdatesUserPasswords` action, which validates the new password and saves it. The action is published to `app/Actions/Keyring/UpdateUserPassword.php`.

| Field | |
|---|---|
| `current_password` | Required when the user has a password. Keyring checks it itself, using the `Keyring\Rules\CurrentPassword` rule. That way, a change always takes the current password, whatever your action does (OWASP ASVS 5.0.0, 6.2.3). A fresh verification can be a passkey or a code, and neither shows that the user knows the password they're replacing. |
| `password`, `password_confirmation` | The new password. The published action checks it against the [password rules](#password-rules). |
| `sign_out_others` | An optional boolean, `true` by default. Keyring reads it. |

`CurrentPassword` works like Laravel's `current_password` rule, with one difference. A password that's too long for the stored hash fails like any wrong one, without reaching the hasher. For bcrypt, that means more than 72 bytes, because bcrypt only reads the first 72. Use the rule wherever your own code asks for the current password:

```php
use Keyring\Rules\CurrentPassword;

$request->validate(['current_password' => ['required', 'string', new CurrentPassword($request->user())]]);
```

Your action doesn't need to check `current_password` again. An action that still does, such as one carried over from another package, keeps working, because it's given the same input.

A user without a password, for example one who only uses passkeys, can set one with only the fresh verification. So can whoever holds a copy of their session, so that first password counts as a new sign-in method. It isn't [established](authenticators.md#established-authenticators) for 7 days, changed in the meantime or not: it [freezes](authenticators.md#frozen-sign-in-methods) the account's sign-in methods, an `ifEnrolled()` policy doesn't ask for it, and [adding a second factor](authenticators.md#the-password-for-a-first-second-factor) doesn't take it. A password reset makes it established at once. Only a first password set through `PasswordChanges::change()` is dated this way. One your own code sets some other way, such as at registration, is established from the start.

Keyring runs your action as one of its own flows, so the action may change the protected `password` attribute, and only that. Changing `email` there still throws. The action must either save a new password or throw a `ValidationException`. If it returns without saving, Keyring throws a `LogicException`, because everything that follows assumes the password changed.

The action runs while holding the user's row. The save only goes ahead if the session is still signed in and the stored password is still the one `current_password` was checked against. A change that a reset, or a change from another session, overtook is refused, and the reset's password stays in place.

Your action's validation and hashing run in that transaction, while the row is held. So anything else it does, such as dispatching an event or queueing an email, happens before the save commits. On PostgreSQL, a query error that the action catches still leaves the save undone. A sign in that rehashes the same password at that exact moment makes the change fail as a wrong current password, and sending it again works. If your own code calls `PasswordChanges::change()`, don't call it inside a transaction of your own. The lock would then be held through whatever comes after the save, which takes other rows.

Afterwards, Keyring regenerates the session ID, which destroys the old one. It cancels any pending email change, ends any reset links still outstanding, and stops trusting the user's devices, including this one. It also starts the account's sign-in limits over, as a reset does, so a password that too many wrong guesses had got refused works again. With `sign_out_others` on, it also revokes every other session and changes the "remember me" token. The response is the `password-updated` [status response](sign-in-flow.md#status-responses).

## Requiring a Password Change

Keyring never expires passwords. When there's evidence that a password is known to someone else, Keyring can hold the user until they choose another, as NIST SP 800-63B-4 asks (Sec. 3.1.1.2). Keyring places a hold itself in one case. That's when the [`BreachedPassword`](risk.md#requiring-a-new-password) signal is on and the password someone signed in with turns up in a breach. For anything else you learn, place a hold from your own code, or from a [risk response](risk.md#requiring-a-new-password) of your own:

```php
use Keyring\Facades\Keyring;

Keyring::requirePasswordChange($user, 'Reported phished on 12 November.');

Keyring::requiresPasswordChange($user);   // true until the password changes
Keyring::cancelPasswordChange($user);     // the evidence was wrong
```

Next, tell Keyring where your change-password form is:

```php
// config/keyring.php
'password_change_url' => '/settings/password',
```

While a user is held:

- They can still sign in. On every signed-in request in the `web` group, they're sent to `password_change_url` with the `change-password` status. JSON requests get a `403` with that status, and the URL as `redirect`. Without a `password_change_url`, they get a plain `403`.
- The change-password page is let through for any method. So are `PUT /user/password`, the [confirm page](step-up.md#the-confirm-flow) the user may be sent to, signing out, and email verification. Nothing else is let through, including Keyring's other routes.
- The hold ends when the password changes, either through `PUT /user/password` or through a [password reset](#resetting-the-password). The new password has to be a different one. `PUT /user/password` refuses the current password as the new one, for every user. A reset to the same password goes through like any other, but it leaves the hold in place. That way, the form doesn't tell whoever holds the link that they guessed the password. If your application saves passwords itself, without `Features::updatePasswords()`, call `Keyring::cancelPasswordChange($user)` once it has saved a new one. Check that it's a new one first, because nothing in that call checks it.
- Signing out and back in changes nothing. The hold is a row in `keyring_password_holds`, not something stored in the session or the cache.
- A hold placed during a request applies to that request's session straight away. Other sessions that are already signed in find out about it within a minute.

`requirePasswordChange()` returns `false` and does nothing for a user without a password. Someone who only signs in with a passkey has no password to change, and holding them would lock them out. A user whose password is removed after they were held is released too. The optional reason is kept on the row for your support tools, and you can read it with `Keyring\Changes\PasswordHolds::reason($user)`. A risk response fills the reason with the signals it acted on. Keyring dispatches a `Keyring\Events\PasswordChangeRequired` event when a hold is placed, with `user` and `reason`. Listen for it if you want to email the user, since Keyring doesn't send that email itself.

### Carrying On Afterwards

Keyring remembers the page a held user was going to when it sent them to `password_change_url`. When they change their password through `PUT /user/password`, the `password-updated` [status response](sign-in-flow.md#status-responses) redirects there instead of back. JSON callers get it as `redirect`. A password change the user chose themselves, without a hold, goes back as before.

The same rules apply as [after enrolling](policies.md#carrying-on-afterwards). Only a page the browser navigated to is remembered, and it's only used on your app's own origin, for the same user, within an hour. The change-password page itself is never saved. Pages opened from emailed links aren't saved either. Their URL holds the link's token, and some of them, like confirming an email change, stop working once the password changes. A reset doesn't use it, since the user signs in again afterwards.

The check runs in the `Keyring\Http\Middleware\RequirePasswordChange` middleware. Keyring adds it to the `web` group, after its [session middleware](devices-and-sessions.md#the-session-middleware). If `sessions.middleware` is off, add `keyring.password` wherever you add `keyring.session`.

## Password Rules

`Keyring\Support\PasswordRules::for($user)` returns validation rules that follow the password requirements in OWASP ASVS 5.0.0 (section 6.2). [Standards](security.md#standards) lists them one by one. In brief, the rules check the following:

- A password must be at least `min_with_mfa` characters (8) when the user has a second factor, and at least `min_without_mfa` characters (15) when they don't. Here, "a second factor" means their authenticators could meet AAL2, including possession, without counting recovery codes (a fallback) or email codes (not a second factor). Removing the last one takes the password typed again, so Keyring can check it's long enough on its own. See [Removing Authenticators](authenticators.md#removing-authenticators). Neither option can be set below 8. If you try, Keyring throws a `LogicException` rather than accept a shorter minimum.
- A password can be at most `max` characters (128) with a hasher that reads a whole password, such as argon2id.
- There are no composition rules, such as "one uppercase, one symbol". Any characters are accepted, including spaces, punctuation, and emoji.
- Breached passwords are rejected, in production by default. Laravel's check lets a password through when Have I Been Pwned can't be reached. To refuse it in that case too, set [`passwords.refuse_unchecked`](configuration.md#passwords).
- The most common passwords are always rejected, whatever their case and with or without spaces around them. The list comes bundled with Keyring: the 10,000 most common of 8 characters or more, the 3,000 most common of 15 or more, and the entries from the list Keyring shipped before, 13,052 in all. It's taken from SecLists (MIT licensed). `resources/passwords/README.md` in the package records the exact source.
- Passwords made up of [context-specific words](#context-specific-words) are refused. Those words are the site's name, the words you list, and the user's name, email username, and email domain.
- With bcrypt, Laravel's default, passwords over 72 bytes are rejected, because bcrypt silently ignores the rest. Passwords with a NUL byte are rejected too, since bcrypt can't hash them at all. That's 72 plain characters, but as few as 18 emoji reach the same limit, so 64 characters don't always fit. To accept every password up to `max`, which is what OWASP ASVS 5.0.0 (6.2.9) needs, set `HASH_DRIVER=argon2id`. See [Passwords](configuration.md#passwords).
- The `confirmed` rule applies too, so the request needs `password_confirmation`.

Passwords may contain any Unicode characters. Keyring converts each one to Unicode's NFC form before it measures, hashes, or checks it, as NIST SP 800-63B-4 recommends (Sec. 3.1.1.2). The same "é" is one code point on some keyboards and two on others. Without this step, a password set on one device could fail on another. The rules above count what will be hashed, so a character is one code point of the NFC form. Keyring's routes do this for the input they hand your actions (`password`, `password_confirmation`, and `current_password`), and for every password they check. If your own code sets a password some other way, such as in a seeder, an admin tool, or a route of your own, pass it through `PasswordRules::normalize()` first:

```php
$user->password = Hash::make(PasswordRules::normalize($password));
```

A password hashed without normalising only matters when it has characters that aren't already in NFC. Keyring only ever checks the NFC form, so that hash never matches, and there's no second try with the password as typed. Keyring has done this since its first release, so no hash it made needs one.

Calling `PasswordRules::for()` with no user applies the stricter, no-MFA minimum, which is what registration uses. There's no user to take a name from at registration, so pass the name and email yourself. The published `CreateNewUser` does this in `validate()`, through the trait's `passwordRules(context: [$input['name'] ?? null, $input['email']])`.

### Context-Specific Words

A password that's only the name of your application, your company, or its owner is easy to guess for anyone who knows where it's used. OWASP ASVS 5.0.0 (6.1.2) asks you to keep a list of such words, and 6.2.11 asks you to use that list to stop easy-to-guess passwords. Put the list in the `passwords.context` option:

```php
'passwords' => [
    'context' => ['Acme', 'Acme Rockets', 'Roadrunner', 'Wile E'],
],
```

Include the names of your organisation, products, systems, projects, departments, and roles. Keyring adds what it can work out for itself, and it refuses a password made up of nothing but these words:

| | From |
|---|---|
| Your application's name | `app.name` |
| The words you list | `passwords.context` |
| The user's name | Their `name` attribute, or the `context` argument at registration |
| Their email username | What's before the `@` in their username and email attributes |
| The organisation they're at | The first label of their email domain, so `megacorp` in `megacorp.example`. Skipped for providers that anyone can have an address at (Gmail, Googlemail, Outlook, Hotmail, Live, Yahoo, Ymail, iCloud, Proton, Fastmail, Tutanota, Yandex, Zoho, and any domain starting with `mail.` or `email.`). |

Here's how the words are compared:

- The whole password is compared, not the words inside it, as NIST SP 800-63B-4 asks (Sec. 3.1.1.2). A password is refused when, with its digits, spaces, and punctuation taken out, it is one of these words or several of them run together. `acme2026!`, `acmeacmeacme`, and `Grace.Hopper.1906` for a user named Grace Hopper are all refused. A passphrase that happens to contain one is as hard to guess as any other, so `acme sells the best anvils` passes. Refusing it would be a composition rule by another name.
- Case doesn't matter. Each value also counts word by word, split at anything that isn't a letter or a digit, so `Acme Rockets` counts as `acme` and `rockets`.
- Characters that stand in for letters count as those letters: `0` counts as `o`, `1` and `l` as `i`, `3` as `e`, `4` and `@` as `a`, `5` and `$` as `s`, and `7` as `t`. So `k3yr1ng` counts as `keyring`.
- Words under four characters don't count, because they turn up by chance. The exception is your application's name or a listed entry as a whole. Those count from three characters, so an app called `IBM` refuses `ibm-ibm-ibm`. Two characters or fewer never count.
- A name made of several words also counts run together. `My App` counts as `myapp`, even though `my` and `app` alone are too short to count.

The published actions all take their rules from one trait, `app/Actions/Keyring/PasswordValidationRules.php`, so that's where you change them. To add to Keyring's rules, pass a callback that receives the `Illuminate\Validation\Rules\Password` rule, with its length already set for the user, and returns it:

```php
use Illuminate\Validation\Rules\Password;

protected function passwordRules((Authenticatable&Model)|null $user = null, array $context = []): array
{
    // Administrators need 20 characters, second factor or not.
    return PasswordRules::for($user, fn (Password $rule) => $user?->is_admin ? $rule->rules(['min:20']) : $rule, $context);
}
```

Ask for more length rather than for particular kinds of character. A composition rule, such as `mixedCase()`, `letters()`, `numbers()`, `symbols()`, or a pattern of your own that a password has to match, takes your application out of OWASP ASVS 5.0.0 (6.2.5). That requirement wants passwords of any composition accepted, and NIST SP 800-63B-4 says the same (Sec. 3.1.1.2). People meet such rules with `Password1!`, which the length rules and the lists above handle better.

## Resetting the Password

Send `email` to `POST /forgot-password`, and Keyring sends a reset link when the address has an account. The answer is the same either way: the `reset-link-sent` [status response](sign-in-flow.md#status-responses). The email goes out after the response, so timing doesn't give it away either.

The email is Laravel's own `Illuminate\Auth\Notifications\ResetPassword` notification, sent through your user model's `sendPasswordResetNotification` method, so you can change it the usual Laravel way. Keyring sets its link with `ResetPassword::createUrlUsing`. The link is built from `APP_URL`, never from the `Host` header. If you've already set `createUrlUsing` yourself, Keyring leaves it alone. The reset page is sent with `Referrer-Policy: no-referrer`, so the token in its URL doesn't reach anything the page loads through the referrer.

`POST /reset-password` takes `token`, `email`, `password`, and `password_confirmation`. A bad token, or an address without an account, always gets the same error on `email`. Only once the token is accepted does Keyring pass the request to your `ResetsUserPasswords` action. That action is published to `app/Actions/Keyring/ResetUserPassword.php`. It checks the password rules and saves the password, so the form doesn't reveal which addresses have accounts or MFA. As with changes, the action may only change the password, and it must save one or throw. Then Keyring:

- Revokes every session and changes the "remember me" token.
- Cancels any pending email change.
- Lifts any [risk lock](risk.md#actions) on the account.
- Unlinks every [identity provider](sso.md#password-resets-and-email-changes) linked to the account, dispatching `AuthenticatorRemoved` for each, since each one stands in for the password. Second factors stay.
- Clears the account's sign-in lockouts and failure counts, including the ones in a row, on the factors that can start a sign in. It logs that it did. A password or passkey that was refused [at the cap](security.md#at-the-cap) works again. Second factors keep theirs. Per-IP limits stay.
- Dispatches `Keyring\Events\PasswordReset`, and Laravel's `Illuminate\Auth\Events\PasswordReset`.
- Redirects to the login page with the `password-reset` status. It never signs the user in, so the policy still applies at their next login.

Resets use Laravel's password broker, which is `passwords.broker` or your default. That means two of its settings in `config/auth.php` are part of the flow:

```php
'passwords' => [
    'users' => [
        'provider' => 'users',
        'table' => 'password_reset_tokens',
        'expire' => 60,
        'throttle' => 60,
    ],
],
```

`throttle` is the number of seconds an account waits between reset links. It's the only limit on how often one account is mailed. Keyring's own limit on `POST /forgot-password` is the [form limiter](configuration.md#pending-logins-timebox-and-rate-limits), 6 a minute per sender. That doesn't stop many senders from asking for one account. A new Laravel application has `throttle` set to 60 seconds. Keyring neither sets nor checks it when the application runs, so keep it in place. The [conformance suite](testing.md#the-conformance-suite) fails when it's missing or zero. A request the broker throttles gets the same `reset-link-sent` answer as any other. `expire` is how many minutes a link works for. OWASP's Forgot Password Cheat Sheet asks for both settings. NIST SP 800-63B-4 (Sec. 4.2.1.2) asks for a link that lasts 24 hours at most. Keyring doesn't cap `expire` itself, so don't raise it past 1440.

A reset link stops working as soon as the password changes through Keyring, the account's email address changes, or the user is deleted. Password reset keeps working while an account is locked, and it lifts the lock, so a lock can't keep the owner out for good.

## Email Verification

When `Features::emailVerification()` is on, Keyring provides Laravel's verification routes. It also provides the `verify-email` page that asks the user to check their inbox, and the `email-verification` page that the emailed link opens. Verification links are built from `APP_URL`. They're signed over the path only, using `keyring.signed:relative`, which is Laravel's `signed` middleware with [refused links logged](security-log-and-emails.md#refused-links). So a forged `Host` header can't redirect them.

Laravel verifies the address as soon as the link is opened. Keyring doesn't. Like its other emailed links, this one opens a page with a button, and only the button changes anything. So nothing that fetches the link by itself verifies an address, and no `GET` in Keyring changes state.

- `GET /email/verify/{id}/{hash}` renders the `email-verification` page with `email` (the address being verified), `url`, `expires`, and `signature`. It changes nothing. Someone who's already verified is sent on to `home`.
- A `POST` to `url`, with `expires` and `signature` in the body, verifies the address. `url` is the link's path without its query string, so the signature isn't in the URL of the request that acts. It's refused while [impersonating](impersonation.md#whats-refused-while-impersonating), as sending another link is.

```html
<form method="POST" action="{{ $url }}">
    @csrf
    <input type="hidden" name="expires" value="{{ $expires }}">
    <input type="hidden" name="signature" value="{{ $signature }}">
    <button>Verify {{ $email }}</button>
</form>
```

Both steps need the user to be signed in as the account the link was sent to. Anyone else gets a `403`. A signed-out browser that opens the link goes to the login page, and comes back to it. A signed-out browser that posts to `url` goes to the login page. The link stops working when it expires (`auth.verification.expire`, 60 minutes) or when the account's address changes. After verifying, users go to `home` with `?verified=1`, and Laravel's `Illuminate\Auth\Events\Verified` event is dispatched as usual.

Laravel's own `VerifyEmail` notification and the `MustVerifyEmail` contract work unchanged. Only what the link's `GET` does is different.

With [registration that doesn't reveal who has an account](sign-in-flow.md#without-revealing-who-has-an-account), which is the default, nobody is signed in before their address is verified. So a new user never sees this page. They open the link signed out and are sent to sign in. Signing in from the browser that followed the link is what verifies their address. It takes the link and the password together, never the link alone. A finished password reset verifies the address too. You only need the `verify-email` and `email-verification` pages if you set `registration.reveal_taken`.

If you've already set `VerifyEmail::createUrlUsing` yourself, Keyring leaves it alone.

## Events

These events live in `Keyring\Events`:

| Event | Properties |
|---|---|
| `EmailChangeRequested` | `user`, `change` |
| `EmailChanged` | `user`, `change` |
| `EmailChangeReverted` | `user`, `change` |
| `PasswordChanged` | `user` |
| `PasswordReset` | `user` |
| `PasswordChangeRequired` | `user`, `reason` |
| `ProtectionBypassed` | `reason` |
| `LinkRefused` | `link`, `reason`, `user`. It's dispatched for an email change link with a wrong or ended token, a reset with a token that wasn't the one sent, or a signed link that didn't check out. |

The `change` property is a `Keyring\Models\PendingChange`. Its tokens and addresses are hidden from serialisation, and the addresses are encrypted at rest.

Keyring also dispatches Laravel's `Illuminate\Auth\Events\PasswordReset` alongside its own `PasswordReset` event, so listeners for either one work.
