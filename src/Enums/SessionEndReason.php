<?php

declare(strict_types=1);

namespace Keyring\Enums;

/**
 * Why a registered session ended (RegisteredSessionEnded). The reasons the
 * session middleware signs a browser out for keep the names they have on
 * SessionEnded.
 */
enum SessionEndReason: string
{
    /** Revoked with no other reason given: one ended from the sessions list, or a call to the registry of your own. An app's own Auth::logout() is LoggedOut. */
    case Revoked = 'revoked';

    /**
     * The user signed out of it: with Keyring's sign-out, or the app's own
     * Auth::logout() or logoutCurrentDevice() on Keyring's guard, unless the
     * app gave a reason of its own around it with Sessions::because(). That
     * includes Laravel's auth.session middleware signing a browser out once
     * the user's password hash has changed.
     */
    case LoggedOut = 'logged_out';

    /** "Sign out everywhere else", or an administrator's keyring:sign-out for the user. */
    case SignedOutEverywhere = 'signed_out_everywhere';

    /** The browser signed in again, and left the session it was on. */
    case SignedInAgain = 'signed_in_again';

    /** Its device was signed out from the devices list. */
    case DeviceRevoked = 'device_revoked';

    /** Its device was reported with the "this wasn't me" link. */
    case DeviceReported = 'device_reported';

    /** Its device was forgotten to keep the account to devices.limit. */
    case DeviceLimit = 'device_limit';

    /** It went unused longest when a sign in took the account past sessions.max. */
    case SessionLimit = 'session_limit';

    /** The user was deleted, soft deleted or for good. */
    case AccountDeleted = 'account_deleted';

    /** The password was changed, and the other sessions signed out. */
    case PasswordChanged = 'password_changed';

    /** The password was reset from a reset link. */
    case PasswordReset = 'password_reset';

    /** The email address changed, and the other sessions signed out. */
    case EmailChanged = 'email_changed';

    /** The old address undid an email change ("this wasn't me"). */
    case EmailChangeUndone = 'email_change_undone';

    /** A risk response ended it, or ended every session of the account. */
    case Risk = 'risk';

    /** The session middleware found it had gone unused for too long. */
    case Idle = 'idle';

    /** The session middleware found it past its absolute limit, or its "remember me" no longer good. */
    case Expired = 'expired';

    /** The session middleware found its record belongs to another user. */
    case OtherUser = 'other_user';

    /** Its "remember me" cookie was used twice. */
    case Reused = 'reused';

    /** The app no longer lets the user sign in (Keyring::allowSignInWhen). */
    case NotAllowed = 'not_allowed';

    /**
     * An impersonation ended: the session someone was signed in to as the
     * user, and their own parked one when the browser was signed out rather
     * than going back to it.
     */
    case ImpersonationEnded = 'impersonation_ended';
}
