<?php

declare(strict_types=1);

use Keyring\Features;

return [

    /*
    |--------------------------------------------------------------------------
    | Guard, Username and Home
    |--------------------------------------------------------------------------
    |
    | The guard Keyring signs users in to, the attribute they sign in with,
    | and where they go once they have.
    |
    */

    'guard' => 'web',

    'username' => 'email',

    'home' => '/dashboard',

    /*
    |--------------------------------------------------------------------------
    | Features
    |--------------------------------------------------------------------------
    |
    | Signing in and out, challenges and step-up are always on. Add the rest
    | as your app needs them. Each one brings its routes, and anything else
    | it needs, only once it's here. Without the security log, its events
    | are written to your app's log instead.
    |
    */

    'features' => [
        Features::registration(),
        Features::resetPasswords(),
        Features::emailVerification(),
        Features::updatePasswords(),
        Features::manageAuthenticators(),
        Features::devices(),
        Features::emailChanges(),
        Features::securityLog(),
        Features::impersonation(),
    ],

    /*
    |--------------------------------------------------------------------------
    | Registration
    |--------------------------------------------------------------------------
    |
    | Registering answers the same whether or not the address has an account,
    | and new users sign in once they've followed the link emailed to them.
    | Set "reveal_taken" to true to say when an address is taken and sign new
    | users in straight away, which lets anyone check who has an account.
    |
    */

    'registration' => [
        'reveal_taken' => false,
    ],

    /*
    |--------------------------------------------------------------------------
    | Enrollment Page
    |--------------------------------------------------------------------------
    |
    | Your page for adding a sign-in method. Step-up and the keyring.enrolled
    | middleware send users there when they don't have what a route needs.
    | Null answers 403 instead.
    |
    */

    'enrollment_url' => null,

    /*
    |--------------------------------------------------------------------------
    | Sign-In Methods Page
    |--------------------------------------------------------------------------
    |
    | Your page where users see and remove their sign-in methods. The emails
    | about a new sign-in method and new recovery codes link to it. Null
    | leaves the link out.
    |
    */

    'authenticators_url' => null,

    /*
    |--------------------------------------------------------------------------
    | Support Contact
    |--------------------------------------------------------------------------
    |
    | Where users can reach you about their account: a page's URL or an email
    | address. Keyring's security emails then end by saying who to contact
    | if something wasn't them. Null leaves that line out.
    |
    */

    'support_contact' => null,

    /*
    |--------------------------------------------------------------------------
    | Everything Else
    |--------------------------------------------------------------------------
    |
    | Sessions, passwords, devices, rate limits and the rest keep Keyring's
    | defaults. "Configuration" in the docs lists every option: copy one in
    | here to change it.
    |
    */

];
