<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Keyring\Features;
use Keyring\Http\Controllers\AuthenticatedSessionController;
use Keyring\Http\Controllers\AuthenticatorController;
use Keyring\Http\Controllers\ChallengeController;
use Keyring\Http\Controllers\DeviceController;
use Keyring\Http\Controllers\EmailChangeController;
use Keyring\Http\Controllers\EmailVerificationController;
use Keyring\Http\Controllers\ImpersonationController;
use Keyring\Http\Controllers\PasswordController;
use Keyring\Http\Controllers\PasswordResetController;
use Keyring\Http\Controllers\RegisteredUserController;
use Keyring\Http\Controllers\SessionController;
use Keyring\Http\Controllers\SingleSignOnController;
use Keyring\Http\Middleware\ValidatePostedSignature;

$guard = config('keyring.guard');

// Single sign-on's routes are only there once a provider is configured, so
// an app without one keeps any /auth/... routes of its own.
$sso = is_array(config('keyring.sso.providers')) && config('keyring.sso.providers') !== [];

// Routes that read and then write Keyring's session state (pending logins,
// code guesses, WebAuthn challenges, and the challenge pages that save them)
// call block() to take the session lock, so parallel requests can't each
// spend the same state or write back a stale copy of it.

// One challenge controller serves signing in and step-up alike.
$challenge = function () {
    Route::get('/{factor?}', [ChallengeController::class, 'show'])->block()->name('challenge');
    Route::post('/{factor}', [ChallengeController::class, 'verify'])->block()->name('verify');
    Route::post('/{factor}/send', [ChallengeController::class, 'send'])->block()->name('send');
};

Route::middleware('guest:'.$guard)->group(function () use ($challenge, $sso) {
    if (Features::enabled(Features::registration())) {
        Route::get('/register', [RegisteredUserController::class, 'create'])->name('register');
        Route::post('/register', [RegisteredUserController::class, 'store'])->middleware('throttle:keyring')->name('register.store');
    }

    if (Features::enabled(Features::resetPasswords())) {
        Route::get('/forgot-password', [PasswordResetController::class, 'create'])->name('password.request');
        Route::post('/forgot-password', [PasswordResetController::class, 'store'])->middleware('throttle:keyring')->name('password.email');
        Route::get('/reset-password/{token}', [PasswordResetController::class, 'edit'])->name('password.reset');
        Route::post('/reset-password', [PasswordResetController::class, 'update'])->middleware('throttle:keyring')->name('password.update');
    }

    Route::get('/login', [AuthenticatedSessionController::class, 'create'])->name('login');
    Route::post('/login', [AuthenticatedSessionController::class, 'store'])->block()->name('login.store');

    Route::prefix('/login/challenge')->name('keyring.login.')->group($challenge);

    // Sign in with another primary factor, like a passkey: /login/passkey
    Route::get('/login/{factor}/options', [AuthenticatedSessionController::class, 'options'])
        ->where('factor', '(?!challenge$)[a-z0-9-]+')
        ->middleware('throttle:keyring-login-options')
        ->name('keyring.login.options');
    Route::post('/login/{factor}', [AuthenticatedSessionController::class, 'store'])
        ->where('factor', '(?!challenge$)[a-z0-9-]+')
        ->block()
        ->name('keyring.login.factor');

    // Sign in with an identity provider from keyring.sso.providers. These
    // answer 404 until the SingleSignOn factor is registered.
    if ($sso) {
        Route::get('/auth/{provider}/redirect', [SingleSignOnController::class, 'redirect'])
            ->where('provider', '[A-Za-z0-9_-]+')
            ->middleware('throttle:keyring-login-options')
            ->block()
            ->name('keyring.sso.redirect');
    }
});

Route::middleware('auth:'.$guard)->group(function () use ($challenge, $sso) {
    // A browser impersonating someone can't prove anything as them, nor
    // change how they sign in (keyring.not-impersonating).
    Route::prefix('/confirm')->middleware('keyring.not-impersonating')->name('keyring.confirm.')->group($challenge);

    // Confirm a step-up by signing in again at the provider of a link the
    // confirm page offers. Its callback is the one signing in uses.
    if ($sso) {
        Route::get('/confirm/sso/redirect', [SingleSignOnController::class, 'reauthenticate'])
            ->middleware(['keyring.not-impersonating', 'throttle:keyring-login-options'])
            ->block()
            ->name('keyring.sso.confirm');
    }

    // Changing how someone signs in needs a recent verification.
    Route::middleware('keyring.not-impersonating')->middleware(config('keyring.changes_middleware'))->group(function () {
        if (Features::enabled(Features::manageAuthenticators())) {
            Route::prefix('/user/authenticators')->name('keyring.authenticators.')->group(function () {
                Route::post('/{factor}', [AuthenticatorController::class, 'store'])->block()->name('store');
                Route::post('/{factor}/confirm', [AuthenticatorController::class, 'confirm'])->middleware('throttle:keyring')->block()->name('confirm');
                Route::post('/{factor}/proof-options', [AuthenticatorController::class, 'proofOptions'])->middleware('throttle:keyring')->name('proof-options');
                Route::patch('/{authenticator}', [AuthenticatorController::class, 'update'])->block()->name('update');
                Route::delete('/{authenticator}', [AuthenticatorController::class, 'destroy'])->middleware('throttle:keyring')->block()->name('destroy');
            });
        }

        // Sessions are kept whatever the features, so ending them is always there.
        Route::delete('/user/sessions', [SessionController::class, 'destroyOthers'])->name('keyring.sessions.destroy-others');
        // Only something shaped like a handle gets as far as being looked for
        // or logged. A registry ID isn't.
        Route::delete('/user/sessions/{session}', [SessionController::class, 'destroy'])->where('session', '[0-9a-f]{64}')->name('keyring.sessions.destroy');

        if (Features::enabled(Features::devices())) {
            Route::delete('/user/devices', [DeviceController::class, 'destroyOthers'])->name('keyring.devices.destroy-others');
            Route::delete('/user/devices/{device}', [DeviceController::class, 'destroy'])->name('keyring.devices.destroy');
        }

        if (Features::enabled(Features::updatePasswords())) {
            Route::put('/user/password', [PasswordController::class, 'update'])->middleware('throttle:keyring')->name('user-password.update');
        }

        if (Features::enabled(Features::emailChanges())) {
            Route::post('/user/email', [EmailChangeController::class, 'store'])->middleware('throttle:keyring')->name('keyring.email.store');
        }
    });

    Route::get('/user/sessions', [SessionController::class, 'index'])->name('keyring.sessions.index');

    if (Features::enabled(Features::devices())) {
        Route::get('/user/devices', [DeviceController::class, 'index'])->name('keyring.devices.index');
    }

    if (Features::enabled(Features::emailChanges())) {
        Route::get('/user/email', [EmailChangeController::class, 'show'])->name('keyring.email.show');
        Route::delete('/user/email', [EmailChangeController::class, 'destroy'])->middleware('keyring.not-impersonating')->name('keyring.email.destroy');
    }

    // The verification link is an emailed link like the ones below: its GET
    // shows a page, and the page's button posts the link's signature. The
    // GET is further down, since the link is often opened signed out.
    // Following it, and sending another, are the user's to do, so both are
    // refused while impersonating.
    if (Features::enabled(Features::emailVerification())) {
        Route::get('/email/verify', [EmailVerificationController::class, 'notice'])->name('verification.notice');
        Route::post('/email/verify/{id}/{hash}', [EmailVerificationController::class, 'verify'])->middleware(['keyring.not-impersonating', ValidatePostedSignature::class, 'throttle:keyring'])->name('verification.verify.store');
        Route::post('/email/verification-notification', [EmailVerificationController::class, 'send'])->middleware(['keyring.not-impersonating', 'throttle:keyring'])->name('verification.send');
    }

    // Signing in as another user takes what impersonation.middleware asks,
    // by default two factors proved in the last 15 minutes, and isn't
    // offered to a browser that's impersonating already. Stopping is for
    // anyone who is.
    if (Features::enabled(Features::impersonation())) {
        Route::post('/impersonate/{user}', [ImpersonationController::class, 'store'])
            ->middleware(['keyring.not-impersonating', ...(array) config('keyring.impersonation.middleware'), 'throttle:keyring'])
            ->block()
            ->name('keyring.impersonation.store');
        Route::match(['POST', 'DELETE'], '/impersonate', [ImpersonationController::class, 'destroy'])->block()->name('keyring.impersonation.destroy');
    }

    Route::post('/logout', [AuthenticatedSessionController::class, 'destroy'])->name('logout');
});

// Where an identity provider sends the user back to, to sign in, to link an
// account and to confirm a step-up, so each provider has one redirect URI to
// register. What it's for decides who may finish it, so the controller gives
// it the guest or signed-in middleware (and the changes_middleware for a
// link) itself.
if ($sso) {
    Route::get('/auth/{provider}/callback', [SingleSignOnController::class, 'callback'])
        ->where('provider', '[A-Za-z0-9_-]+')
        ->block()
        ->name('keyring.sso.callback');
}

// The link in a verification email, for whoever opens it. A browser that
// isn't signed in is sent to sign in by the controller, which remembers the
// link first where an unverified account can only sign in after following it.
if (Features::enabled(Features::emailVerification())) {
    Route::get('/email/verify/{id}/{hash}', [EmailVerificationController::class, 'page'])->middleware(['keyring.signed:relative', 'throttle:keyring-pages'])->name('verification.verify');
}

// Emailed links. GET only shows a page with a button and the POST acts, so a
// mail scanner that opens a link changes nothing. The link's token or
// signature is in its URL, and the page posts it in the body, so the request
// that acts doesn't put it in a URL a second time. keyring.signed is
// Laravel's signed middleware, which also logs the links it refuses. The
// pages have a looser limit of their own, so opening them doesn't use up
// the few tries their buttons get.
if (Features::enabled(Features::emailChanges())) {
    Route::get('/email-changes/{change}/confirm/{token}', [EmailChangeController::class, 'page'])->middleware('throttle:keyring-pages')->name('keyring.email.confirm');
    Route::post('/email-changes/{change}/confirm', [EmailChangeController::class, 'confirm'])->middleware('throttle:keyring')->name('keyring.email.confirm.store');
    Route::get('/email-changes/{change}/revert/{token}', [EmailChangeController::class, 'page'])->middleware('throttle:keyring-pages')->name('keyring.email.revert');
    Route::post('/email-changes/{change}/revert', [EmailChangeController::class, 'revert'])->middleware('throttle:keyring')->name('keyring.email.revert.store');
}

if (Features::enabled(Features::devices())) {
    Route::get('/devices/{device}/report', [DeviceController::class, 'page'])->middleware(['keyring.signed:relative', 'throttle:keyring-pages'])->name('keyring.devices.report');
    Route::post('/devices/{device}/report', [DeviceController::class, 'report'])->middleware([ValidatePostedSignature::class, 'throttle:keyring'])->name('keyring.devices.report.store');
}
