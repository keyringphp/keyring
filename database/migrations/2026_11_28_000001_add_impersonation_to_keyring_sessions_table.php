<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Who is signed in to a session as its user, for impersonation: their ID,
 * the connection and table it's one of, and the record of their own session,
 * parked until they stop. Only needed with the "database" session registry
 * driver, and only once Features::impersonation() is on. Other sessions
 * leave the columns out, so they're never needed for anything else.
 */
return new class extends Migration
{
    public function getConnection(): ?string
    {
        return config('keyring.sessions.connection');
    }

    public function up(): void
    {
        Schema::table(config('keyring.sessions.table', 'keyring_sessions'), function (Blueprint $table) {
            $table->string('impersonator_id')->nullable();
            $table->string('impersonator_type')->nullable();
            $table->string('impersonator_session', 64)->nullable();
        });
    }

    public function down(): void
    {
        Schema::table(config('keyring.sessions.table', 'keyring_sessions'), function (Blueprint $table) {
            $table->dropColumn(['impersonator_id', 'impersonator_type', 'impersonator_session']);
        });
    }
};
