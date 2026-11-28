<?php

declare(strict_types=1);

namespace Keyring\Tests\Fixtures;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Database\Eloquent\Attributes\Table;
use Illuminate\Database\Eloquent\Attributes\Unguarded;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Keyring\Concerns\HasKeyring;

#[Unguarded]
#[Hidden('password', 'remember_token')]
#[Table(name: 'users')]
class User extends Authenticatable implements MustVerifyEmail
{
    use HasKeyring, Notifiable;

    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
        ];
    }

    /**
     * For the docs' impersonation examples: whoever's address starts with
     * "admin@".
     */
    public function isAdmin(): bool
    {
        return str_starts_with((string) $this->getAttribute('email'), 'admin@');
    }
}
