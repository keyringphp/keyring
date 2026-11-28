<?php

declare(strict_types=1);

namespace Keyring\Sessions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use Keyring\Enums\Assurance;

/**
 * A signed-in session. Its ID is Keyring's own, kept inside the session, so
 * Laravel's session ID is never stored or logged.
 *
 * A session that moves to a new record leaves the old one behind, naming
 * the new one (replacedBy). It's no longer a session, but its ID can be
 * told from one never issued, and followed to the session it became.
 *
 * Every record a session moves through names the first one (origin), so
 * the session can be told apart from its user's others wherever it is now.
 * The first record names none: its own ID is the origin.
 *
 * A remembered session is one "remember me" may bring back once Laravel's
 * own session has gone, so it's allowed to sit unused for longer.
 *
 * An impersonated session is one someone else is signed in to as this user
 * (Impersonation): it names who (impersonatorId, impersonatorType) and the
 * record of their own session, parked meanwhile (impersonatorSession).
 * That's a registry ID too, so it never leaves the server either.
 *
 * Whose it is takes more than the ID: two user models can have the same
 * IDs. userType says which table the ID is one of. It's the table and not
 * the class, so one account loaded as two classes (an Admin that extends
 * User, on the users table) is still one account, as it is to the guard.
 */
final readonly class RegisteredSession
{
    public function __construct(
        public string $id,
        public string $userId,
        public string $userType,
        public string $guard,
        public ?string $deviceId,
        public Assurance $assurance,
        public ?string $ip,
        public ?string $userAgent,
        public int $authenticatedAt,
        public int $lastActivityAt,
        public int $expiresAt,
        public ?int $revokedAt = null,
        public ?string $replacedBy = null,
        public ?int $replacedAt = null,
        public bool $remembered = false,
        public ?string $origin = null,
        public ?string $impersonatorId = null,
        public ?string $impersonatorType = null,
        public ?string $impersonatorSession = null,
    ) {}

    /**
     * The ID of the record this session started on, which every record it
     * moves to keeps. It's a registry ID: on a remembered session that
     * hasn't moved, it's the value of the "remember me" cookie. Keep it on
     * the server, and use Sessions::handle() anywhere else.
     */
    public function origin(): string
    {
        return $this->origin ?? $this->id;
    }

    /**
     * Whether this is a session of that user: the same model and the same ID.
     */
    public function belongsTo(Authenticatable $user): bool
    {
        return $this->userId === (string) $user->getAuthIdentifier() && $this->userType === self::typeOf($user);
    }

    /**
     * What a user's records carry as userType: the connection and table
     * their ID is unique in. A user that isn't a model has only its class.
     */
    public static function typeOf(Authenticatable $user): string
    {
        return $user instanceof Model ? $user->getConnection()->getName().':'.$user->getTable() : $user::class;
    }

    /**
     * Whether someone else is signed in to this session as its user.
     */
    public function isImpersonated(): bool
    {
        return $this->impersonatorId !== null;
    }

    public function isActive(int $now): bool
    {
        return $this->revokedAt === null && $this->replacedBy === null && $this->expiresAt > $now;
    }

    /**
     * @param  array<string, mixed>  $changes
     */
    #[\NoDiscard]
    public function with(array $changes): self
    {
        return clone ($this, $changes);
    }

    /**
     * The record with every registry ID blanked: its own, the one it moved
     * to, the one it started on, and an impersonator's own. Each is, or was,
     * the value of a "remember me" cookie, so this is what goes anywhere off
     * the server, such as a queued event. A handle can't be worked out from
     * what's left.
     */
    #[\NoDiscard]
    public function withoutIds(): self
    {
        return $this->with(['id' => '', 'replacedBy' => null, 'origin' => null, 'impersonatorSession' => null]);
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'user_id' => $this->userId,
            'user_type' => $this->userType,
            'guard' => $this->guard,
            'device_id' => $this->deviceId,
            'assurance' => $this->assurance->value,
            'ip' => $this->ip,
            'user_agent' => $this->userAgent,
            'authenticated_at' => $this->authenticatedAt,
            'last_activity_at' => $this->lastActivityAt,
            'expires_at' => $this->expiresAt,
            'revoked_at' => $this->revokedAt,
            'replaced_by' => $this->replacedBy,
            'replaced_at' => $this->replacedAt,
            'remembered' => $this->remembered,
            'origin' => $this->origin,
            'impersonator_id' => $this->impersonatorId,
            'impersonator_type' => $this->impersonatorType,
            'impersonator_session' => $this->impersonatorSession,
        ];
    }

    /**
     * Storage columns for some of the fields, e.g. ['lastActivityAt' => 1] to ['last_activity_at' => 1].
     *
     * @param  array<string, mixed>  $changes
     * @return array<string, mixed>
     */
    public static function columns(array $changes): array
    {
        return collect($changes)
            ->mapWithKeys(fn (mixed $value, string $field) => [Str::snake($field) => $value instanceof Assurance ? $value->value : $value])
            ->all();
    }

    /**
     * @param  array<string, mixed>  $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            id: $data['id'],
            userId: (string) $data['user_id'],
            userType: $data['user_type'],
            guard: $data['guard'],
            deviceId: $data['device_id'],
            assurance: Assurance::from((int) $data['assurance']),
            ip: $data['ip'],
            userAgent: $data['user_agent'],
            authenticatedAt: (int) $data['authenticated_at'],
            lastActivityAt: (int) $data['last_activity_at'],
            expiresAt: (int) $data['expires_at'],
            revokedAt: $data['revoked_at'] === null ? null : (int) $data['revoked_at'],
            replacedBy: $data['replaced_by'] ?? null,
            replacedAt: isset($data['replaced_at']) ? (int) $data['replaced_at'] : null,
            remembered: (bool) ($data['remembered'] ?? false),
            origin: $data['origin'] ?? null,
            impersonatorId: isset($data['impersonator_id']) ? (string) $data['impersonator_id'] : null,
            impersonatorType: $data['impersonator_type'] ?? null,
            impersonatorSession: $data['impersonator_session'] ?? null,
        );
    }
}
