<?php

declare(strict_types=1);

namespace Keyring\Sessions;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Connection;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\QueryException;
use Illuminate\Support\Collection;
use Keyring\Contracts\SessionRegistry;
use Keyring\Enums\SessionEndReason;
use Keyring\Support\WithoutBindings;
use LogicException;

class DatabaseSessionRegistry implements SessionRegistry, SweepsSessions
{
    /** The columns the sweep needs, from their own migration. */
    public const array SWEEP_COLUMNS = ['announced_at', 'end_reason', 'announce_attempts', 'announce_after'];

    /** The columns an impersonated session needs, from their own migration. */
    public const array IMPERSONATION_COLUMNS = ['impersonator_id', 'impersonator_type', 'impersonator_session'];

    /** What end_reason says for a record everyone was signed out of: EveryoneSignedOut announces it, not one of its own. */
    public const string EVERYONE = 'everyone_signed_out';

    /** How many IDs one statement names: SQLite takes the fewest. */
    protected const int CHUNK = 500;

    /** Whether the sweep's notes are kept, once found to be (notes). */
    protected ?bool $notes = null;

    /** Whether the impersonation columns are there, once found to be (canImpersonate). */
    protected bool $impersonates = false;

    public function __construct(
        protected ConnectionInterface $connection,
        protected string $table = 'keyring_sessions',
    ) {}

    public function save(#[\SensitiveParameter] RegisteredSession $session): void
    {
        // Never clear revoked_at from a stale copy: a revocation that lands
        // between reading and saving a record must stick. So must the
        // record that replaced it.
        $row = $session->toArray();

        // A record a session started on has no origin to write. Leaving the
        // column out keeps signing in working on a table that's still
        // waiting for the migration that adds it.
        if ($row['origin'] === null) {
            unset($row['origin']);
        }

        // The same for the impersonation columns, which only an
        // impersonated session fills, so an app that never impersonates
        // anyone needs no migration for them.
        if ($row['impersonator_id'] === null) {
            unset($row['impersonator_id'], $row['impersonator_type'], $row['impersonator_session']);
        } elseif (! $this->canImpersonate()) {
            throw new LogicException(sprintf(
                'The [%s] table is missing the columns Keyring keeps an impersonation in (%s). Publish and run Keyring\'s migrations: php artisan keyring:install, then php artisan migrate.',
                $this->table,
                implode(', ', self::IMPERSONATION_COLUMNS),
            ));
        }

        $this->withoutBindings(fn () => $this->query()->upsert([$row], ['id'], array_values(array_diff(array_keys($row), ['id', 'revoked_at', 'replaced_by', 'replaced_at']))));
    }

    public function find(#[\SensitiveParameter] string $id): ?RegisteredSession
    {
        $row = $this->withoutBindings(fn () => $this->query()->find($id));

        return $row === null ? null : RegisteredSession::fromArray((array) $row);
    }

    public function forUser(Authenticatable $user): Collection
    {
        return $this->activeFor($user)
            ->where('expires_at', '>', now()->getTimestamp())
            ->latest('last_activity_at')
            ->get()
            ->map(fn (object $row) => RegisteredSession::fromArray((array) $row));
    }

    public function update(#[\SensitiveParameter] string $id, array $changes): void
    {
        $this->withoutBindings(fn () => $this->query()->where('id', $id)->update(RegisteredSession::columns($changes)));
    }

    /**
     * The row is read with a lock and revoked in the same transaction, so
     * nothing changes it in between: of two calls the second waits, then
     * finds it revoked and returns null. The update only matches a record
     * that isn't revoked yet, as a second guard. A locking read is always
     * made on the write connection, and sees the latest committed row even
     * inside a caller's MySQL transaction that took its snapshot earlier. It
     * can't deadlock with replace() or revokeEveryone(): this takes one lock
     * (the row, or on MySQL the gap where a missing one would be) and
     * nothing after it, so it never holds one while waiting for another.
     */
    public function revoke(#[\SensitiveParameter] string $id): ?RegisteredSession
    {
        return $this->noting(function () use ($id) {
            // Settled before this method's transaction. Inside a caller's
            // (RowLock::hold) the queries that settle it run in a savepoint,
            // so one that fails leaves that transaction usable (notes).
            $reason = $this->reason();

            return $this->withoutBindings(fn () => $this->connection->transaction(function () use ($id, $reason) {
                $row = $this->query()->lockForUpdate()->find($id);
                $session = $row === null ? null : RegisteredSession::fromArray((array) $row);

                if ($session === null || $session->revokedAt !== null) {
                    return null;
                }

                $now = now()->getTimestamp();
                $revoked = $this->query()->where('id', $id)->whereNull('revoked_at')->update(['revoked_at' => $now, ...$reason]) === 1;

                return $revoked ? $session->with(['revokedAt' => $now]) : null;
            }));
        });
    }

    /**
     * The update only matches a record still in use, and holds its row until
     * the new record is stored. Of two requests at the same moment the
     * second waits, then matches nothing.
     */
    public function replace(#[\SensitiveParameter] string $id, #[\SensitiveParameter] RegisteredSession $successor, bool $revoke = false): bool
    {
        return $this->withoutBindings(fn () => $this->connection->transaction(function () use ($id, $successor, $revoke) {
            $now = now()->getTimestamp();

            $replaced = $this->query()->where('id', $id)->whereNull('revoked_at')->whereNull('replaced_by')->update([
                'replaced_by' => $successor->id,
                'replaced_at' => $now,
                ...$revoke ? ['revoked_at' => $now] : [],
            ]) === 1;

            if ($replaced) {
                $this->save($successor);
            }

            return $replaced;
        }));
    }

    public function revokeAll(Authenticatable $user, #[\SensitiveParameter] ?string $except = null): Collection
    {
        return $this->revokeFound($this->activeFor($user)->when($except, fn (Builder $query) => $query->where('id', '!=', $except)));
    }

    public function revokeDevice(Authenticatable $user, string $deviceId): Collection
    {
        return $this->revokeFound($this->activeFor($user)->where('device_id', $deviceId));
    }

    /**
     * Find the records with a lock, then revoke them by ID in the same
     * transaction, 500 at a time, so a user
     * with years of expired records that were never pruned doesn't make one
     * statement too big. A locking read is always made on the write
     * connection, and reads the latest committed rows, not the snapshot of
     * a caller's MySQL transaction that started earlier: a session signed
     * in since then is found and revoked. It takes the locks the single
     * UPDATE this used to be took (on MySQL, the user's range of the
     * index), so a sign in for this user waits until it's done, and the
     * rows can't change between the read and the update. So the records
     * returned are exactly the ones revoked, and the update matches what
     * the single UPDATE matched. Of two calls at once the second waits, and
     * then finds nothing left to revoke. Rows are read in ID order, so two
     * calls on PostgreSQL lock the rows they share in the same order.
     *
     * @return Collection<int, RegisteredSession>
     */
    protected function revokeFound(Builder $query): Collection
    {
        return $this->noting(function () use ($query) {
            $reason = $this->reason();

            return $this->withoutBindings(fn () => $this->connection->transaction(function () use ($query, $reason) {
                $now = now()->getTimestamp();

                $found = (clone $query)->orderBy('id')->lockForUpdate()->get()->map(fn (object $row) => RegisteredSession::fromArray((array) $row));

                $found->pluck('id')->chunk(self::CHUNK)->each(
                    fn (Collection $ids) => $this->query()->whereIn('id', $ids->values())->whereNull('revoked_at')->whereNull('replaced_by')->update(['revoked_at' => $now, ...$reason]),
                );

                return $found->map(fn (RegisteredSession $session) => $session->with(['revokedAt' => $now]));
            }));
        });
    }

    /**
     * A thousand at a time, found first and then revoked by ID, until none
     * are left. A session moving to a new record holds its old one until the
     * new one is stored, so the round that comes to the old one waits, and
     * the next finds where it went. Replaced records are revoked with the
     * rest, which is what keeps the rounds coming. Rows are locked one by
     * one this way, never a range, so a sign in or a move isn't held up or
     * deadlocked. A session that started after this did is left alone, so
     * new sign ins can't keep it going. Each round reads from the database
     * it writes to: a replica that lags would keep handing back what the
     * last round revoked.
     */
    public function revokeEveryone(): void
    {
        $now = now()->getTimestamp();

        $this->noting(function () use ($now) {
            // EveryoneSignedOut announces them all at once, so they're marked
            // for it, and not for announcing one by one. They count as
            // announced once it has gone out (announcedEveryone), and the
            // sweep sends it again if it didn't.
            $announced = $this->notes() ? ['end_reason' => self::EVERYONE] : [];

            do {
                $ids = $this->query()
                    ->useWritePdo()
                    ->whereNull('revoked_at')
                    ->where('authenticated_at', '<=', $now)
                    ->where('expires_at', '>', $now)
                    ->limit(1000)
                    ->pluck('id');

                $this->withoutBindings(fn () => $this->query()->whereIn('id', $ids)->whereNull('revoked_at')->update(['revoked_at' => $now, ...$announced]));
            } while ($ids->isNotEmpty());
        });
    }

    /**
     * Before the migration the sweep needs, every record that has expired or
     * been revoked goes, as it always has. After it, whether or not a sweep
     * is scheduled, a record goes once nothing is left to announce for it:
     * a replaced one when it expires, a revoked one once it's announced or
     * the sweep has given up on it (Sweep::GIVE_UP_AFTER). One that has
     * timed out is left for the sweep to end, until a day past its expiry:
     * with no sweep running, or one that can't keep up, the table can't
     * grow without end.
     */
    public function prune(): int
    {
        $now = now()->getTimestamp();

        if (! $this->canSweep()) {
            return $this->query()
                ->where('expires_at', '<=', $now)
                ->orWhere(fn (Builder $query) => $query->whereNotNull('revoked_at')->whereNull('replaced_by'))
                ->delete();
        }

        // A record "remember me" moved a session to (one with an origin)
        // stays until it expires, ended or not: it's what a used cookie is
        // followed to, so that turning up again still raises the alarm
        // (RememberMeReused) after the sweep ended the session. One that
        // ended for timing out stays as long as it would have unended, a
        // day past its expiry, so a browser that comes back is told it
        // timed out, as it would be had nothing swept it.
        return $this->query()
            ->where(fn (Builder $query) => $query->whereNotNull('replaced_by')->where('expires_at', '<=', $now))
            ->orWhere(fn (Builder $query) => $query->whereNotNull('revoked_at')->whereNull('replaced_by')
                ->where(fn (Builder $query) => $query->whereNotNull('announced_at')->orWhere('revoked_at', '<=', $now - Sweep::GIVE_UP_AFTER))
                ->where(fn (Builder $query) => $query->whereNull('origin')->orWhere('expires_at', '<=', $now))
                ->where(fn (Builder $query) => $query->whereNull('end_reason')
                    ->orWhereNotIn('end_reason', [SessionEndReason::Idle->value, SessionEndReason::Expired->value])
                    ->orWhere('expires_at', '<=', $now - Sweep::GIVE_UP_AFTER)))
            ->orWhere(fn (Builder $query) => $query->whereNull('revoked_at')->where('expires_at', '<=', $now - Sweep::GIVE_UP_AFTER))
            ->delete();
    }

    /**
     * Asks the database itself, and keeps the answer, either way, in the
     * cache for every process (Sweep::SCHEMA_CACHED_FOR). keyring:sweep and
     * keyring:prune come here, so wherever they run, a stale answer is put
     * right within one run.
     */
    public function canSweep(): bool
    {
        $can = $this->hasSweepColumns();

        $this->notes = $can ?: null;
        rescue(fn () => cache()->put($this->schemaKey(), $can, Sweep::SCHEMA_CACHED_FOR), report: false);

        return $can;
    }

    protected function hasSweepColumns(): bool
    {
        return $this->connection instanceof Connection
            && $this->connection->getSchemaBuilder()->hasColumns($this->table, self::SWEEP_COLUMNS);
    }

    /**
     * Whether the table has the impersonation columns, asked before the
     * first impersonated session is saved, so a missing migration says so
     * rather than failing on the insert. A yes is kept for the process, and
     * in the cache for every process for a few minutes
     * (Sweep::SCHEMA_CACHED_FOR), so starting makes no schema query after
     * the first. A no isn't kept: the next start asks again, and works as
     * soon as the migration has run.
     */
    protected function canImpersonate(): bool
    {
        if ($this->impersonates) {
            return true;
        }

        $key = 'keyring:sessions:impersonatable:'.sha1($this->connection->getDatabaseName().'|'.($this->connection instanceof Connection ? $this->connection->getTablePrefix() : '').$this->table);

        if ($this->contained(fn () => cache()->get($key), null) === true) {
            return $this->impersonates = true;
        }

        $can = $this->connection instanceof Connection
            && $this->connection->getSchemaBuilder()->hasColumns($this->table, self::IMPERSONATION_COLUMNS);

        if ($can) {
            $this->contained(fn () => cache()->put($key, true, Sweep::SCHEMA_CACHED_FOR), null);
        }

        return $this->impersonates = $can;
    }

    /**
     * Whether to write the notes the sweep reads: why each record ended as
     * it's revoked, and which were announced. The first process that needs
     * to know asks the database, and keeps the answer, yes or no, in the
     * cache for a few minutes (Sweep::SCHEMA_CACHED_FOR). Every process then
     * takes the cache's word, so a request that ends a session makes no
     * schema query. A yes holds for the process from then on. So once the
     * migration has run, notes start within those minutes, and at once
     * where keyring:sweep or keyring:prune runs, which ask the database
     * themselves. A record revoked in those minutes has no note, and the
     * sweep announces it a second time. Once it's rolled back, a revocation
     * that finds the columns gone is made again without them (noting). The
     * warning that the migration is missing is logged once a day.
     *
     * Its queries run in a savepoint when a transaction is open on the
     * registry's connection, so one that fails (a database cache store on
     * the same connection, say) can't leave a caller's transaction unusable
     * on PostgreSQL.
     */
    protected function notes(): bool
    {
        if ($this->notes !== null) {
            return $this->notes;
        }

        $can = $this->contained(fn () => cache()->get($this->schemaKey()), null);

        // The process that found the columns missing has warned already.
        if ($can === false) {
            return false;
        }

        if ($can !== true) {
            $can = $this->contained(fn () => $this->hasSweepColumns(), false);
            $this->contained(fn () => cache()->put($this->schemaKey(), $can, Sweep::SCHEMA_CACHED_FOR), null);
        }

        if ($can) {
            return $this->notes = true;
        }

        if ($this->contained(fn () => cache()->add($this->schemaKey().':warned', true, Sweep::GIVE_UP_AFTER), true)) {
            rescue(fn () => logger()->warning("The [{$this->table}] table is missing the columns Keyring notes announced sessions in. Sessions end and are announced as usual, but none is announced again if its announcement is lost, and keyring:sweep won't run. Publish and run Keyring's migrations: php artisan keyring:install, then php artisan migrate."), report: false);
        }

        return false;
    }

    /**
     * Run a revocation, and once more without the notes when it failed for
     * their columns being gone: the migration was rolled back after this
     * process, or the cache, found them. What the cache said is forgotten,
     * so the next revocation asks the database again. The retry notes
     * nothing, whatever the cache says by then: a forget that failed, or
     * another process that still says yes, can't send it to the missing
     * columns too. A sign-out never fails for the sweep's sake.
     *
     * Inside a caller's transaction the first try is a savepoint of its own,
     * so its failure rolls back only that try: on PostgreSQL a failed
     * statement aborts the whole transaction, and the retry, and whatever
     * the caller does next, would be refused. Outside one, revoke() and
     * revokeFound() roll back their own transaction, and revokeEveryone()
     * fails on its first update, which names the columns, before it has
     * written anything. It isn't put in a transaction there: its rounds
     * would then hold every row they revoke until the last.
     *
     * @template TResult
     *
     * @param  Closure(): TResult  $revoke
     * @return TResult
     */
    protected function noting(Closure $revoke): mixed
    {
        try {
            return $this->connection->transactionLevel() > 0 ? $this->connection->transaction($revoke) : $revoke();
        } catch (QueryException $e) {
            if ($this->notes !== true || ! $this->lostColumns($e)) {
                throw $e;
            }

            $this->contained(fn () => cache()->forget($this->schemaKey()), null);
            $this->notes = false;

            try {
                return $revoke();
            } finally {
                $this->notes = null;
            }
        }
    }

    /**
     * Whether a query failed for naming one of the sweep's columns that the
     * table doesn't have: MySQL's and PostgreSQL's "undefined column", or
     * SQLite's words for it. Read from the database's own error, not the
     * exception's message, which has the SQL in it and so always names the
     * columns.
     */
    protected function lostColumns(QueryException $e): bool
    {
        $message = (string) $e->getPrevious()?->getMessage();
        $undefined = in_array($e->errorInfo[0] ?? null, ['42S22', '42703'], true)
            || str_contains($message, 'no such column')
            || str_contains($message, 'has no column named');

        return $undefined && array_any(self::SWEEP_COLUMNS, fn (string $column) => str_contains($message, $column));
    }

    /**
     * Run a query whose failure is no one's concern, in a savepoint of its
     * own when the registry's connection has a transaction open. Its answer,
     * or $otherwise when it fails.
     *
     * @template TResult
     *
     * @param  Closure(): TResult  $query
     * @param  TResult  $otherwise
     * @return TResult
     */
    protected function contained(Closure $query, mixed $otherwise): mixed
    {
        return rescue(
            fn () => $this->connection->transactionLevel() > 0 ? $this->connection->transaction($query) : $query(),
            $otherwise,
            report: false,
        );
    }

    protected function schemaKey(): string
    {
        return self::schemaCacheKey($this->connection, $this->table);
    }

    /**
     * Where the cache keeps whether a sessions table has the columns the
     * sweep needs: one key for each table, with the connection's prefix,
     * in each database, whichever connection reaches it.
     */
    public static function schemaCacheKey(ConnectionInterface $connection, string $table): string
    {
        $prefix = $connection instanceof Connection ? $connection->getTablePrefix() : '';

        return 'keyring:sessions:sweepable:'.sha1($connection->getDatabaseName().'|'.$prefix.$table);
    }

    /**
     * What a revocation writes besides its time: why, if the notes are kept,
     * so a record whose announcement is lost is announced again for the
     * right reason. It's the reason in force where the call was made
     * (AnnouncingSessionRegistry::because).
     *
     * @return array<string, string>
     */
    protected function reason(): array
    {
        return $this->notes() ? ['end_reason' => AnnouncingSessionRegistry::reason()->value] : [];
    }

    /**
     * The records that have timed out are found oldest first, by the time
     * each timed out, on the write connection: each kind with its own query
     * on its own index. One more than $limit is asked for, to say whether
     * more are left. Then they're locked by ID in one statement, sorted by
     * the database, so of two sweeps the second waits for the first. On
     * PostgreSQL that's the order revokeAll() locks a user's rows in too.
     * On MySQL revokeAll() locks them in the order it reads its index,
     * which is by user, then ID, under the same collation, so for the rows
     * of one user the two agree. A sign in past sessions.max sorts in PHP,
     * which can differ: see Sessions::register.
     * Locking by ID takes the rows alone, not a range of an index a sign-out
     * is writing into. Whether each has timed out is decided again from the
     * locked row, against one $now: one revoked or moved meanwhile is left,
     * and so is one a request used a moment ago. The rest are ended by ID,
     * still only if neither revoked nor replaced, so what's returned is
     * exactly what this call ended. A deadlock is tried again, twice.
     */
    public function sweep(int $now, ?int $idle, ?int $rememberedIdle, int $limit): array
    {
        return $this->withoutBindings(fn () => $this->connection->transaction(function () use ($now, $idle, $rememberedIdle, $limit) {
            $open = fn () => $this->query()->useWritePdo()->whereNull('revoked_at')->whereNull('replaced_by');

            /** @var array<string, int> $due when each timed out, by ID */
            $due = $open()->where('expires_at', '<=', $now)->oldest('expires_at')->limit($limit + 1)->pluck('expires_at', 'id')->map(fn (mixed $at) => (int) $at)->all();

            foreach ([false => $idle, true => $rememberedIdle] as $remembered => $limitFor) {
                if ($limitFor === null) {
                    continue;
                }

                $open()->where('remembered', (bool) $remembered)->where('last_activity_at', '<', $now - $limitFor)
                    ->oldest('last_activity_at')->limit($limit + 1)->pluck('last_activity_at', 'id')
                    ->each(function (mixed $at, string $id) use (&$due, $limitFor) {
                        $due[$id] = min($due[$id] ?? PHP_INT_MAX, (int) $at + $limitFor + 1);
                    });
            }

            asort($due);
            $ids = array_map(strval(...), array_keys(array_slice($due, 0, $limit, preserve_keys: true)));

            // Locked in one statement, in the order the database sorts IDs
            // in, as revokeAll() locks a user's. Only SQLite, which locks
            // the whole database to write, takes them a chunk at a time.
            $ended = new Collection($ids)->chunk($this->connection instanceof Connection && $this->connection->getDriverName() === 'sqlite' ? self::CHUNK : Sweep::MAX_LIMIT)
                ->flatMap(fn (Collection $chunk) => $this->query()->whereIn('id', $chunk->values()->all())->orderBy('id')->lockForUpdate()->get())
                ->map(fn (object $row) => RegisteredSession::fromArray((array) $row))
                ->map(fn (RegisteredSession $session) => match (true) {
                    $session->revokedAt !== null, $session->replacedBy !== null => null,
                    $session->expiresAt <= $now => new EndedSession($session->with(['revokedAt' => $now]), SessionEndReason::Expired),
                    $this->idledOut($session, $now, $idle, $rememberedIdle) => new EndedSession($session->with(['revokedAt' => $now]), SessionEndReason::Idle),
                    default => null,
                })
                ->filter()
                ->values();

            foreach ([SessionEndReason::Expired, SessionEndReason::Idle] as $reason) {
                $ended->filter(fn (EndedSession $one) => $one->reason === $reason)->map(fn (EndedSession $one) => $one->session->id)->chunk(self::CHUNK)->each(
                    fn (Collection $chunk) => $this->query()->whereIn('id', $chunk->values()->all())->whereNull('revoked_at')->whereNull('replaced_by')->update(['revoked_at' => $now, 'end_reason' => $reason->value]),
                );
            }

            return ['ended' => $ended, 'more' => count($due) > $limit];
        }, attempts: 3));
    }

    /**
     * Unused for longer than the limit for its kind, as Sessions::idledOut()
     * has it: strictly more seconds than the limit since its last activity.
     */
    protected function idledOut(RegisteredSession $session, int $now, ?int $idle, ?int $rememberedIdle): bool
    {
        $limit = $session->remembered ? $rememberedIdle : $idle;

        return $limit !== null && $now - $session->lastActivityAt > $limit;
    }

    /**
     * Oldest first, one more than $limit to say whether more are left. Ones
     * whose announcement failed wait for their next try (announce_after). A
     * record revoked before this driver kept why has no reason, and is
     * announced again as plain "revoked".
     */
    public function unannounced(int $from, int $until, int $now, int $limit): array
    {
        $found = $this->query()->useWritePdo()
            ->whereNull('announced_at')
            ->where('revoked_at', '>', $from)
            ->where('revoked_at', '<=', $until)
            ->whereNull('replaced_by')
            ->where(fn (Builder $query) => $query->whereNull('end_reason')->orWhere('end_reason', '!=', self::EVERYONE))
            ->where(fn (Builder $query) => $query->whereNull('announce_after')->orWhere('announce_after', '<=', $now))
            ->oldest('revoked_at')
            ->orderBy('id')
            ->limit($limit + 1)
            ->get();

        return [
            'ended' => $found->take($limit)->map(fn (object $row) => new EndedSession(RegisteredSession::fromArray((array) $row), SessionEndReason::tryFrom((string) $row->end_reason) ?? SessionEndReason::Revoked))->values(),
            'more' => $found->count() > $limit,
        ];
    }

    /**
     * A failure counts against the record, and puts its next try off for
     * longer each time (Sweep::retryAfter), until the sweep gives up on it
     * a day after its revocation. In a transaction of its own, so a failed
     * write leaves the caller's transaction usable.
     */
    public function announced(#[\SensitiveParameter] array $announced, #[\SensitiveParameter] array $failed, int $at): void
    {
        if (! $this->notes()) {
            return;
        }

        $this->withoutBindings(fn () => $this->connection->transaction(function () use ($announced, $failed, $at) {
            foreach (array_chunk($announced, self::CHUNK) as $chunk) {
                $this->query()->whereIn('id', $chunk)->update(['announced_at' => $at]);
            }

            foreach (array_chunk($failed, self::CHUNK) as $chunk) {
                $this->failed($this->query()->whereIn('id', $chunk), $at);
            }
        }));
    }

    /**
     * Count a failed try against each record, and put its next one off
     * (Sweep::retryAfter), by how many tries it has had.
     */
    protected function failed(Builder $records, int $at): void
    {
        // Most tries first, so none is counted twice.
        (clone $records)->distinct()->orderByDesc('announce_attempts')->pluck('announce_attempts')
            ->each(fn (mixed $attempts) => (clone $records)->where('announce_attempts', (int) $attempts)->update([
                'announce_attempts' => (int) $attempts + 1,
                'announce_after' => $at + Sweep::retryAfter((int) $attempts + 1),
            ]));
    }

    /**
     * The moments everyone was signed out at, between $from and $until,
     * whose EveryoneSignedOut never went out and is due a try at $now,
     * latest first.
     *
     * @return list<int>
     */
    public function everyoneUnannounced(int $from, int $until, int $now): array
    {
        return $this->query()->useWritePdo()
            ->where('end_reason', self::EVERYONE)
            ->whereNull('announced_at')
            ->where('revoked_at', '>', $from)
            ->where('revoked_at', '<=', $until)
            ->where(fn (Builder $query) => $query->whereNull('announce_after')->orWhere('announce_after', '<=', $now))
            ->distinct()
            ->latest('revoked_at')
            ->pluck('revoked_at')
            ->map(fn (mixed $at) => (int) $at)
            ->values()
            ->all();
    }

    /**
     * Note how the EveryoneSignedOut for the sign-out made between $from and
     * $until went. One that went out settles every sign-out of everyone up
     * to $until, earlier ones that were lost included: each ended sessions
     * that signed in before its moment, and this one's moment is later. One
     * that didn't is tried again later, as one record is. A thousand records
     * at a time, as revokeEveryone() revoked them, each in a statement of
     * its own.
     */
    public function everyoneAnnounced(int $from, int $until, bool $announced, int $at): void
    {
        if (! $this->notes()) {
            return;
        }

        $records = fn () => $this->query()->useWritePdo()->where('end_reason', self::EVERYONE)->whereNull('announced_at')
            ->where('revoked_at', '<=', $until)
            ->unless($announced, fn (Builder $query) => $query->where('revoked_at', '>=', $from));

        $this->withoutBindings(function () use ($records, $announced, $at) {
            for ($after = ''; ($ids = $records()->where('id', '>', $after)->orderBy('id')->limit(1000)->pluck('id')->map(strval(...)))->isNotEmpty(); $after = $ids->last()) {
                $announced
                    ? $this->query()->whereIn('id', $ids->all())->update(['announced_at' => $at])
                    : $this->failed($this->query()->whereIn('id', $ids->all()), $at);
            }
        });
    }

    /**
     * The user's sessions that haven't been revoked or replaced.
     */
    protected function activeFor(Authenticatable $user): Builder
    {
        return $this->query()
            ->where('user_type', RegisteredSession::typeOf($user))
            ->where('user_id', (string) $user->getAuthIdentifier())
            ->whereNull('revoked_at')
            ->whereNull('replaced_by');
    }

    /**
     * The connection the records are kept on, whose transactions decide
     * when a revocation holds (AnnouncingSessionRegistry).
     */
    public function connection(): ConnectionInterface
    {
        return $this->connection;
    }

    /**
     * Run statements that name records by their IDs, and fail without them
     * (WithoutBindings). Wrapped around whole transactions, so Laravel's
     * own retries and rollbacks see the original.
     *
     * @template TResult
     *
     * @param  Closure(): TResult  $statements
     * @return TResult
     */
    protected function withoutBindings(Closure $statements): mixed
    {
        return WithoutBindings::run($statements);
    }

    protected function query(): Builder
    {
        return $this->connection->table($this->table);
    }
}
