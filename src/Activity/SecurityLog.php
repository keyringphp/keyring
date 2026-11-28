<?php

declare(strict_types=1);

namespace Keyring\Activity;

use Closure;
use DateTimeInterface;
use Illuminate\Cache\RateLimiter;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Query\Builder as QueryBuilder;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Context;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Keyring\Devices\UserAgent;
use Keyring\Enums\Severity;
use Keyring\Features;
use Keyring\Impersonation\Impersonation;
use Keyring\KeyringManager;
use Keyring\Models\SecurityEvent;
use Keyring\Support\Collation;
use Keyring\Support\Duration;
use Throwable;

/**
 * Writes and reads the security log. Never records secrets, codes, tokens
 * or session IDs.
 */
class SecurityLog
{
    /**
     * Where Keyring keeps the ID it gives a request, in Laravel's hidden
     * context, when the app hasn't given it one.
     */
    public const string REQUEST_ID = 'keyring_request_id';

    /**
     * Every entry type Keyring writes, in the order the docs list them. An
     * app's or a package's own types are any others.
     */
    public const array TYPES = [
        'signed_in', 'confirmed', 'factor_failed', 'second_factor_failed', 'locked_out', 'rate_limited',
        'account_locked', 'signed_out', 'authenticator_added', 'authenticator_removed', 'recovery_codes_generated',
        'recovery_code_used', 'new_device', 'device_revoked', 'device_reported', 'sessions_revoked', 'session_ended',
        'session_resumed', 'remember_me_reused', 'email_change_requested', 'email_changed', 'email_change_reverted',
        'password_changed', 'password_reset', 'protection_bypassed', 'clone_suspected', 'risk_step_up',
        'risk_reauthenticate', 'risk_notified', 'risk_password_change', 'risk_denied', 'risk_locked',
        'risk_revoked_sessions', 'access_refused', 'enrollment_refused', 'authenticator_removal_refused',
        'link_refused', 'verification_refused', 'refusals_limited', 'impersonation_started', 'impersonation_ended',
        'impersonation_refused',
    ];

    public function __construct(
        protected KeyringManager $keyring,
    ) {}

    /**
     * Log an event: in keyring_events with Features::securityLog(), and in
     * the app's log without it, so it's always recorded somewhere. An entry
     * the table won't take is reported and goes to the app's log instead,
     * and one whose details can't be kept is reported and logged without
     * them.
     *
     * @param  array<string, mixed>  $meta
     */
    public function record(string $type, ?Authenticatable $user = null, ?string $factor = null, ?string $device = null, array $meta = [], ?Severity $severity = null): ?SecurityEvent
    {
        return rescue(function () use ($type, $user, $factor, $device, $meta, $severity) {
            try {
                $event = $this->entry($type, $user, $factor, $device, $meta, $severity);
            } catch (Throwable $e) {
                report($e);

                $event = $this->entry($type, $user, $factor, $device, [], $severity);
            }

            return $this->keep($event, orWrite: true);
        });
    }

    /**
     * Log an event that must not happen unlogged. A failed write is thrown,
     * so whatever was about to happen doesn't. The savepoint leaves the
     * caller's transaction usable on Postgres.
     *
     * @param  array<string, mixed>  $meta
     */
    public function recordOrFail(string $type, ?Authenticatable $user = null, ?string $factor = null, ?string $device = null, array $meta = [], ?Severity $severity = null): ?SecurityEvent
    {
        return $this->keep($this->entry($type, $user, $factor, $device, $meta, $severity));
    }

    /**
     * Log something that was refused. Whoever was refused can ask again as
     * often as they like, and the log is kept for months, so only so many
     * entries of one type are written about one account, or from one IP
     * address when the entry names nobody ("security_log.refusals" every
     * "refusals_per"). The first one left out is marked by a
     * "refusals_limited" entry, so the log says where it stopped counting.
     *
     * With $once, a refusal that repeats is written once every $for seconds:
     * a lock is logged when it starts, not each time it turns someone away.
     *
     * @param  array<string, mixed>  $meta
     */
    public function recordRefusal(string $type, ?Authenticatable $user = null, ?string $factor = null, ?string $device = null, array $meta = [], ?string $once = null, int $for = 60): ?SecurityEvent
    {
        return rescue(function () use ($type, $user, $factor, $device, $meta, $once, $for) {
            // Asked for when an entry is written, never when the app boots:
            // building the limiter takes its cache store.
            $limiter = app(RateLimiter::class);
            $about = $type.'|'.($user instanceof Model ? $user->getMorphClass().':'.$user->getKey() : 'ip:'.request()->ip());

            if ($once !== null && ! $limiter->attempt('keyring-log:'.sha1($about.'|'.$once), 1, fn () => true, max($for, 1))) {
                return null;
            }

            $limit = config('keyring.security_log.refusals');

            if ($limit === null) {
                return $this->record($type, $user, $factor, $device, $meta);
            }

            $written = $limiter->hit('keyring-log:'.sha1($about), Duration::seconds(config('keyring.security_log.refusals_per')));

            return match (true) {
                $written <= $limit => $this->record($type, $user, $factor, $device, $meta),
                $written === $limit + 1 => $this->record('refusals_limited', $user, meta: ['type' => $type]),
                default => null,
            };
        });
    }

    /**
     * Recent security activity, newest first, for a settings page. Leaves
     * out the unlistedActivityTypes(): entries about the user that aren't
     * something they did.
     *
     * @return Collection<int, SecurityEvent>
     */
    public function activity(Authenticatable&Model $user, int $limit = 25): Collection
    {
        return $this->query($user)
            ->whereNotIn('type', $this->unlistedActivityTypes())
            ->latest('created_at')
            ->latest('id')
            ->limit($limit)
            ->get();
    }

    /**
     * The types activity() leaves out, from "security_log.unlisted", for an
     * app's own activity query too. Plus the impersonation types when
     * "impersonation.show_in_activity" is false: the one way to leave out
     * any of Keyring's, and the app's alone to take, since a package that
     * could would hide an impersonation from the user it was of. It's read while a page is built, so
     * anything but an array, from a config cached before the option existed
     * say, leaves out nothing rather than breaking the page. An entry that
     * isn't a string is passed over, since a null would leave out every
     * entry, and so would a 0 on MySQL. Only that entry: several packages
     * may add to the list, and one bad entry shouldn't undo the others.
     * Keyring's own types are passed over too, in any spelling a database
     * would take for them: on MySQL, Laravel's default collation takes
     * "Signed_Out " for "signed_out". A package adds its types where the
     * app doesn't see them, and one of Keyring's there would take the
     * user's real sign ins or sign outs off their page.
     *
     * @return list<string>
     */
    public function unlistedActivityTypes(): array
    {
        $types = config('keyring.security_log.unlisted');
        $impersonation = config('keyring.impersonation.show_in_activity') === false ? ['impersonation_started', 'impersonation_ended'] : [];

        if (! is_array($types)) {
            return $impersonation;
        }

        $keyrings = array_map(Collation::fold(...), self::TYPES);

        return [...array_values(array_filter($types, fn (mixed $type) => is_string($type) && ! in_array(Collation::fold($type), $keyrings, true))), ...$impersonation];
    }

    /**
     * Unseen events worth asking "was this you?" about. Marks them seen.
     * With $since, only those logged after that moment: the rest stay unseen
     * for whoever may see them.
     *
     * @return Collection<int, SecurityEvent>
     */
    public function pullAlerts(Authenticatable&Model $user, ?DateTimeInterface $since = null): Collection
    {
        return $this->safely(function () use ($user, $since) {
            $alerts = $this->query($user)
                ->whereIn('type', config('keyring.security_log.alerts'))
                ->whereNull('seen_at')
                ->when($since, fn (Builder $query) => $query->where('created_at', '>', $since))
                ->latest('created_at')
                ->get();

            if ($alerts->isNotEmpty()) {
                $this->keyring->securityEventModel()::query()->whereKey($alerts->modelKeys())->update(['seen_at' => now()]);
            }

            return $alerts;
        }, new Collection);
    }

    /**
     * How many events of a type the user had recently. Given another type
     * as $since, only those after the user's last event of that one: the
     * failures since they last signed in, say.
     */
    public function count(Authenticatable&Model $user, string $type, int $withinSeconds, ?string $since = null): int
    {
        return $this->safely(function () use ($user, $type, $withinSeconds, $since) {
            // IDs are ULIDs, so a later entry has a greater one, also when
            // both were written within the same second.
            $last = $since === null ? null : $this->query($user)->where('type', $since)->max('id');

            return $this->query($user)
                ->where('type', $type)
                ->where('created_at', '>=', now()->subSeconds($withinSeconds))
                ->when($last !== null, fn (Builder $query) => $query->where('id', '>', $last))
                ->count();
        }, 0);
    }

    /**
     * How many accounts had events of a type recently from the IP address
     * Keyring records for this request, leaving out $except's own. Entries
     * that name nobody can't be told apart, so together they count as one.
     * With no recorded address there's nothing to match, and it's 0.
     */
    public function accountsFrom(Request $request, string $type, int $withinSeconds, ?Model $except = null): int
    {
        $ip = $this->keyring->recordedIp($request);

        if ($ip === null) {
            return 0;
        }

        return $this->safely(function () use ($ip, $type, $withinSeconds, $except) {
            $accounts = $this->keyring->securityEventModel()::query()
                ->toBase()
                ->select(['authenticatable_type', 'authenticatable_id'])
                ->distinct()
                ->where('type', $type)
                ->where('ip', $ip)
                ->where('created_at', '>=', now()->subSeconds($withinSeconds));

            // Spelled out for entries with no user: NOT on a comparison with
            // NULL is NULL, which would leave them out too.
            if ($except !== null) {
                $accounts->where(fn (QueryBuilder $query) => $query
                    ->whereNull('authenticatable_id')
                    ->orWhere('authenticatable_type', '!=', $except->getMorphClass())
                    ->orWhere('authenticatable_id', '!=', $except->getKey()));
            }

            return $accounts->newQuery()->fromSub($accounts, 'accounts')->count();
        }, 0);
    }

    /**
     * The entry for an event, before it's kept anywhere.
     *
     * @param  array<string, mixed>  $meta
     */
    protected function entry(string $type, ?Authenticatable $user, ?string $factor, ?string $device, array $meta, ?Severity $severity): SecurityEvent
    {
        $impersonated = $user !== null && $this->aboutImpersonated($type, $user, $meta);

        $event = new ($this->keyring->securityEventModel())([
            'type' => $type,
            'severity' => $severity ?? Severity::of($type),
            // Taken from the URL for a refused enrollment, so cut to fit the
            // column, and the entry is still kept.
            'factor' => $factor === null ? null : mb_substr($factor, 0, 64),
            'device_id' => $device,
            'ip' => $impersonated ? null : $this->keyring->recordedIp(request()),
            'user_agent' => $impersonated ? null : UserAgent::from(request()),
            'request_id' => $this->requestId(),
            'meta' => $meta === [] ? null : $this->scrubbed($meta),
            'created_at' => now(),
        ]);

        if ($user instanceof Model) {
            $event->authenticatable()->associate($user);
        }

        return $event;
    }

    /**
     * Whether an entry on $user's account is written while someone is
     * impersonating them, or is the start or end of that: the request is
     * then the impersonator's, so its IP address and browser are theirs,
     * and are left off, as off the user's sessions list. The start and end
     * say so with their "role", the start being logged before the browser
     * changes hands. The impersonator's own entries keep them.
     *
     * @param  array<string, mixed>  $meta
     */
    protected function aboutImpersonated(string $type, Authenticatable $user, array $meta): bool
    {
        if (in_array($type, ['impersonation_started', 'impersonation_ended'], true)) {
            return ($meta['role'] ?? null) === 'impersonated';
        }

        return Features::enabled(Features::impersonation()) && app(Impersonation::class)->impersonates(request(), $user);
    }

    /**
     * The details with any text in them made valid UTF-8, as the table's JSON
     * and the log's need it to be. Some of it is chosen by whoever the entry
     * is about, an authenticator's name say, and must not keep it from
     * being written.
     *
     * @param  array<array-key, mixed>  $meta
     * @return array<array-key, mixed>
     */
    protected function scrubbed(array $meta): array
    {
        array_walk_recursive($meta, function (mixed &$value) {
            if (is_string($value)) {
                $value = mb_scrub($value, 'UTF-8');
            }
        });

        return $meta;
    }

    /**
     * Keep the entry in the table, or in the app's log when the table is
     * off. With $orWrite, one the table won't take goes there as well.
     */
    protected function keep(SecurityEvent $event, bool $orWrite = false): ?SecurityEvent
    {
        if (Features::enabled(Features::securityLog())) {
            try {
                $event->getConnection()->transaction(fn () => $event->save());

                return $event;
            } catch (Throwable $e) {
                throw_unless($orWrite, $e);

                report($e);
            }
        }

        $this->write($event);

        return null;
    }

    /**
     * The entry as a line in the app's log, at its own severity, with what
     * the table would hold as its context. The time is given with its
     * offset: Laravel stamps a log line without one, so a line alone
     * wouldn't say which timezone it was written in.
     */
    protected function write(SecurityEvent $event): void
    {
        Log::channel(config('keyring.security_log.channel'))->log($event->severity->value, 'Keyring: '.$event->type, array_filter([
            'at' => $event->created_at->toIso8601String(),
            'user' => $event->authenticatable_id === null ? null : $event->authenticatable_type.':'.$event->authenticatable_id,
            'factor' => $event->factor,
            'device_id' => $event->device_id,
            'ip' => $event->ip,
            'user_agent' => $event->user_agent,
            'request_id' => $event->request_id,
            'meta' => $event->meta,
        ], fn (mixed $value) => $value !== null));
    }

    /**
     * What ties one request's entries together. An app that already names
     * its requests in Laravel's Context (under "security_log.context_key")
     * has its own ID used, so entries match its log lines. Otherwise one is
     * made and kept in the hidden context, which lasts as long as the
     * request does and stays out of the app's own log lines.
     */
    protected function requestId(): ?string
    {
        $key = config('keyring.security_log.context_key');

        if ($key === null) {
            return null;
        }

        $id = Context::get($key) ?? Context::getHidden($key);

        return Str::limit(is_scalar($id) && (string) $id !== '' ? (string) $id : Context::rememberHidden(self::REQUEST_ID, fn () => (string) Str::uuid()), 64, '');
    }

    /**
     * The log only observes sign ins, so a failure here is reported and goes
     * no further. The savepoint stops a failed query from aborting the
     * caller's transaction on Postgres.
     *
     * @template TResult
     * @template TFallback
     *
     * @param  Closure(): TResult  $callback
     * @param  TFallback  $fallback
     * @return TResult|TFallback
     */
    protected function safely(Closure $callback, mixed $fallback): mixed
    {
        return rescue(fn () => $this->keyring->securityEventModel()::query()->getConnection()->transaction($callback), $fallback);
    }

    /**
     * @return Builder<SecurityEvent>
     */
    protected function query(Authenticatable&Model $user): Builder
    {
        return $this->keyring->securityEventModel()::query()->ownedBy($user);
    }
}
