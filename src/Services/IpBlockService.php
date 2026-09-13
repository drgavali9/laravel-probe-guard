<?php

namespace ProbeGuard\LaravelProbeGuard\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;
use ProbeGuard\LaravelProbeGuard\Contracts\BlockRepository;
use ProbeGuard\LaravelProbeGuard\Enums\BlockStatus;
use ProbeGuard\LaravelProbeGuard\Events\IpBlocked;
use ProbeGuard\LaravelProbeGuard\Events\IpUnblocked;
use ProbeGuard\LaravelProbeGuard\Models\BlockedIp;
use ProbeGuard\LaravelProbeGuard\Models\SuspiciousRequest;
use ProbeGuard\LaravelProbeGuard\Support\BlockDuration;
use ProbeGuard\LaravelProbeGuard\Support\ThreatDetectionResult;

class IpBlockService implements BlockRepository
{
    public function find(string $ipAddress): ?BlockedIp
    {
        if ($cachedAttributes = $this->cached($ipAddress)) {
            $blockedIp = new BlockedIp;
            $blockedIp->setRawAttributes($cachedAttributes, true);
            $blockedIp->exists = true;

            return $blockedIp;
        }

        $blockedIp = BlockedIp::query()->where('ip_address', $ipAddress)->first();

        if ($blockedIp?->isActive() === true) {
            $this->cache($blockedIp);
        }

        return $blockedIp;
    }

    public function block(string $ipAddress, Request $request, ThreatDetectionResult $result): BlockedIp
    {
        $blockedIp = $this->find($ipAddress);
        $now = now();
        $baseUntil = $blockedIp?->isActive() === true && config('probe-guard.extend_existing_blocks', true)
            ? ($blockedIp->expires_at ?? $blockedIp->blocked_until)
            : $now;
        $blockedAt = $blockedIp?->isActive() === true
            ? ($blockedIp->blocked_at ?? $now)
            : now();

        $expiresAt = $baseUntil->copy()->addDays(BlockDuration::days());

        $blockedIp = BlockedIp::query()->updateOrCreate(
            ['ip_address' => $ipAddress],
            [
                'status'          => BlockStatus::Active,
                'reason'          => $result->reason,
                'severity'        => $result->severity,
                'path'            => '/' . ltrim($request->path(), '/'),
                'method'          => $request->method(),
                'user_agent'      => $request->userAgent(),
                'hit_count'       => ($blockedIp?->hit_count ?? 0) + 1,
                'blocked_at'      => $blockedAt,
                'expires_at'      => $expiresAt,
                'blocked_until'   => $expiresAt,
                'last_attempt_at' => $now,
                'unblocked_at'    => null,
            ],
        );

        $this->recordSuspiciousRequest($blockedIp, $ipAddress, $request, $result);

        event(new IpBlocked($blockedIp));

        $this->cache($blockedIp);

        return $blockedIp;
    }

    public function recordBlockedHit(BlockedIp $blockedIp, Request $request): void
    {
        $blockedIp->forceFill([
            'hit_count'       => $blockedIp->hit_count + 1,
            'path'            => '/' . ltrim($request->path(), '/'),
            'method'          => $request->method(),
            'user_agent'      => $request->userAgent(),
            'last_attempt_at' => now(),
        ])->save();

        $this->cache($blockedIp);
    }

    public function extend(BlockedIp $blockedIp): bool
    {
        $expiresAt = ($blockedIp->expires_at?->isFuture() === true ? $blockedIp->expires_at : now())
            ->copy()
            ->addDays(BlockDuration::days());

        $saved = $blockedIp->forceFill([
            'status'        => BlockStatus::Active,
            'expires_at'    => $expiresAt,
            'blocked_until' => $expiresAt,
            'unblocked_at'  => null,
        ])->save();

        if ($saved) {
            $this->cache($blockedIp);
        }

        return $saved;
    }

    public function unblock(BlockedIp $blockedIp): bool
    {
        $saved = $blockedIp->forceFill([
            'status'       => BlockStatus::Expired,
            'unblocked_at' => now(),
        ])->save();

        event(new IpUnblocked($blockedIp));

        $this->forgetCached($blockedIp->ip_address);

        return $saved;
    }

    public function cleanupExpired(): int
    {
        return BlockedIp::query()
            ->whereNotNull('expires_at')
            ->where('expires_at', '<=', now())
            ->delete();
    }

    public function active(int $limit = 50): Collection
    {
        return BlockedIp::query()->active()->latest('last_attempt_at')->limit($limit)->get();
    }

    private function recordSuspiciousRequest(BlockedIp $blockedIp, string $ipAddress, Request $request, ThreatDetectionResult $result): void
    {
        SuspiciousRequest::query()->create([
            'blocked_ip_id' => $blockedIp->id,
            'ip_address'    => $ipAddress,
            'reason'        => $result->reason,
            'severity'      => $result->severity,
            'path'          => '/' . ltrim($request->path(), '/'),
            'method'        => $request->method(),
            'user_agent'    => $request->userAgent(),
            'headers'       => [
                'referer' => $request->headers->get('referer'),
                'cf-ray'  => $request->headers->get('cf-ray'),
            ],
            'metadata'    => $result->metadata,
            'detected_at' => now(),
        ]);
    }

    /**
     * @return array<string, mixed>|null
     */
    private function cached(string $ipAddress): ?array
    {
        if (! config('probe-guard.cache.enabled', true)) {
            return null;
        }

        $blockedIps = Cache::get($this->cacheKey(), []);
        $entry = is_array($blockedIps) ? ($blockedIps[$ipAddress] ?? null) : null;

        if (! is_array($entry) || ! isset($entry['attributes'], $entry['cached_until'])) {
            return null;
        }

        if ((int) $entry['cached_until'] <= now()->timestamp) {
            $this->forgetCached($ipAddress);

            return null;
        }

        return is_array($entry['attributes']) ? $entry['attributes'] : null;
    }

    private function cache(BlockedIp $blockedIp): void
    {
        if (! config('probe-guard.cache.enabled', true) || ! $blockedIp->isActive()) {
            return;
        }

        $this->mutateCache(function (array $blockedIps) use ($blockedIp): array {
            $blockedIps[$blockedIp->ip_address] = [
                'attributes'   => $blockedIp->getAttributes(),
                'cached_until' => now()->addSeconds($this->cacheTtl())->timestamp,
            ];

            return $blockedIps;
        });
    }

    private function forgetCached(string $ipAddress): void
    {
        if (! config('probe-guard.cache.enabled', true)) {
            return;
        }

        $this->mutateCache(function (array $blockedIps) use ($ipAddress): array {
            unset($blockedIps[$ipAddress]);

            return $blockedIps;
        });
    }

    /**
     * @param callable(array<string, array<string, mixed>>): array<string, array<string, mixed>> $callback
     */
    private function mutateCache(callable $callback): void
    {
        $lock = Cache::lock($this->cacheKey() . ':lock', 5);

        if (! $lock->get()) {
            return;
        }

        try {
            $blockedIps = Cache::get($this->cacheKey(), []);
            $blockedIps = is_array($blockedIps) ? $blockedIps : [];
            $blockedIps = $callback($blockedIps);

            if ($blockedIps === []) {
                Cache::forget($this->cacheKey());
            } else {
                Cache::put($this->cacheKey(), $blockedIps, $this->cacheTtl());
            }
        } finally {
            $lock->release();
        }
    }

    private function cacheKey(): string
    {
        return (string) config('probe-guard.cache.key', 'probe-guard:blocked-ips');
    }

    private function cacheTtl(): int
    {
        return max(1, (int) config('probe-guard.cache.ttl_seconds', 86400));
    }
}
