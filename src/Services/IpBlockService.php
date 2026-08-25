<?php

namespace ProbeGuard\LaravelProbeGuard\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use ProbeGuard\LaravelProbeGuard\Contracts\BlockRepository;
use ProbeGuard\LaravelProbeGuard\Enums\BlockStatus;
use ProbeGuard\LaravelProbeGuard\Events\IpBlocked;
use ProbeGuard\LaravelProbeGuard\Events\IpUnblocked;
use ProbeGuard\LaravelProbeGuard\Models\BlockedIp;
use ProbeGuard\LaravelProbeGuard\Models\SuspiciousRequest;
use ProbeGuard\LaravelProbeGuard\Support\ThreatDetectionResult;

class IpBlockService implements BlockRepository
{
    public function find(string $ipAddress): ?BlockedIp
    {
        return BlockedIp::query()->where('ip_address', $ipAddress)->first();
    }

    public function block(string $ipAddress, Request $request, ThreatDetectionResult $result): BlockedIp
    {
        $blockedIp = $this->find($ipAddress);
        $baseUntil = $blockedIp?->isActive() === true && config('probe-guard.extend_existing_blocks', true)
            ? $blockedIp->blocked_until
            : now();

        $blockedUntil = $baseUntil->copy()->add($this->blockInterval());

        $blockedIp = BlockedIp::query()->updateOrCreate(
            ['ip_address' => $ipAddress],
            [
                'status' => BlockStatus::Active,
                'reason' => $result->reason,
                'severity' => $result->severity,
                'path' => '/'.ltrim($request->path(), '/'),
                'method' => $request->method(),
                'user_agent' => $request->userAgent(),
                'hit_count' => ($blockedIp?->hit_count ?? 0) + 1,
                'blocked_until' => $blockedUntil,
                'last_attempt_at' => now(),
                'unblocked_at' => null,
            ],
        );

        $this->recordSuspiciousRequest($blockedIp, $ipAddress, $request, $result);

        event(new IpBlocked($blockedIp));

        return $blockedIp;
    }

    public function recordBlockedHit(BlockedIp $blockedIp, Request $request): void
    {
        $blockedIp->forceFill([
            'hit_count' => $blockedIp->hit_count + 1,
            'path' => '/'.ltrim($request->path(), '/'),
            'method' => $request->method(),
            'user_agent' => $request->userAgent(),
            'last_attempt_at' => now(),
        ])->save();
    }

    public function unblock(BlockedIp $blockedIp): bool
    {
        $saved = $blockedIp->forceFill([
            'status' => BlockStatus::Expired,
            'unblocked_at' => now(),
        ])->save();

        event(new IpUnblocked($blockedIp));

        return $saved;
    }

    public function cleanupExpired(): int
    {
        return BlockedIp::query()
            ->where('blocked_until', '<=', now())
            ->whereNull('unblocked_at')
            ->update([
                'status' => BlockStatus::Expired,
                'unblocked_at' => now(),
                'updated_at' => now(),
            ]);
    }

    public function active(int $limit = 50): Collection
    {
        return BlockedIp::query()->active()->latest('last_attempt_at')->limit($limit)->get();
    }

    private function recordSuspiciousRequest(BlockedIp $blockedIp, string $ipAddress, Request $request, ThreatDetectionResult $result): void
    {
        SuspiciousRequest::query()->create([
            'blocked_ip_id' => $blockedIp->id,
            'ip_address' => $ipAddress,
            'reason' => $result->reason,
            'severity' => $result->severity,
            'path' => '/'.ltrim($request->path(), '/'),
            'method' => $request->method(),
            'user_agent' => $request->userAgent(),
            'headers' => [
                'referer' => $request->headers->get('referer'),
                'cf-ray' => $request->headers->get('cf-ray'),
            ],
            'metadata' => $result->metadata,
            'detected_at' => now(),
        ]);
    }

    private function blockInterval(): \DateInterval
    {
        return \DateInterval::createFromDateString((string) config('probe-guard.block_duration', '7 days'));
    }
}
