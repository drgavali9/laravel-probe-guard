<?php

namespace ProbeGuard\LaravelProbeGuard\Contracts;

use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use ProbeGuard\LaravelProbeGuard\Models\BlockedIp;
use ProbeGuard\LaravelProbeGuard\Support\ThreatDetectionResult;

interface BlockRepository
{
    public function find(string $ipAddress): ?BlockedIp;

    public function block(string $ipAddress, Request $request, ThreatDetectionResult $result): BlockedIp;

    public function recordBlockedHit(BlockedIp $blockedIp, Request $request): void;

    public function unblock(BlockedIp $blockedIp): bool;

    public function cleanupExpired(): int;

    /**
     * @return Collection<int, BlockedIp>
     */
    public function active(int $limit = 50): Collection;
}
