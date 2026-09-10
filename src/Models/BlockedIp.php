<?php

namespace ProbeGuard\LaravelProbeGuard\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use ProbeGuard\LaravelProbeGuard\Enums\BlockStatus;
use ProbeGuard\LaravelProbeGuard\Enums\ThreatSeverity;

class BlockedIp extends Model
{
    protected $guarded = [];

    public function getTable(): string
    {
        return config('probe-guard.table_names.blocked_ips', 'probe_guard_blocked_ips');
    }

    protected function casts(): array
    {
        return [
            'blocked_at' => 'datetime',
            'expires_at' => 'datetime',
            'blocked_until' => 'datetime',
            'last_attempt_at' => 'datetime',
            'unblocked_at' => 'datetime',
            'status' => BlockStatus::class,
            'severity' => ThreatSeverity::class,
        ];
    }

    public function scopeActive(Builder $query): Builder
    {
        return $query->where(function (Builder $query): void {
            $query->where('expires_at', '>', now())
                ->orWhereNull('expires_at');
        })->whereNull('unblocked_at');
    }

    public function isActive(): bool
    {
        if ($this->unblocked_at !== null) {
            return false;
        }

        $expiresAt = $this->expires_at ?? $this->blocked_until;

        return $expiresAt === null || $expiresAt->isFuture();
    }
}
