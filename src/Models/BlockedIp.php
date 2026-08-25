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
            'blocked_until'   => 'datetime',
            'last_attempt_at' => 'datetime',
            'unblocked_at'    => 'datetime',
            'status'          => BlockStatus::class,
            'severity'        => ThreatSeverity::class,
        ];
    }

    public function scopeActive(Builder $query): Builder
    {
        return $query->where('blocked_until', '>', now())->whereNull('unblocked_at');
    }

    public function isActive(): bool
    {
        return $this->unblocked_at === null && $this->blocked_until?->isFuture() === true;
    }
}
