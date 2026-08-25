<?php

namespace ProbeGuard\LaravelProbeGuard\Models;

use Illuminate\Database\Eloquent\Model;
use ProbeGuard\LaravelProbeGuard\Enums\ThreatSeverity;

class SuspiciousRequest extends Model
{
    protected $guarded = [];

    public function getTable(): string
    {
        return config('probe-guard.table_names.suspicious_requests', 'probe_guard_suspicious_requests');
    }

    protected function casts(): array
    {
        return [
            'headers' => 'array',
            'metadata' => 'array',
            'detected_at' => 'datetime',
            'severity' => ThreatSeverity::class,
        ];
    }
}
