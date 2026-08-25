<?php

namespace ProbeGuard\LaravelProbeGuard\Support;

use ProbeGuard\LaravelProbeGuard\Enums\ThreatSeverity;

final readonly class ThreatDetectionResult
{
    public function __construct(
        public string $reason,
        public ThreatSeverity $severity = ThreatSeverity::Medium,
        public array $metadata = [],
    ) {}
}
