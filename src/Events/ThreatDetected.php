<?php

namespace ProbeGuard\LaravelProbeGuard\Events;

use Illuminate\Http\Request;
use ProbeGuard\LaravelProbeGuard\Support\ThreatDetectionResult;

final readonly class ThreatDetected
{
    public function __construct(
        public string $ipAddress,
        public Request $request,
        public ThreatDetectionResult $result,
    ) {}
}
