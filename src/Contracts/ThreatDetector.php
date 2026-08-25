<?php

namespace ProbeGuard\LaravelProbeGuard\Contracts;

use Illuminate\Http\Request;
use ProbeGuard\LaravelProbeGuard\Support\ThreatDetectionResult;

interface ThreatDetector
{
    public function detect(Request $request): ?ThreatDetectionResult;
}
