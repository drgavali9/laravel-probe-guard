<?php

namespace ProbeGuard\LaravelProbeGuard\Enums;

enum ThreatSeverity: string
{
    case Low = 'low';
    case Medium = 'medium';
    case High = 'high';
    case Critical = 'critical';
}
