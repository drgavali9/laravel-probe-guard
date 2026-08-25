<?php

namespace ProbeGuard\LaravelProbeGuard\Events;

use ProbeGuard\LaravelProbeGuard\Models\BlockedIp;

final readonly class IpBlocked
{
    public function __construct(public BlockedIp $blockedIp) {}
}
