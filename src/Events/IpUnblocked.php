<?php

namespace ProbeGuard\LaravelProbeGuard\Events;

use ProbeGuard\LaravelProbeGuard\Models\BlockedIp;

final readonly class IpUnblocked
{
    public function __construct(public BlockedIp $blockedIp) {}
}
