<?php

namespace ProbeGuard\LaravelProbeGuard\Enums;

enum BlockStatus: string
{
    case Active = 'active';
    case Expired = 'expired';
    case Manual = 'manual';
}
