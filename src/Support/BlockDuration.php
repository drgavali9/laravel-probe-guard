<?php

namespace ProbeGuard\LaravelProbeGuard\Support;

final class BlockDuration
{
    public static function days(): int
    {
        $legacyDuration = config('probe-guard.block_duration');

        if (is_string($legacyDuration) && preg_match('/^\s*(\d+)\s+days?\s*$/i', $legacyDuration, $matches) === 1) {
            return max(1, (int) $matches[1]);
        }

        return max(1, (int) config('probe-guard.block_duration_days', 7));
    }
}
