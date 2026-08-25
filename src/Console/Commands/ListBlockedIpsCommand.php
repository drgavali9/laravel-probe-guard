<?php

namespace ProbeGuard\LaravelProbeGuard\Console\Commands;

use Illuminate\Console\Command;
use ProbeGuard\LaravelProbeGuard\Contracts\BlockRepository;

class ListBlockedIpsCommand extends Command
{
    protected $signature = 'probe-guard:list {--limit=50}';

    protected $description = 'List active Probe Guard IP blocks.';

    public function handle(BlockRepository $blocks): int
    {
        $rows = $blocks->active((int) $this->option('limit'))
            ->map(fn ($blockedIp): array => [
                $blockedIp->ip_address,
                $blockedIp->reason,
                $blockedIp->hit_count,
                $blockedIp->blocked_until?->toDateTimeString(),
            ])
            ->all();

        $this->table(['IP', 'Reason', 'Hits', 'Blocked Until'], $rows);

        return self::SUCCESS;
    }
}
