<?php

namespace ProbeGuard\LaravelProbeGuard\Console\Commands;

use Illuminate\Console\Command;
use ProbeGuard\LaravelProbeGuard\Contracts\BlockRepository;

class CleanupExpiredBlocksCommand extends Command
{
    protected $signature = 'probe-guard:cleanup-expired';

    protected $description = 'Delete expired Probe Guard IP blocks.';

    protected $aliases = [
        'blocked-ips:cleanup',
    ];

    public function handle(BlockRepository $blocks): int
    {
        $updated = $blocks->cleanupExpired();

        $this->info("Deleted {$updated} expired IP block(s).");

        return self::SUCCESS;
    }
}
