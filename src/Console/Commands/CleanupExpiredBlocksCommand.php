<?php

namespace ProbeGuard\LaravelProbeGuard\Console\Commands;

use Illuminate\Console\Command;
use ProbeGuard\LaravelProbeGuard\Contracts\BlockRepository;

class CleanupExpiredBlocksCommand extends Command
{
    protected $signature = 'probe-guard:cleanup-expired';

    protected $description = 'Mark expired Probe Guard IP blocks as unblocked.';

    public function handle(BlockRepository $blocks): int
    {
        $updated = $blocks->cleanupExpired();

        $this->info("Released {$updated} expired IP block(s).");

        return self::SUCCESS;
    }
}
