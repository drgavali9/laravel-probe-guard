<?php

namespace ProbeGuard\LaravelProbeGuard\Console\Commands;

use Illuminate\Console\Command;
use ProbeGuard\LaravelProbeGuard\Contracts\BlockRepository;

class UnblockIpCommand extends Command
{
    protected $signature = 'probe-guard:unblock {ip : IP address to unblock}';

    protected $description = 'Manually unblock an IP address.';

    public function handle(BlockRepository $blocks): int
    {
        $blockedIp = $blocks->find((string) $this->argument('ip'));

        if ($blockedIp === null) {
            $this->warn('No block exists for that IP address.');

            return self::SUCCESS;
        }

        $blocks->unblock($blockedIp);
        $this->info("Unblocked {$blockedIp->ip_address}.");

        return self::SUCCESS;
    }
}
