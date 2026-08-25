<?php

namespace ProbeGuard\LaravelProbeGuard\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Http\Request;
use ProbeGuard\LaravelProbeGuard\Contracts\BlockRepository;
use ProbeGuard\LaravelProbeGuard\Support\ThreatDetectionResult;

class BlockIpCommand extends Command
{
    protected $signature = 'probe-guard:block {ip : IP address to block} {--reason=Manual block}';

    protected $description = 'Manually block an IP address.';

    public function handle(BlockRepository $blocks): int
    {
        $ipAddress = (string) $this->argument('ip');

        if (filter_var($ipAddress, FILTER_VALIDATE_IP) === false) {
            $this->error('The provided value is not a valid IP address.');

            return self::FAILURE;
        }

        $request = Request::create('/', 'GET', server: ['REMOTE_ADDR' => $ipAddress]);
        $blocks->block($ipAddress, $request, new ThreatDetectionResult((string) $this->option('reason')));

        $this->info("Blocked {$ipAddress}.");

        return self::SUCCESS;
    }
}
