<?php

namespace ProbeGuard\LaravelProbeGuard;

use Illuminate\Contracts\Http\Kernel;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;
use Laravel\Telescope\EntryType;
use Laravel\Telescope\Telescope;
use ProbeGuard\LaravelProbeGuard\Console\Commands\BlockIpCommand;
use ProbeGuard\LaravelProbeGuard\Console\Commands\CleanupExpiredBlocksCommand;
use ProbeGuard\LaravelProbeGuard\Console\Commands\ListBlockedIpsCommand;
use ProbeGuard\LaravelProbeGuard\Console\Commands\UnblockIpCommand;
use ProbeGuard\LaravelProbeGuard\Contracts\BlockRepository;
use ProbeGuard\LaravelProbeGuard\Contracts\IpResolver;
use ProbeGuard\LaravelProbeGuard\Contracts\ThreatDetector;
use ProbeGuard\LaravelProbeGuard\Middleware\BlockMaliciousRequests;
use ProbeGuard\LaravelProbeGuard\Services\ClientIpResolver;
use ProbeGuard\LaravelProbeGuard\Services\IpBlockService;
use ProbeGuard\LaravelProbeGuard\Services\ThreatDetectionService;

class RequestGuardServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/probe-guard.php', 'probe-guard');

        $this->app->bind(ThreatDetector::class, ThreatDetectionService::class);
        $this->app->bind(IpResolver::class, ClientIpResolver::class);
        $this->app->bind(BlockRepository::class, IpBlockService::class);
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__.'/../config/probe-guard.php' => config_path('probe-guard.php'),
        ], 'probe-guard-config');

        $this->publishesMigrations([
            __DIR__.'/../database/migrations' => database_path('migrations'),
        ], 'probe-guard-migrations');

        $this->app->make(Router::class)->aliasMiddleware(
            (string) config('probe-guard.middleware_alias', 'probe-guard'),
            BlockMaliciousRequests::class,
        );

        if (config('probe-guard.auto_register_global_middleware', false)) {
            $this->app->make(Kernel::class)->prependMiddleware(BlockMaliciousRequests::class);
        }

        $this->registerTelescopeFilter();

        if ($this->app->runningInConsole()) {
            $this->commands([
                CleanupExpiredBlocksCommand::class,
                BlockIpCommand::class,
                UnblockIpCommand::class,
                ListBlockedIpsCommand::class,
            ]);
        }
    }

    private function registerTelescopeFilter(): void
    {
        if (! config('probe-guard.telescope.ignore_probe_guard_requests', true)) {
            return;
        }

        if (! class_exists(Telescope::class) || ! class_exists(EntryType::class)) {
            return;
        }

        Telescope::filter(function ($entry): bool {
            if ($entry->type !== EntryType::REQUEST) {
                return true;
            }

            return ($entry->content['response_headers']['x-probe-guard-blocked'] ?? null) !== '1';
        });
    }
}
