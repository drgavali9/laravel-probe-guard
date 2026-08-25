<?php

namespace ProbeGuard\LaravelProbeGuard\Filament;

use Filament\Contracts\Plugin;
use Filament\Panel;
use ProbeGuard\LaravelProbeGuard\Filament\Resources\BlockedIps\BlockedIpResource;

class ProbeGuardPlugin implements Plugin
{
    public static function make(): static
    {
        return app(static::class);
    }

    public function getId(): string
    {
        return 'probe-guard';
    }

    public function register(Panel $panel): void
    {
        if (config('probe-guard.filament.enabled', true)) {
            $panel->resources([
                BlockedIpResource::class,
            ]);
        }
    }

    public function boot(Panel $panel): void {}
}
