<?php

namespace ProbeGuard\LaravelProbeGuard\Filament\Resources\BlockedIps\Pages;

use Filament\Resources\Pages\ManageRecords;
use ProbeGuard\LaravelProbeGuard\Filament\Resources\BlockedIps\BlockedIpResource;

class ManageBlockedIps extends ManageRecords
{
    protected static string $resource = BlockedIpResource::class;
}
