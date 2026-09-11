<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use ProbeGuard\LaravelProbeGuard\Support\BlockDuration;

return new class extends Migration
{
    public function up(): void
    {
        $tableName = config('probe-guard.table_names.blocked_ips', 'probe_guard_blocked_ips');

        if (! Schema::hasTable($tableName) || ! Schema::hasColumn($tableName, 'expires_at')) {
            return;
        }

        DB::table($tableName)
            ->whereNull('unblocked_at')
            ->whereNotNull('blocked_at')
            ->where(function ($query): void {
                $query->whereNull('expires_at')
                    ->orWhereColumn('expires_at', '<=', 'blocked_at');
            })
            ->orderBy('id')
            ->eachById(function (object $blockedIp) use ($tableName): void {
                $expiresAt = Carbon::parse($blockedIp->blocked_at)->addDays(BlockDuration::days());

                DB::table($tableName)
                    ->where('id', $blockedIp->id)
                    ->update([
                        'expires_at'    => $expiresAt,
                        'blocked_until' => $expiresAt,
                    ]);
            });
    }

    public function down(): void {}
};
