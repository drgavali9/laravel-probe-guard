<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        $tableName = config('probe-guard.table_names.blocked_ips', 'probe_guard_blocked_ips');

        Schema::table($tableName, function (Blueprint $table) use ($tableName): void {
            if (! Schema::hasColumn($tableName, 'blocked_at')) {
                $table->timestamp('blocked_at')->nullable()->after('hit_count')->index();
            }

            if (! Schema::hasColumn($tableName, 'expires_at')) {
                $table->timestamp('expires_at')->nullable()->after('blocked_at')->index();
            }
        });

        DB::table($tableName)
            ->whereNull('blocked_at')
            ->update([
                'blocked_at' => DB::raw('created_at'),
            ]);

        if (Schema::hasColumn($tableName, 'blocked_until')) {
            DB::table($tableName)
                ->whereNull('expires_at')
                ->update([
                    'expires_at' => DB::raw('blocked_until'),
                ]);
        }
    }

    public function down(): void {}
};
