<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create(config('probe-guard.table_names.blocked_ips', 'probe_guard_blocked_ips'), function (Blueprint $table): void {
            $table->id();
            $table->string('ip_address', 45)->unique();
            $table->string('status')->default('active')->index();
            $table->string('reason')->nullable();
            $table->string('severity')->default('medium')->index();
            $table->string('path', 2048)->nullable();
            $table->string('method', 16)->nullable();
            $table->text('user_agent')->nullable();
            $table->unsignedInteger('hit_count')->default(1);
            $table->timestamp('blocked_until')->index();
            $table->timestamp('last_attempt_at')->nullable();
            $table->timestamp('unblocked_at')->nullable();
            $table->timestamps();
        });

        Schema::create(config('probe-guard.table_names.suspicious_requests', 'probe_guard_suspicious_requests'), function (Blueprint $table): void {
            $table->id();
            $table->foreignId('blocked_ip_id')->nullable()->constrained(config('probe-guard.table_names.blocked_ips', 'probe_guard_blocked_ips'))->nullOnDelete();
            $table->string('ip_address', 45)->index();
            $table->string('reason')->nullable();
            $table->string('severity')->default('medium')->index();
            $table->string('path', 2048)->nullable();
            $table->string('method', 16)->nullable();
            $table->text('user_agent')->nullable();
            $table->json('headers')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamp('detected_at')->index();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists(config('probe-guard.table_names.suspicious_requests', 'probe_guard_suspicious_requests'));
        Schema::dropIfExists(config('probe-guard.table_names.blocked_ips', 'probe_guard_blocked_ips'));
    }
};
