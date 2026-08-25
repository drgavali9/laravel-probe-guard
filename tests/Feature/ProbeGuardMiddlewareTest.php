<?php

namespace ProbeGuard\LaravelProbeGuard\Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use ProbeGuard\LaravelProbeGuard\Models\BlockedIp;
use ProbeGuard\LaravelProbeGuard\Models\SuspiciousRequest;
use ProbeGuard\LaravelProbeGuard\Tests\TestCase;

class ProbeGuardMiddlewareTest extends TestCase
{
    use RefreshDatabase;

    public function test_normal_request_is_allowed(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])
            ->get('/')
            ->assertOk()
            ->assertSee('ok');

        $this->assertDatabaseCount('probe_guard_blocked_ips', 0);
    }

    public function test_typo_route_is_not_blocked_indiscriminately(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.11'])
            ->get('/proparty')
            ->assertOk()
            ->assertSee('typo route');

        $this->assertDatabaseCount('probe_guard_blocked_ips', 0);
    }

    public function test_suspicious_path_is_recorded_and_returns_not_found(): void
    {
        $this->withServerVariables([
            'REMOTE_ADDR' => '203.0.113.20',
            'HTTP_USER_AGENT' => 'scanner',
        ])->get('/composer.json')->assertNotFound();

        $this->assertDatabaseHas('probe_guard_blocked_ips', [
            'ip_address' => '203.0.113.20',
            'reason' => 'Suspicious path probe',
            'path' => '/composer.json',
            'method' => 'GET',
            'hit_count' => 1,
        ]);

        $this->assertDatabaseHas('probe_guard_suspicious_requests', [
            'ip_address' => '203.0.113.20',
            'reason' => 'Suspicious path probe',
        ]);
    }

    public function test_active_blocked_ip_is_rejected_before_normal_routes(): void
    {
        BlockedIp::query()->create([
            'ip_address' => '203.0.113.30',
            'reason' => 'Suspicious path probe',
            'path' => '/config.json',
            'method' => 'GET',
            'hit_count' => 1,
            'blocked_until' => now()->addDays(7),
        ]);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.30'])
            ->get('/')
            ->assertForbidden()
            ->assertSee('Access blocked temporarily due to suspicious activity.');

        $this->assertDatabaseHas('probe_guard_blocked_ips', [
            'ip_address' => '203.0.113.30',
            'path' => '/',
            'hit_count' => 2,
        ]);
    }

    public function test_whitelisted_ip_is_never_blocked(): void
    {
        config()->set('probe-guard.ip_whitelist', ['203.0.113.50']);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.50'])
            ->get('/composer.json')
            ->assertOk()
            ->assertSee('missing');

        $this->assertDatabaseCount('probe_guard_blocked_ips', 0);
    }

    public function test_cloudflare_header_is_only_trusted_from_configured_proxy(): void
    {
        config()->set('probe-guard.trusted_proxies', ['198.51.100.1']);

        $this->withServerVariables([
            'REMOTE_ADDR' => '198.51.100.1',
            'HTTP_CF_CONNECTING_IP' => '203.0.113.60',
        ])->get('/.env')->assertNotFound();

        $this->assertDatabaseHas('probe_guard_blocked_ips', [
            'ip_address' => '203.0.113.60',
        ]);
    }

    public function test_encoded_traversal_probe_is_blocked(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.70'])
            ->get('/%252e%252e/%252e%252e/etc/passwd')
            ->assertNotFound();

        $this->assertDatabaseHas('probe_guard_blocked_ips', [
            'ip_address' => '203.0.113.70',
            'reason' => 'Suspicious path pattern probe',
        ]);
    }

    public function test_cleanup_command_marks_expired_blocks_without_deleting_audit_history(): void
    {
        $blockedIp = BlockedIp::query()->create([
            'ip_address' => '203.0.113.80',
            'blocked_until' => now()->subDay(),
        ]);

        SuspiciousRequest::query()->create([
            'blocked_ip_id' => $blockedIp->id,
            'ip_address' => '203.0.113.80',
            'detected_at' => now()->subDay(),
        ]);

        $this->artisan('probe-guard:cleanup-expired')
            ->expectsOutput('Released 1 expired IP block(s).')
            ->assertSuccessful();

        $this->assertDatabaseHas('probe_guard_blocked_ips', [
            'ip_address' => '203.0.113.80',
            'status' => 'expired',
        ]);
        $this->assertDatabaseCount('probe_guard_suspicious_requests', 1);
    }
}
