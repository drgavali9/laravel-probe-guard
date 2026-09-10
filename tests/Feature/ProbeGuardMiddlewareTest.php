<?php

namespace ProbeGuard\LaravelProbeGuard\Tests\Feature;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;
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
        Carbon::setTestNow('2026-09-10 10:00:00');

        $this->withServerVariables([
            'REMOTE_ADDR'     => '203.0.113.20',
            'HTTP_USER_AGENT' => 'scanner',
        ])->get('/composer.json')
            ->assertNotFound()
            ->assertHeader('X-Probe-Guard-Blocked', '1');

        $this->assertDatabaseHas('probe_guard_blocked_ips', [
            'ip_address' => '203.0.113.20',
            'reason'     => 'Suspicious path probe',
            'path'       => '/composer.json',
            'method'     => 'GET',
            'hit_count'  => 1,
        ]);

        $blockedIp = BlockedIp::query()->where('ip_address', '203.0.113.20')->firstOrFail();

        $this->assertTrue($blockedIp->blocked_at->equalTo(now()));
        $this->assertTrue($blockedIp->expires_at->equalTo(now()->addDays(7)));
        $this->assertTrue($blockedIp->blocked_until->equalTo($blockedIp->expires_at));

        $this->assertDatabaseHas('probe_guard_suspicious_requests', [
            'ip_address' => '203.0.113.20',
            'reason'     => 'Suspicious path probe',
        ]);

        Carbon::setTestNow();
    }

    public function test_block_duration_days_config_controls_expiry(): void
    {
        Carbon::setTestNow('2026-09-10 10:00:00');
        config()->set('probe-guard.block_duration', null);
        config()->set('probe-guard.block_duration_days', 3);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.21'])
            ->get('/composer.json')
            ->assertNotFound();

        $blockedIp = BlockedIp::query()->where('ip_address', '203.0.113.21')->firstOrFail();

        $this->assertTrue($blockedIp->expires_at->equalTo(now()->addDays(3)));

        Carbon::setTestNow();
    }

    public function test_active_blocked_ip_is_rejected_before_normal_routes(): void
    {
        BlockedIp::query()->create([
            'ip_address'    => '203.0.113.30',
            'reason'        => 'Suspicious path probe',
            'path'          => '/config.json',
            'method'        => 'GET',
            'hit_count'     => 1,
            'blocked_at'    => now()->subDay(),
            'expires_at'    => now()->addDays(7),
            'blocked_until' => now()->addDays(7),
        ]);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.30'])
            ->get('/')
            ->assertForbidden()
            ->assertHeader('X-Probe-Guard-Blocked', '1')
            ->assertSee('Access blocked temporarily due to suspicious activity.');

        $this->assertDatabaseHas('probe_guard_blocked_ips', [
            'ip_address' => '203.0.113.30',
            'path'       => '/',
            'hit_count'  => 2,
        ]);
    }

    public function test_expired_block_is_marked_released_and_request_is_allowed(): void
    {
        BlockedIp::query()->create([
            'ip_address'    => '203.0.113.40',
            'reason'        => 'Suspicious path probe',
            'path'          => '/config.json',
            'method'        => 'GET',
            'hit_count'     => 1,
            'blocked_at'    => now()->subDays(8),
            'expires_at'    => now()->subMinute(),
            'blocked_until' => now()->subMinute(),
        ]);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.40'])
            ->get('/')
            ->assertOk()
            ->assertSee('ok');

        $this->assertDatabaseHas('probe_guard_blocked_ips', [
            'ip_address' => '203.0.113.40',
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
            'REMOTE_ADDR'           => '198.51.100.1',
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
            'reason'     => 'Suspicious path pattern probe',
        ]);
    }

    public function test_scanner_paths_from_observability_frameworks_and_dev_tools_are_blocked(): void
    {
        foreach ([
            '/_next',
            '/next.config.js',
            '/grafana/api/datasources',
            '/kibana/api/status',
            '/_cluster/health',
            '/elasticsearch/_cat/indices',
            '/app_dev.php/_profiler/open?file=.env',
            '/xampp/php-cgi.exe?%ADd%20auto_prepend_file%3Dphp://input',
        ] as $index => $path) {
            $ipAddress = '203.0.114.' . ($index + 1);

            $this->withServerVariables(['REMOTE_ADDR' => $ipAddress])
                ->get($path)
                ->assertNotFound();

            $this->assertDatabaseHas('probe_guard_blocked_ips', [
                'ip_address' => $ipAddress,
            ]);
        }
    }

    public function test_secret_backup_and_encoded_admin_probes_are_blocked(): void
    {
        foreach ([
            '/private.pem',
            '/api/secrets',
            '/credentials/%61dmin',
            '/backup.tar.gz',
            '/database.sqlite',
            '/wp-json/wp/v2/users',
            '/docker-compose.prod.yml',
            '/terraform/main.tf',
            '/?file=..%2F..%2F..%2F..%2Fvar%2Fwww%2Fhtml%2F.env',
            '/?phpinfo=1',
        ] as $index => $path) {
            $ipAddress = '203.0.115.' . ($index + 1);

            $this->withServerVariables(['REMOTE_ADDR' => $ipAddress])
                ->get($path)
                ->assertNotFound();

            $this->assertDatabaseHas('probe_guard_blocked_ips', [
                'ip_address' => $ipAddress,
            ]);
        }
    }

    public function test_genuine_application_api_webhook_upload_and_environment_routes_are_not_blocked(): void
    {
        foreach ([
            '/api/v1/profile',
            '/api/v1/home',
            '/api/webhooks/stripe',
            '/webhooks/stripe',
            '/uploads/avatar.png',
            '/api/upload',
            '/dev/team',
            '/staging/dashboard',
            '/downloads/report.zip',
            '/docs/openapi.yaml',
        ] as $index => $path) {
            $this->withServerVariables(['REMOTE_ADDR' => '203.0.116.' . ($index + 1)])
                ->get($path)
                ->assertOk()
                ->assertSee('missing');
        }

        $this->assertDatabaseCount('probe_guard_blocked_ips', 0);
    }

    public function test_cleanup_command_marks_expired_blocks_without_deleting_audit_history(): void
    {
        $blockedIp = BlockedIp::query()->create([
            'ip_address'    => '203.0.113.80',
            'blocked_at'    => now()->subDays(8),
            'expires_at'    => now()->subDay(),
            'blocked_until' => now()->subDay(),
        ]);

        BlockedIp::query()->create([
            'ip_address'    => '203.0.113.81',
            'blocked_at'    => now(),
            'expires_at'    => now()->addDay(),
            'blocked_until' => now()->addDay(),
        ]);

        BlockedIp::query()->create([
            'ip_address'    => '203.0.113.82',
            'blocked_at'    => now(),
            'expires_at'    => null,
            'blocked_until' => now()->addYears(100),
        ]);

        SuspiciousRequest::query()->create([
            'blocked_ip_id' => $blockedIp->id,
            'ip_address'    => '203.0.113.80',
            'detected_at'   => now()->subDay(),
        ]);

        $this->artisan('probe-guard:cleanup-expired')
            ->expectsOutput('Deleted 1 expired IP block(s).')
            ->assertSuccessful();

        $this->assertDatabaseMissing('probe_guard_blocked_ips', [
            'ip_address' => '203.0.113.80',
        ]);

        $this->assertDatabaseHas('probe_guard_blocked_ips', [
            'ip_address' => '203.0.113.81',
        ]);

        $this->assertDatabaseHas('probe_guard_blocked_ips', [
            'ip_address' => '203.0.113.82',
        ]);

        $this->assertDatabaseCount('probe_guard_suspicious_requests', 1);

        $this->artisan('blocked-ips:cleanup')
            ->expectsOutput('Deleted 0 expired IP block(s).')
            ->assertSuccessful();
    }

    public function test_cleanup_command_is_registered_with_scheduler(): void
    {
        $events = collect(app(Schedule::class)->events());

        $this->assertTrue($events->contains(
            fn ($event): bool => str_contains($event->command ?? '', 'probe-guard:cleanup-expired')
        ));
    }

    public function test_expired_ip_can_be_blocked_again_with_new_expiry(): void
    {
        Carbon::setTestNow('2026-09-10 10:00:00');

        BlockedIp::query()->create([
            'ip_address'    => '203.0.113.90',
            'blocked_at'    => now()->subDays(10),
            'expires_at'    => now()->subDay(),
            'blocked_until' => now()->subDay(),
            'hit_count'     => 1,
        ]);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.90'])
            ->get('/composer.json')
            ->assertNotFound();

        $blockedIp = BlockedIp::query()->where('ip_address', '203.0.113.90')->firstOrFail();

        $this->assertSame(2, $blockedIp->hit_count);
        $this->assertTrue($blockedIp->blocked_at->equalTo(now()));
        $this->assertTrue($blockedIp->expires_at->equalTo(now()->addDays(7)));

        Carbon::setTestNow();
    }
}
