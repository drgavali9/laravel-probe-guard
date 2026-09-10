<?php

namespace ProbeGuard\LaravelProbeGuard\Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Laravel\Telescope\Contracts\EntriesRepository;
use Laravel\Telescope\IncomingEntry;
use Laravel\Telescope\Storage\EntryModel;
use Laravel\Telescope\Telescope;
use Laravel\Telescope\TelescopeServiceProvider;
use Laravel\Telescope\Watchers\LogWatcher;
use Laravel\Telescope\Watchers\QueryWatcher;
use ProbeGuard\LaravelProbeGuard\Models\BlockedIp;
use ProbeGuard\LaravelProbeGuard\Tests\TestCase;

class TelescopeIntegrationTest extends TestCase
{
    use RefreshDatabase;

    protected function getPackageProviders($app): array
    {
        return [
            ...parent::getPackageProviders($app),
            TelescopeServiceProvider::class,
        ];
    }

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('telescope.enabled', true);
        $app['config']->set('telescope.driver', 'database');
        $app['config']->set('telescope.storage.database.connection', 'testing');
        $app['config']->set('telescope.watchers', [
            QueryWatcher::class => true,
            LogWatcher::class   => [
                'enabled' => true,
                'level'   => 'debug',
            ],
        ]);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->loadMigrationsFrom(__DIR__ . '/../../vendor/laravel/telescope/database/migrations');
        Telescope::flushEntries();
        Telescope::startRecording(false);
    }

    protected function tearDown(): void
    {
        Telescope::flushEntries();
        Telescope::stopRecording();

        parent::tearDown();
    }

    public function test_blocked_ip_request_is_rejected_and_not_stored_by_telescope(): void
    {
        BlockedIp::query()->create([
            'ip_address'    => '203.0.113.201',
            'reason'        => 'Suspicious path probe',
            'path'          => '/config.json',
            'method'        => 'GET',
            'hit_count'     => 1,
            'blocked_at'    => now()->subDay(),
            'expires_at'    => now()->addDays(6),
            'blocked_until' => now()->addDays(7),
        ]);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.201'])
            ->get('/')
            ->assertForbidden()
            ->assertHeader('X-Probe-Guard-Blocked', '1');

        Log::warning('blocked request package noise');
        Telescope::recordRequest(IncomingEntry::make([
            'uri'             => '/',
            'method'          => 'GET',
            'response_status' => 403,
        ]));

        Telescope::store(app(EntriesRepository::class));

        $this->assertDatabaseCount('telescope_entries', 0);
    }

    public function test_expired_blocked_ip_request_resumes_normal_telescope_recording(): void
    {
        BlockedIp::query()->create([
            'ip_address'    => '203.0.113.202',
            'reason'        => 'Suspicious path probe',
            'path'          => '/config.json',
            'method'        => 'GET',
            'hit_count'     => 1,
            'blocked_at'    => now()->subDays(8),
            'expires_at'    => now()->subMinute(),
            'blocked_until' => now()->subMinute(),
        ]);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.202'])
            ->get('/')
            ->assertOk();

        Telescope::recordRequest(IncomingEntry::make([
            'uri'             => '/',
            'method'          => 'GET',
            'response_status' => 200,
        ]));
        Telescope::store(app(EntriesRepository::class));

        $this->assertGreaterThan(0, EntryModel::query()->count());
        $this->assertTrue(EntryModel::query()->where('type', 'request')->exists());
    }

    public function test_normal_request_entries_are_still_stored_by_telescope(): void
    {
        $this->get('/')->assertOk();

        DB::select('select 1 as normal_probe_guard_test');
        Log::warning('normal request log entry');
        Telescope::recordRequest(IncomingEntry::make([
            'uri'             => '/',
            'method'          => 'GET',
            'response_status' => 200,
        ]));

        Telescope::store(app(EntriesRepository::class));

        $this->assertGreaterThan(0, EntryModel::query()->count());
        $this->assertTrue(EntryModel::query()->where('type', 'request')->exists());
        $this->assertTrue(EntryModel::query()->where('type', 'query')->exists());
        $this->assertTrue(EntryModel::query()->where('type', 'log')->exists());
    }

    public function test_config_can_disable_telescope_blocked_request_filter(): void
    {
        config()->set('probe-guard.telescope.ignore_blocked_requests', false);

        $this->app['request']->attributes->set('probe_guard.blocked_ip_request', true);

        Telescope::recordRequest(IncomingEntry::make([
            'uri'             => '/',
            'method'          => 'GET',
            'response_status' => 403,
        ]));
        Telescope::store(app(EntriesRepository::class));

        $this->assertDatabaseCount('telescope_entries', 1);
    }

    public function test_telescope_filter_does_not_query_blocked_ips_per_entry(): void
    {
        $this->app['request']->attributes->set('probe_guard.blocked_ip_request', true);

        Telescope::recordRequest(IncomingEntry::make(['uri' => '/', 'method' => 'GET']));
        Telescope::recordLog(IncomingEntry::make(['level' => 'warning', 'message' => 'blocked']));

        DB::enableQueryLog();
        Telescope::store(app(EntriesRepository::class));

        $blockedIpQueries = collect(DB::getQueryLog())
            ->filter(fn (array $query): bool => str_contains((string) $query['query'], 'probe_guard_blocked_ips'))
            ->count();

        $this->assertSame(0, $blockedIpQueries);
        $this->assertDatabaseCount('telescope_entries', 0);
    }
}
