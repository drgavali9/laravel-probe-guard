<?php

namespace ProbeGuard\LaravelProbeGuard\Tests;

use Orchestra\Testbench\TestCase as Orchestra;
use ProbeGuard\LaravelProbeGuard\Middleware\BlockMaliciousRequests;
use ProbeGuard\LaravelProbeGuard\RequestGuardServiceProvider;

abstract class TestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [
            RequestGuardServiceProvider::class,
        ];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ]);

        $app['config']->set('probe-guard.ip_whitelist', []);
        $app['config']->set('probe-guard.trusted_proxy_headers', ['cf-connecting-ip']);
        $app['config']->set('probe-guard.trusted_proxies', []);
    }

    protected function defineRoutes($router): void
    {
        $router->middleware(BlockMaliciousRequests::class)->get('/', fn (): string => 'ok');
        $router->middleware(BlockMaliciousRequests::class)->get('/proparty', fn (): string => 'typo route');
        $router->middleware(BlockMaliciousRequests::class)->get('/{any}', fn (): string => 'missing')->where('any', '.*');
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');
    }
}
