# Laravel Probe Guard

Laravel Probe Guard blocks suspicious URL probes such as `.env`, `.git`, WordPress, phpMyAdmin, backup, shell, traversal, and config disclosure paths. It is framework-generic and does not depend on KirayaBook.

## Install

```bash
composer require drgavali9/laravel-probe-guard
php artisan vendor:publish --tag=probe-guard-config
php artisan vendor:publish --tag=probe-guard-migrations
php artisan migrate
```

Register the middleware globally in `app/Http/Kernel.php`, or set `PROBE_GUARD_GLOBAL_MIDDLEWARE=true`.

```php
protected $middleware = [
    \ProbeGuard\LaravelProbeGuard\Middleware\BlockMaliciousRequests::class,
];
```

You may also attach the published alias to specific route groups:

```php
Route::middleware('probe-guard')->group(function () {
    // web or API routes
});
```

## Filament

Filament is optional. In a Filament panel provider:

```php
use ProbeGuard\LaravelProbeGuard\Filament\ProbeGuardPlugin;

public function panel(Panel $panel): Panel
{
    return $panel->plugin(ProbeGuardPlugin::make());
}
```

## Commands

```bash
php artisan probe-guard:list
php artisan probe-guard:block 203.0.113.10 --reason="Manual block"
php artisan probe-guard:unblock 203.0.113.10
php artisan probe-guard:cleanup-expired
```

Schedule cleanup in the host app if you want expired rows marked automatically:

```php
$schedule->command('probe-guard:cleanup-expired')->daily()->withoutOverlapping();
```

## Extraction Audit From KirayaBook

What worked well:

- Global middleware rejected already-blocked IPs before normal routes.
- Suspicious route detection was narrow and avoided blocking every 404.
- Config-driven exact paths, prefixes, extensions, safe paths, and whitelist existed.
- Filament management allowed operators to view, unblock, delete, and extend blocks.
- Tests covered normal requests, suspicious probes, whitelisting, active blocks, and cleanup.

What was KirayaBook-specific:

- `config/security.php` safe paths included KirayaBook admin, landlord, tenant, and short-link routes.
- Filament access checks depended on `ROLE_ADMIN`, Spatie role semantics, and the admin panel namespace.
- The cleanup command name and scheduler lived in the application.
- The table/model names were generic app names (`blocked_ips`, `App\Models\BlockedIp`) rather than package-owned names.

What became configurable:

- Block duration, whitelist, safe paths/prefixes, suspicious exact paths, prefixes, extensions, regexes, query probes, response status/body, table names, middleware alias, logging channel, trusted proxy headers, trusted proxy IPs, and optional global middleware registration.

Security weaknesses addressed:

- Cloudflare/proxy headers are only trusted when the immediate proxy is explicitly trusted.
- Suspicious request history is stored separately from the current block row.
- Expired blocks are marked released instead of deleted, preserving audit history.
- Paths are repeatedly URL-decoded and backslashes are normalized before matching.
- Traversal and common web-shell patterns are detected via configurable regex rules.

Reusable components:

- Threat detector, IP resolver, block repository, middleware, Eloquent models, migrations, events, console commands, and optional Filament plugin/resource.

Components not moved:

- KirayaBook-specific route allow-list values, scheduler timezone policy, admin role checks, and custom Filament back action.
