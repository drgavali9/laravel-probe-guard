<?php

return [
    'enabled' => env('PROBE_GUARD_ENABLED', true),

    'table_names' => [
        'blocked_ips' => 'probe_guard_blocked_ips',
        'suspicious_requests' => 'probe_guard_suspicious_requests',
    ],

    'middleware_alias' => 'probe-guard',

    'auto_register_global_middleware' => env('PROBE_GUARD_GLOBAL_MIDDLEWARE', false),

    'block_duration' => env('PROBE_GUARD_BLOCK_DURATION', '7 days'),

    'extend_existing_blocks' => true,

    'blocked_response' => [
        'status' => 403,
        'body' => 'Access blocked temporarily due to suspicious activity.',
    ],

    'detected_response' => [
        'status' => 404,
        'body' => null,
    ],

    'ip_whitelist' => array_values(array_filter(array_map(
        'trim',
        explode(',', env('PROBE_GUARD_IP_WHITELIST', '127.0.0.1,::1'))
    ))),

    'trusted_proxy_headers' => [
        'cf-connecting-ip',
    ],

    'trusted_proxies' => [],

    'safe_paths' => [
        '',
        'favicon.ico',
        'robots.txt',
        'sitemap.xml',
    ],

    'safe_prefixes' => [],

    'exact_paths' => [
        '.env',
        '.env.backup',
        '.env.example',
        '.git/config',
        'adminer.php',
        'appsettings.json',
        'composer.json',
        'composer.lock',
        'config.php',
        'config.json',
        'database.sql',
        'docker-compose.yml',
        'package.json',
        'phpinfo.php',
        'server.js',
        'shell.php',
        'web.config',
        'wp-login.php',
        'xmlrpc.php',
    ],

    'path_prefixes' => [
        '.git',
        '.svn',
        'actuator',
        'administrator',
        'backup',
        'debug',
        'phpmyadmin',
        'plugins',
        'pma',
        'storage/logs',
        'vendor/phpunit',
        'wp-admin',
        'wp-content',
        'wp-includes',
        'wordpress',
    ],

    'extensions' => [
        'bak',
        'conf',
        'env',
        'gz',
        'ini',
        'old',
        'sql',
        'tar',
        'tgz',
        'yaml',
        'yml',
        'zip',
    ],

    'regex_patterns' => [
        '#(^|/)\.\./#',
        '#(^|/)etc/passwd$#',
        '#(^|/)(cmd|shell|wso|c99|r57)\.php$#',
    ],

    'query_keys' => [
        'dns' => 'Suspicious DNS probe',
    ],

    'query_value_contains' => [
        'name' => [
            'dnsmeasure' => 'Suspicious DNS probe',
        ],
    ],

    'logging' => [
        'enabled' => true,
        'channel' => null,
    ],

    'filament' => [
        'enabled' => true,
        'navigation_group' => 'Security',
    ],
];
