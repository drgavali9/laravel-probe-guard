<?php

namespace ProbeGuard\LaravelProbeGuard\Support;

use Illuminate\Support\Str;

class PathNormalizer
{
    public function normalize(string $path): string
    {
        $decoded = $path;

        for ($i = 0; $i < 3; $i++) {
            $next = rawurldecode($decoded);

            if ($next === $decoded) {
                break;
            }

            $decoded = $next;
        }

        $decoded = str_replace('\\', '/', $decoded);
        $decoded = preg_replace('#/+#', '/', $decoded) ?: $decoded;

        return trim(Str::lower($decoded), '/');
    }
}
