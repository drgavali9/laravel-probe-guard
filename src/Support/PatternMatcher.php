<?php

namespace ProbeGuard\LaravelProbeGuard\Support;

use Illuminate\Support\Str;

class PatternMatcher
{
    public function __construct(private readonly PathNormalizer $normalizer) {}

    public function matchesExact(string $path, array $patterns): bool
    {
        return in_array($path, array_map(fn (string $pattern): string => $this->normalizer->normalize($pattern), $patterns), true);
    }

    public function matchesPrefix(string $path, array $prefixes): bool
    {
        foreach ($prefixes as $prefix) {
            $normalizedPrefix = $this->normalizer->normalize((string) $prefix);

            if ($normalizedPrefix !== '' && ($path === $normalizedPrefix || Str::startsWith($path, $normalizedPrefix . '/'))) {
                return true;
            }
        }

        return false;
    }

    public function matchesRegex(string $path, array $patterns): ?string
    {
        foreach ($patterns as $pattern) {
            if (@preg_match((string) $pattern, $path) === 1) {
                return (string) $pattern;
            }
        }

        return null;
    }
}
