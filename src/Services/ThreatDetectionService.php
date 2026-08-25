<?php

namespace ProbeGuard\LaravelProbeGuard\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Str;
use ProbeGuard\LaravelProbeGuard\Contracts\ThreatDetector;
use ProbeGuard\LaravelProbeGuard\Enums\ThreatSeverity;
use ProbeGuard\LaravelProbeGuard\Support\PathNormalizer;
use ProbeGuard\LaravelProbeGuard\Support\PatternMatcher;
use ProbeGuard\LaravelProbeGuard\Support\ThreatDetectionResult;

class ThreatDetectionService implements ThreatDetector
{
    public function __construct(
        private readonly PathNormalizer $normalizer,
        private readonly PatternMatcher $matcher,
    ) {}

    public function detect(Request $request): ?ThreatDetectionResult
    {
        $path = $this->normalizer->normalize($request->path());

        if ($queryThreat = $this->detectQueryThreat($request)) {
            return $queryThreat;
        }

        if ($this->isSafePath($path)) {
            return null;
        }

        if ($this->matcher->matchesExact($path, config('probe-guard.exact_paths', []))) {
            return new ThreatDetectionResult('Suspicious path probe', ThreatSeverity::High, ['match' => 'exact']);
        }

        if ($this->matcher->matchesPrefix($path, config('probe-guard.path_prefixes', []))) {
            return new ThreatDetectionResult('Suspicious path prefix probe', ThreatSeverity::High, ['match' => 'prefix']);
        }

        $extension = Str::lower((string) pathinfo($path, PATHINFO_EXTENSION));

        if ($extension !== '' && in_array($extension, config('probe-guard.extensions', []), true)) {
            return new ThreatDetectionResult('Suspicious file extension probe', ThreatSeverity::Medium, ['extension' => $extension]);
        }

        if ($pattern = $this->matcher->matchesRegex($path, config('probe-guard.regex_patterns', []))) {
            return new ThreatDetectionResult('Suspicious path pattern probe', ThreatSeverity::Critical, ['pattern' => $pattern]);
        }

        return null;
    }

    private function detectQueryThreat(Request $request): ?ThreatDetectionResult
    {
        foreach (config('probe-guard.query_keys', []) as $key => $reason) {
            if ($request->query->has((string) $key)) {
                return new ThreatDetectionResult((string) $reason, ThreatSeverity::Medium, ['query_key' => $key]);
            }
        }

        foreach (config('probe-guard.query_value_contains', []) as $key => $needles) {
            $value = Str::lower((string) $request->query((string) $key));

            foreach ($needles as $needle => $reason) {
                if ($value !== '' && Str::contains($value, Str::lower((string) $needle))) {
                    return new ThreatDetectionResult((string) $reason, ThreatSeverity::Medium, [
                        'query_key' => $key,
                        'needle' => $needle,
                    ]);
                }
            }
        }

        return null;
    }

    private function isSafePath(string $path): bool
    {
        if ($this->matcher->matchesExact($path, config('probe-guard.safe_paths', []))) {
            return true;
        }

        return $this->matcher->matchesPrefix($path, config('probe-guard.safe_prefixes', []));
    }
}
