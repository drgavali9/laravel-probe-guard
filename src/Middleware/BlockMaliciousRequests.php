<?php

namespace ProbeGuard\LaravelProbeGuard\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use ProbeGuard\LaravelProbeGuard\Contracts\BlockRepository;
use ProbeGuard\LaravelProbeGuard\Contracts\IpResolver;
use ProbeGuard\LaravelProbeGuard\Contracts\ThreatDetector;
use ProbeGuard\LaravelProbeGuard\Events\ThreatDetected;
use Symfony\Component\HttpFoundation\Response;

class BlockMaliciousRequests
{
    public function __construct(
        private readonly ThreatDetector $detector,
        private readonly IpResolver $ipResolver,
        private readonly BlockRepository $blocks,
    ) {}

    /**
     * @param Closure(Request): Response $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (! config('probe-guard.enabled', true)) {
            return $next($request);
        }

        $ipAddress = $this->ipResolver->resolve($request);

        if ($ipAddress === null || in_array($ipAddress, config('probe-guard.ip_whitelist', []), true)) {
            return $next($request);
        }

        $blockedIp = $this->blocks->find($ipAddress);

        if ($blockedIp?->isActive() === true) {
            $this->blocks->recordBlockedHit($blockedIp, $request);

            return response(
                config('probe-guard.blocked_response.body', 'Access blocked temporarily due to suspicious activity.'),
                (int) config('probe-guard.blocked_response.status', 403),
            );
        }

        if ($blockedIp !== null) {
            $this->blocks->unblock($blockedIp);
        }

        $result = $this->detector->detect($request);

        if ($result === null) {
            return $next($request);
        }

        event(new ThreatDetected($ipAddress, $request, $result));

        $this->blocks->block($ipAddress, $request, $result);
        $this->logDetection($ipAddress, $request, $result->reason);

        return response(
            config('probe-guard.detected_response.body'),
            (int) config('probe-guard.detected_response.status', 404),
        );
    }

    private function logDetection(string $ipAddress, Request $request, string $reason): void
    {
        if (! config('probe-guard.logging.enabled', true)) {
            return;
        }

        Log::channel(config('probe-guard.logging.channel'))->warning('Suspicious request blocked.', [
            'ip'         => $ipAddress,
            'path'       => '/' . ltrim($request->path(), '/'),
            'method'     => $request->method(),
            'reason'     => $reason,
            'user_agent' => $request->userAgent(),
        ]);
    }
}
