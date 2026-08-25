<?php

namespace ProbeGuard\LaravelProbeGuard\Services;

use Illuminate\Http\Request;
use ProbeGuard\LaravelProbeGuard\Contracts\IpResolver;

class ClientIpResolver implements IpResolver
{
    public function resolve(Request $request): ?string
    {
        foreach (config('probe-guard.trusted_proxy_headers', []) as $header) {
            $value = $request->headers->get((string) $header);

            if ($value !== null && $this->canTrustProxyHeader($request)) {
                $ip = trim(explode(',', $value)[0]);

                if (filter_var($ip, FILTER_VALIDATE_IP) !== false) {
                    return $ip;
                }
            }
        }

        $ip = $request->ip();

        return is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP) !== false ? $ip : null;
    }

    private function canTrustProxyHeader(Request $request): bool
    {
        $trustedProxies = config('probe-guard.trusted_proxies', []);

        if ($trustedProxies === ['*']) {
            return true;
        }

        $remoteAddress = $request->server->get('REMOTE_ADDR');

        return is_string($remoteAddress) && in_array($remoteAddress, $trustedProxies, true);
    }
}
