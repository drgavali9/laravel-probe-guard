<?php

namespace ProbeGuard\LaravelProbeGuard\Contracts;

use Illuminate\Http\Request;

interface IpResolver
{
    public function resolve(Request $request): ?string;
}
