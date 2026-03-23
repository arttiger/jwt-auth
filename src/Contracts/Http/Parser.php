<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Contracts\Http;

use Illuminate\Http\Request;

interface Parser
{
    /**
     * Parse the token from the request.
     */
    public function parse(Request $request): ?string;
}
