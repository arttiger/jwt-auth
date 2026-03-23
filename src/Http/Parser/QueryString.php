<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Http\Parser;

use ArtTiger\JWTAuth\Contracts\Http\Parser as ParserContract;
use ArtTiger\JWTAuth\Traits\KeyTrait;
use Illuminate\Http\Request;

class QueryString implements ParserContract
{
    use KeyTrait;

    /**
     * Try to parse the token from the request query string.
     */
    public function parse(Request $request): ?string
    {
        $value = $request->query(key: $this->key);

        return is_string($value) ? $value : null;
    }
}
