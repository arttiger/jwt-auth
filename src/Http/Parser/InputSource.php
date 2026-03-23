<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Http\Parser;

use ArtTiger\JWTAuth\Contracts\Http\Parser as ParserContract;
use ArtTiger\JWTAuth\Traits\KeyTrait;
use Illuminate\Http\Request;

class InputSource implements ParserContract
{
    use KeyTrait;

    /**
     * Try to parse the token from the request input source.
     */
    public function parse(Request $request): ?string
    {
        $value = $request->input($this->key);

        return is_string($value) ? $value : null;
    }
}
