<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Http\Parser;

use ArtTiger\JWTAuth\Contracts\Http\Parser as ParserContract;
use ArtTiger\JWTAuth\Traits\KeyTrait;
use Illuminate\Http\Request;
use Illuminate\Routing\Route;

class RouteParams implements ParserContract
{
    use KeyTrait;

    /**
     * Try to get the token from the route parameters.
     */
    public function parse(Request $request): ?string
    {
        $route = $request->route();

        if (! $route instanceof Route) {
            return null;
        }

        $value = $route->parameter($this->key);

        return is_string($value) ? $value : null;
    }
}
