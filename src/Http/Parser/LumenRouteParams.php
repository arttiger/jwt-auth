<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Http\Parser;

use Illuminate\Http\Request;
use Illuminate\Support\Arr;

class LumenRouteParams extends RouteParams
{
    /**
     * Try to get the token from the route parameters.
     */
    public function parse(Request $request): ?string
    {
        // WARNING: Only use this parser if you know what you're doing!
        // It will only work with poorly-specified aspects of certain Lumen releases.
        $resolver = $request->getRouteResolver();
        $route = $resolver();

        if (! is_array($route)) {
            return null;
        }

        $value = Arr::get($route, '2.'.$this->key);

        return is_string($value) ? $value : null;
    }
}
