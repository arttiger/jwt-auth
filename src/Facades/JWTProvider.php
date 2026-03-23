<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Facades;

use Illuminate\Support\Facades\Facade;

class JWTProvider extends Facade
{
    /**
     * Get the registered name of the component.
     */
    protected static function getFacadeAccessor(): string
    {
        return 'arttiger.jwt.provider.jwt';
    }
}
