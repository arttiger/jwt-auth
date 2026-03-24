<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test\Stubs;

use ArtTiger\JWTAuth\Contracts\JWTSubject;

class UserStub implements JWTSubject
{
    public function getJWTIdentifier(): int|string
    {
        return 1;
    }

    /**
     * @return array<string, mixed>
     */
    public function getJWTCustomClaims(): array
    {
        return [
            'foo'  => 'bar',
            'role' => 'admin',
        ];
    }
}
