<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Providers\Auth;

use Illuminate\Contracts\Auth\StatefulGuard as GuardContract;
use ArtTiger\JWTAuth\Contracts\Providers\Auth;

class Illuminate implements Auth
{
    public function __construct(protected GuardContract $auth)
    {
    }

    public function byCredentials(array $credentials): bool
    {
        return (bool) $this->auth->once($credentials);
    }

    public function byId(int|string $id): bool
    {
        return (bool) $this->auth->onceUsingId($id);
    }

    public function user(): mixed
    {
        return $this->auth->user();
    }
}
