<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test\Stubs;

use ArtTiger\JWTAuth\Contracts\JWTSubject;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * A stub that satisfies both Authenticatable and JWTSubject.
 * Used in JWTGuardTest and JWTUserProviderTest where a real user object is needed.
 */
class AuthUserStub implements Authenticatable, JWTSubject
{
    public function __construct(public int $id = 1)
    {
    }

    public function getAuthIdentifier(): int
    {
        return $this->id;
    }

    public function getAuthIdentifierName(): string
    {
        return 'id';
    }

    public function getAuthPassword(): string
    {
        return 'hashed';
    }

    public function getRememberToken(): string
    {
        return '';
    }

    public function setRememberToken($value): void
    {
    }

    public function getRememberTokenName(): string
    {
        return 'remember_token';
    }

    public function getJWTIdentifier(): int|string
    {
        return $this->id;
    }

    /**
     * @return array<string, mixed>
     */
    public function getJWTCustomClaims(): array
    {
        return [];
    }

    public function getAuthPasswordName(): string
    {
        return 'password';
    }
}
