<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Contracts;

interface JWTSubject
{
    /**
     * Get the identifier stored in the subject (sub) claim of the JWT.
     * RFC 7519 §4.1.2 requires sub to be a string.
     */
    public function getJWTIdentifier(): string;

    /**
     * Return a key/value array of custom claims to be added to the JWT.
     *
     * @return array<non-empty-string, mixed>
     */
    public function getJWTCustomClaims(): array;
}
