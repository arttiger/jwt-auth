<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Claims;

use ArtTiger\JWTAuth\Abstracts\Claim;
use ArtTiger\JWTAuth\Exceptions\InvalidClaimException;

class JwtId extends Claim
{
    protected string $name = 'jti';

    /**
     * @throws InvalidClaimException
     */
    public function validateCreate(mixed $value): string
    {
        if (! is_string($value)) {
            throw new InvalidClaimException($this);
        }

        return $value;
    }
}
