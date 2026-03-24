<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Validators;

use ArtTiger\JWTAuth\Exceptions\TokenInvalidException;

/**
 * Validates the structural integrity of a JWT string.
 * Not part of the Validator hierarchy since it operates on strings, not arrays.
 */
class TokenValidator
{
    /**
     * Validate the JWT string structure and return the token on success.
     *
     * @throws TokenInvalidException
     */
    public function validate(string $token): string
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            throw new TokenInvalidException(message: 'Wrong number of segments');
        }

        $parts = array_filter(array_map(trim(...), $parts));

        if (count($parts) !== 3 || implode('.', $parts) !== $token) {
            throw new TokenInvalidException(message: 'Malformed token');
        }

        return $token;
    }
}
