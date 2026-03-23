<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Validators;

use ArtTiger\JWTAuth\Exceptions\TokenInvalidException;

class TokenValidator extends Validator
{
    /**
     * Check the structure of the token.
     *
     * @throws TokenInvalidException
     */
    public function check(array $value): void
    {
        $this->validateStructure($value);
    }

    /**
     * @param string $token
     *
     * @return string
     *
     * @throws TokenInvalidException
     */
    protected function validateStructure($token)
    {
        $parts = explode('.', $token);

        if (3 !== count($parts)) {
            throw new TokenInvalidException(message: 'Wrong number of segments');
        }

        $parts = array_filter(array_map('trim', $parts));

        if (3 !== count($parts) || implode('.', $parts) !== $token) {
            throw new TokenInvalidException(message: 'Malformed token');
        }

        return $token;
    }
}
