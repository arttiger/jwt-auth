<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth;

use Stringable;
use ArtTiger\JWTAuth\Validators\TokenValidator;

class Token implements Stringable
{
    private readonly string $value;

    /**
     * Create a new JSON Web Token.
     *
     * @throws Exceptions\TokenInvalidException
     */
    public function __construct(string $value)
    {
        $this->value = (new TokenValidator())->validate($value);
    }

    /**
     * Get the token.
     */
    public function get(): string
    {
        return $this->value;
    }

    /**
     * Get the token when casting to string.
     */
    public function __toString(): string
    {
        return $this->get();
    }
}
