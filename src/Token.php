<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth;

use ArtTiger\JWTAuth\Exceptions\TokenInvalidException;
use Illuminate\Support\Stringable;
use Stringable as StringableContract;
use ArtTiger\JWTAuth\Validators\TokenValidator;

readonly class Token implements StringableContract
{
    private string $value;

    /**
     * Create a new JSON Web Token.
     *
     * @throws TokenInvalidException
     */
    public function __construct(Stringable|self|string $value)
    {
        $this->value = match (true) {
            $value instanceof self => $value->get(),
            $value instanceof Stringable => (new TokenValidator())->validate($value->toString()),
            default => (new TokenValidator())->validate($value),
        };
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
