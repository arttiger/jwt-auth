<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Claims;

use ArtTiger\JWTAuth\Abstracts\Claim;
use ArtTiger\JWTAuth\Enums\ClaimName;
use ArtTiger\JWTAuth\Exceptions\TokenExpiredException;
use ArtTiger\JWTAuth\Traits\DatetimeTrait;

class Expiration extends Claim
{
    use DatetimeTrait;

    protected string $name = ClaimName::Expiration->value;

    public function getValue(): int
    {
        $value = parent::getValue();

        return is_int($value) ? $value : 0;
    }

    /**
     * @throws TokenExpiredException
     */
    public function validatePayload(): bool
    {
        if ($this->isPast($this->getValue())) {
            throw new TokenExpiredException(message: 'Token has expired');
        }

        return true;
    }
}
