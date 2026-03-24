<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Claims;

use ArtTiger\JWTAuth\Abstracts\Claim;
use ArtTiger\JWTAuth\Enums\ClaimName;
use ArtTiger\JWTAuth\Exceptions\InvalidClaimException;
use ArtTiger\JWTAuth\Exceptions\TokenExpiredException;
use ArtTiger\JWTAuth\Exceptions\TokenInvalidException;
use ArtTiger\JWTAuth\Traits\DatetimeTrait;

class IssuedAt extends Claim
{
    use DatetimeTrait {
        validateCreate as commonValidateCreate;
    }

    protected string $name = ClaimName::IssuedAt->value;

    public function getValue(): int
    {
        $value = parent::getValue();

        return is_int($value) ? $value : 0;
    }

    /**
     * @throws InvalidClaimException
     */
    public function validateCreate(mixed $value): int
    {
        $timestamp = $this->commonValidateCreate($value);

        if ($this->isFuture($timestamp)) {
            throw new InvalidClaimException($this);
        }

        return $timestamp;
    }

    /**
     * @throws TokenInvalidException
     */
    public function validatePayload(): bool
    {
        if ($this->isFuture($this->getValue())) {
            throw new TokenInvalidException(message: 'Issued At (iat) timestamp cannot be in the future');
        }

        return true;
    }

    /**
     * @throws TokenExpiredException
     */
    public function validateRefresh(int $refreshTTL): bool
    {
        if ($this->isPast($this->getValue() + $refreshTTL * 60)) {
            throw new TokenExpiredException(message: 'Token has expired and can no longer be refreshed');
        }

        return true;
    }
}
