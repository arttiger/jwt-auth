<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Claims;

use ArtTiger\JWTAuth\Abstracts\Claim;
use ArtTiger\JWTAuth\Exceptions\TokenInvalidException;
use ArtTiger\JWTAuth\Traits\DatetimeTrait;

class NotBefore extends Claim
{
    use DatetimeTrait;

    protected string $name = 'nbf';

    public function getValue(): int
    {
        $value = parent::getValue();

        return is_int($value) ? $value : 0;
    }

    /**
     * RFC 7519 §4.1.5: the current date/time MUST be after or equal to the
     * not-before date/time. Implementers MAY provide for some small leeway
     * (usually no more than a few minutes) to account for clock skew — this
     * is controlled via {@see DatetimeTrait::$leeway}.
     * Its value MUST be a number containing a NumericDate value.
     * Use of this claim is OPTIONAL.
     *
     * @throws TokenInvalidException when the token is submitted before the nbf timestamp (minus leeway).
     */
    public function validatePayload(): bool
    {
        if ($this->isFuture($this->getValue())) {
            throw new TokenInvalidException(message: 'Not Before (nbf) timestamp cannot be in the future');
        }

        return true;
    }
}
