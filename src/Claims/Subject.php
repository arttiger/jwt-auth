<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Claims;

use ArtTiger\JWTAuth\Abstracts\Claim;
use ArtTiger\JWTAuth\Exceptions\InvalidClaimException;

class Subject extends Claim
{
    protected string $name = 'sub';

    /**
     * RFC 7519 §4.1.2: value MUST be a StringOrURI — a case-sensitive string
     * that is either scoped to be locally unique within the issuer context or
     * globally unique. If the string contains an ":" character, it MUST be a
     * valid URI (RFC 3986); otherwise any non-empty string is acceptable.
     * Use of this claim is OPTIONAL.
     *
     * @throws InvalidClaimException
     */
    public function validateCreate(mixed $value): string
    {
        if (! is_string($value) || $value === '') {
            throw new InvalidClaimException($this);
        }

        // StringOrURI: any value containing ":" MUST be a valid URI (RFC 3986).
        if (str_contains($value, ':') && filter_var($value, FILTER_VALIDATE_URL) === false) {
            throw new InvalidClaimException($this);
        }

        return $value;
    }
}
