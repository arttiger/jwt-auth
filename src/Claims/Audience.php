<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Claims;

use ArtTiger\JWTAuth\Abstracts\Claim;
use ArtTiger\JWTAuth\Exceptions\InvalidClaimException;

class Audience extends Claim
{
    protected string $name = 'aud';

    /**
     * RFC 7519 §4.1.3: value MUST be a case-sensitive string or an array of
     * case-sensitive strings.
     *
     * @return string|list<string>
     */
    public function validateCreate(mixed $value): string|array
    {
        if (is_string($value)) {
            return $value;
        }

        if (! is_array($value) || count($value) === 0) {
            throw new InvalidClaimException($this);
        }

        $strings = [];
        foreach ($value as $item) {
            if (! is_string($item)) {
                throw new InvalidClaimException($this);
            }
            $strings[] = $item;
        }

        return $strings;
    }
}
