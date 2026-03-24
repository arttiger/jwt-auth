<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Abstracts;

use ArtTiger\JWTAuth\Collections\ClaimCollection;
use ArtTiger\JWTAuth\Contracts\Validator as ValidatorContract;
use ArtTiger\JWTAuth\Exceptions\JWTException;
use ArtTiger\JWTAuth\Support\RefreshFlow;

abstract class Validator implements ValidatorContract
{
    use RefreshFlow;

    /**
     * @param array<mixed> $value
     */
    public function isValid(array $value): bool
    {
        try {
            $this->check($value);
        } catch (JWTException) {
            return false;
        }

        return true;
    }

    /**
     * @param array<mixed> $value
     */
    abstract public function check(array $value): void;

    abstract public function validateCollection(ClaimCollection $claims): void;
}
