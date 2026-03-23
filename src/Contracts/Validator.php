<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Contracts;

interface Validator
{
    /**
     * Perform some checks on the value.
     */
    public function check(array $value): void;

    /**
     * Helper function to return a boolean.
     */
    public function isValid(array $value): bool;
}
