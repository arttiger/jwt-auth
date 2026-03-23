<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Contracts;

interface Validator
{
    /**
     * Perform validation and throw on failure.
     *
     * @param array<mixed> $value
     */
    public function check(array $value): void;

    /**
     * Return a boolean indicating whether the value is valid.
     *
     * @param array<mixed> $value
     */
    public function isValid(array $value): bool;
}
