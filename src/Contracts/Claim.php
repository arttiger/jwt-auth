<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Contracts;

use ArtTiger\JWTAuth\Exceptions\InvalidClaimException;

interface Claim
{
    /**
     * Set the claim value, and call a validate method.
     *
     * @throws InvalidClaimException
     */
    public function setValue(mixed $value): static;

    /**
     * Get the claim value.
     */
    public function getValue(): mixed;

    /**
     * Set the claim name.
     */
    public function setName(string $name): static;

    /**
     * Get the claim name.
     */
    public function getName(): string;

    /**
     * Validate the Claim value on creation.
     */
    public function validateCreate(mixed $value): mixed;
}
