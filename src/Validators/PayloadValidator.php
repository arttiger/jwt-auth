<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Validators;

use ArtTiger\JWTAuth\Abstracts\Validator;
use ArtTiger\JWTAuth\Collections\ClaimCollection;
use ArtTiger\JWTAuth\Enums\ClaimName;
use ArtTiger\JWTAuth\Exceptions\TokenExpiredException;
use ArtTiger\JWTAuth\Exceptions\TokenInvalidException;

class PayloadValidator extends Validator
{
    /**
     * The required claims.
     *
     * @var string[]
     */
    protected array $requiredClaims = [
        ClaimName::Issuer->value,
        ClaimName::IssuedAt->value,
        ClaimName::Expiration->value,
        ClaimName::NotBefore->value,
        ClaimName::Subject->value,
        ClaimName::JwtId->value,
    ];

    /**
     * The refresh TTL in minutes (null = no limit).
     */
    protected ?int $refreshTTL = 20160;

    /**
     * Run the validations on the claims collection.
     *
     * @param array<mixed> $value
     */
    public function check(array $value): void
    {
        // $value is expected to be a Collection passed via check($claims)
        // but since the contract requires array<mixed>, we receive a Collection
        // which extends Illuminate Collection and is iterable.
        // The actual Collection is passed from Payload::__construct.
        /** @var ClaimCollection $claims */
        $claims = $value[0] ?? $value;

        $this->validateStructure($claims);

        if ($this->refreshFlow) {
            $this->validateRefresh($claims);
        } else {
            $this->validatePayload($claims);
        }
    }

    /**
     * Validate a Claims Collection directly (used by Payload).
     *
     * @throws TokenInvalidException
     */
    public function validateCollection(ClaimCollection $claims): void
    {
        $this->validateStructure($claims);

        if ($this->refreshFlow) {
            $this->validateRefresh($claims);
        } else {
            $this->validatePayload($claims);
        }
    }

    /**
     * Ensure the payload contains the required claims.
     *
     * @throws TokenInvalidException
     */
    protected function validateStructure(ClaimCollection $claims): void
    {
        if ($this->requiredClaims && ! $claims->hasAllClaims($this->requiredClaims)) {
            throw new TokenInvalidException(message: 'JWT payload does not contain the required claims');
        }
    }

    /**
     * Validate the payload timestamps.
     *
     * @throws TokenInvalidException
     * @throws TokenExpiredException
     */
    protected function validatePayload(ClaimCollection $claims): void
    {
        $claims->validate('payload');
    }

    /**
     * Check the token in the refresh flow context.
     *
     * @throws TokenExpiredException
     */
    protected function validateRefresh(ClaimCollection $claims): void
    {
        if ($this->refreshTTL !== null) {
            $claims->validate('refresh', $this->refreshTTL);
        }
    }

    /**
     * Set the required claims.
     *
     * @param string[] $claims
     */
    public function setRequiredClaims(array $claims): self
    {
        $this->requiredClaims = $claims;

        return $this;
    }

    /**
     * Set the refresh TTL in minutes.
     */
    public function setRefreshTTL(?int $ttl): self
    {
        $this->refreshTTL = $ttl;

        return $this;
    }
}
