<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Validators;

use ArtTiger\JWTAuth\Claims\Collection;
use ArtTiger\JWTAuth\Exceptions\TokenInvalidException;

class PayloadValidator extends Validator
{
    /**
     * The required claims.
     *
     * @var string[]
     */
    protected array $requiredClaims = [
        'iss',
        'iat',
        'exp',
        'nbf',
        'sub',
        'jti',
    ];

    /**
     * The refresh TTL.
     */
    protected int $refreshTTL = 20160;

    /**
     * Run the validations on the payload array.
     *
     * @param array $value
     *
     * @return Collection
     */
    public function check(array $value)
    {
        $this->validateStructure($value);

        return $this->refreshFlow ? $this->validateRefresh($value) : $this->validatePayload($value);
    }

    /**
     * Ensure the payload contains the required claims and
     * the claims have the relevant type.
     *
     * @return void
     *
     * @throws TokenInvalidException
     */
    protected function validateStructure(Collection $claims)
    {
        if ($this->requiredClaims && !$claims->hasAllClaims($this->requiredClaims)) {
            throw new TokenInvalidException('JWT payload does not contain the required claims');
        }
    }

    /**
     * Validate the payload timestamps.
     *
     * @return Collection
     *
     * @throws TokenInvalidException
     * @throws \ArtTiger\JWTAuth\Exceptions\TokenExpiredException
     */
    protected function validatePayload(Collection $claims)
    {
        return $claims->validate('payload');
    }

    /**
     * Check the token in the refresh flow context.
     *
     * @return Collection
     *
     * @throws \ArtTiger\JWTAuth\Exceptions\TokenExpiredException
     */
    protected function validateRefresh(Collection $claims)
    {
        return null === $this->refreshTTL ? $claims : $claims->validate('refresh', $this->refreshTTL);
    }

    /**
     * Set the required claims.
     *
     * @return $this
     */
    public function setRequiredClaims(array $claims)
    {
        $this->requiredClaims = $claims;

        return $this;
    }

    /**
     * Set the refresh ttl.
     */
    public function setRefreshTTL(int $ttl): static
    {
        $this->refreshTTL = $ttl;

        return $this;
    }
}
