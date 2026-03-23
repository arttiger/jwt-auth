<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Claims;

use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Contracts\Support\Jsonable;
use ArtTiger\JWTAuth\Contracts\Claim as ClaimContract;
use ArtTiger\JWTAuth\Exceptions\InvalidClaimException;
use JsonSerializable;
use ReturnTypeWillChange;

abstract class Claim implements Arrayable, ClaimContract, Jsonable, JsonSerializable
{
    /**
     * The claim name.
     *
     * @var string
     */
    protected string $name;

    /**
     * The claim value.
     */
    private $value;

    /**
     * @return void
     *
     * @throws InvalidClaimException
     */
    public function __construct($value)
    {
        $this->setValue($value);
    }

    /**
     * Set the claim value, and call a validate method.
     *
     * @return $this
     *
     * @throws InvalidClaimException
     */
    public function setValue($value)
    {
        $this->value = $this->validateCreate($value);

        return $this;
    }

    /**
     * Get the claim value.
     */
    public function getValue()
    {
        return $this->value;
    }

    /**
     * Set the claim name.
     */
    public function setName(string $name): self
    {
        $this->name = $name;

        return $this;
    }

    /**
     * Get the claim name.
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Validate the claim in a standalone Claim context.
     *
     * @return bool
     */
    public function validateCreate($value)
    {
        return $value;
    }

    /**
     * Validate the Claim within a Payload context.
     *
     * @return bool
     */
    public function validatePayload()
    {
        return $this->getValue();
    }

    /**
     * Validate the Claim within a refresh context.
     *
     * @param int $refreshTTL
     *
     * @return bool
     */
    public function validateRefresh($refreshTTL)
    {
        return $this->getValue();
    }

    /**
     * Checks if the value matches the claim.
     *
     * @param bool $strict
     *
     * @return bool
     */
    public function matches($value, $strict = true)
    {
        return $strict ? $this->value === $value : $this->value == $value;
    }

    /**
     * Convert the object into something JSON serializable.
     *
     * @return array
     */
    #[ReturnTypeWillChange]
    public function jsonSerialize()
    {
        return $this->toArray();
    }

    /**
     * Build a key value array comprising of the claim name and value.
     *
     * @return array
     */
    public function toArray(): array
    {
        return [$this->getName() => $this->getValue()];
    }

    /**
     * Get the claim as JSON.
     */
    public function toJson($options = JSON_UNESCAPED_SLASHES)
    {
        return json_encode($this->toArray(), $options);
    }

    /**
     * Get the payload as a string.
     *
     * @return string
     */
    public function __toString()
    {
        return $this->toJson();
    }
}
