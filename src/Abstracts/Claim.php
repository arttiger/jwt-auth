<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Abstracts;

use ArtTiger\JWTAuth\Contracts\Claim as ClaimContract;
use ArtTiger\JWTAuth\Exceptions\InvalidClaimException;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Contracts\Support\Jsonable;
use JsonSerializable;

/**
 * @implements Arrayable<string, mixed>
 */
abstract class Claim implements Arrayable, ClaimContract, Jsonable, JsonSerializable
{
    protected string $name;

    private mixed $value;

    /**
     * @throws InvalidClaimException
     */
    public function __construct(mixed $value)
    {
        $this->setValue($value);
    }

    /**
     * @throws InvalidClaimException
     */
    public function setValue(mixed $value): static
    {
        $this->value = $this->validateCreate($value);

        return $this;
    }

    public function getValue(): mixed
    {
        return $this->value;
    }

    public function setName(string $name): static
    {
        $this->name = $name;

        return $this;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function setLeeway(int $leeway): static
    {
        return $this;
    }

    public function validateCreate(mixed $value): mixed
    {
        return $value;
    }

    public function validatePayload(): mixed
    {
        return $this->getValue();
    }

    public function validateRefresh(int $refreshTTL): mixed
    {
        return $this->getValue();
    }

    public function matches(mixed $value, bool $strict = true): bool
    {
        return $strict ? $this->value === $value : $this->value == $value;
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [$this->getName() => $this->getValue()];
    }

    public function toJson(mixed $options = JSON_UNESCAPED_SLASHES): string
    {
        return (string) json_encode($this->toArray(), (int) $options | JSON_THROW_ON_ERROR);
    }

    public function __toString(): string
    {
        return $this->toJson();
    }
}
