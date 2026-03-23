<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Traits;

use ArtTiger\JWTAuth\Exceptions\InvalidClaimException;
use ArtTiger\JWTAuth\Support\Utils;

trait DatetimeTrait
{
    protected int $leeway = 0;

    /**
     * @throws InvalidClaimException
     */
    public function setValue(mixed $value): static
    {
        if ($value instanceof \DateInterval) {
            $value = Utils::now()->add($value);
        }

        if ($value instanceof \DateTimeInterface) {
            $value = $value->getTimestamp();
        }

        return parent::setValue($value);
    }

    public function validateCreate(mixed $value): int
    {
        if (! is_numeric($value)) {
            throw new InvalidClaimException($this);
        }

        return (int) $value;
    }

    protected function isFuture(int $value): bool
    {
        return Utils::isFuture($value, $this->leeway);
    }

    protected function isPast(int $value): bool
    {
        return Utils::isPast($value, $this->leeway);
    }

    public function setLeeway(int $leeway): static
    {
        $this->leeway = $leeway;

        return $this;
    }
}
