<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Support;

trait CustomClaims
{
    /**
     * @var array<string, mixed>
     */
    protected array $customClaims = [];

    /**
     * @param array<string, mixed> $customClaims
     */
    public function customClaims(array $customClaims): static
    {
        $this->customClaims = $customClaims;

        return $this;
    }

    /**
     * @param array<string, mixed> $customClaims
     */
    public function claims(array $customClaims): static
    {
        return $this->customClaims($customClaims);
    }

    /**
     * @return array<string, mixed>
     */
    public function getCustomClaims(): array
    {
        return $this->customClaims;
    }
}
