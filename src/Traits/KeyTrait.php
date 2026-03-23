<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Traits;

trait KeyTrait
{
    protected string $key = 'token';

    /**
     * Set the key to use for parsing tokens.
     */
    public function setKey(string $key): static
    {
        $this->key = $key;

        return $this;
    }

    /**
     * Get the key used for parsing tokens.
     */
    public function getKey(): string
    {
        return $this->key;
    }
}
