<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Contracts\Providers;

interface Storage
{
    /**
     * Add an item to storage for a given number of minutes.
     */
    public function add(string $key, mixed $value, int $minutes): void;

    /**
     * Add an item to storage indefinitely.
     */
    public function forever(string $key, mixed $value): void;

    /**
     * Get an item from storage.
     */
    public function get(string $key): mixed;

    /**
     * Remove an item from storage.
     */
    public function destroy(string $key): bool;

    /**
     * Remove all items from storage.
     */
    public function flush(): void;
}
