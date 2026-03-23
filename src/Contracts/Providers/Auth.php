<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Contracts\Providers;

interface Auth
{
    /**
     * Check a user's credentials and authenticate them.
     *
     * @param array<string, mixed> $credentials
     */
    public function byCredentials(array $credentials): bool;

    /**
     * Authenticate a user via their identifier.
     */
    public function byId(int|string $id): bool;

    /**
     * Get the currently authenticated user.
     */
    public function user(): mixed;
}
