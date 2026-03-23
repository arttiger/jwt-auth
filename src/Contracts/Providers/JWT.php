<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Contracts\Providers;

interface JWT
{
    /**
     * Encode the payload and return a token string.
     *
     * @param array<string, mixed> $payload
     */
    public function encode(array $payload): string;

    /**
     * Decode a token string and return the payload array.
     *
     * @return array<string, mixed>
     */
    public function decode(string $token): array;
}
