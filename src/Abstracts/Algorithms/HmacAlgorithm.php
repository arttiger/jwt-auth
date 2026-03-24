<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Abstracts\Algorithms;

use ArtTiger\JWTAuth\Algorithms\Algorithm;
use ArtTiger\JWTAuth\Exceptions\JWTException;
use SensitiveParameter;

/**
 * Base class for HMAC-based algorithms (HS256, HS384, HS512).
 *
 * RFC 7518 §3.2 mandates that the HMAC key MUST have a length equal to or
 * greater than the hash output length to prevent trivial brute-force attacks:
 *  - HS256 → SHA-256 → 256 bits → 32 bytes minimum
 *  - HS384 → SHA-384 → 384 bits → 48 bytes minimum
 *  - HS512 → SHA-512 → 512 bits → 64 bytes minimum
 */
abstract class HmacAlgorithm implements Algorithm
{
    /**
     * Minimum number of bytes the shared secret MUST contain for this algorithm.
     */
    abstract protected function minimumKeyBytes(): int;

    public function isAsymmetric(): bool
    {
        return false;
    }

    /**
     * @param array<string, mixed> $keys Unused for symmetric algorithms.
     *
     * @throws JWTException when the secret is absent or too short.
     */
    public function validateKeyMaterial(
        #[SensitiveParameter] ?string $secret,
        #[SensitiveParameter] array $keys,
    ): void {
        if ($secret === null || $secret === '') {
            throw new JWTException(
                message: "Algorithm {$this->id()->value} requires a non-empty shared secret. "
                .'Run `php artisan jwt:secret` to generate one.'
            );
        }

        $actual = strlen($secret);
        $required = $this->minimumKeyBytes();

        if ($actual < $required) {
            throw new JWTException(
                message: "Algorithm {$this->id()->value} requires a secret of at least {$required} bytes "
                ."({$actual} given). "
                .'Run `php artisan jwt:secret` to generate a secure key.'
            );
        }
    }
}
