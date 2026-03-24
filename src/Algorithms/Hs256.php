<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Algorithms;

use ArtTiger\JWTAuth\Abstracts\Algorithms\HmacAlgorithm;
use ArtTiger\JWTAuth\Enums\AlgorithmId;
use Lcobucci\JWT\Signer\Hmac\Sha256;

/**
 * HMAC using SHA-256 (HS256) — RFC 7518 §3.2.
 * Requires a shared secret of at least 32 bytes (256 bits).
 */
final class Hs256 extends HmacAlgorithm
{
    public function id(): AlgorithmId
    {
        return AlgorithmId::HS256;
    }

    /** @return class-string<Sha256> */
    public function signerClass(): string
    {
        return Sha256::class;
    }

    protected function minimumKeyBytes(): int
    {
        return 32;
    }
}
