<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Algorithms;

use ArtTiger\JWTAuth\Abstracts\Algorithms\HmacAlgorithm;
use ArtTiger\JWTAuth\Enums\AlgorithmId;
use Lcobucci\JWT\Signer\Hmac\Sha512;

/**
 * HMAC using SHA-512 (HS512) — RFC 7518 §3.2.
 * Requires a shared secret of at least 64 bytes (512 bits).
 */
final class Hs512 extends HmacAlgorithm
{
    public function id(): AlgorithmId
    {
        return AlgorithmId::HS512;
    }

    /** @return class-string<Sha512> */
    public function signerClass(): string
    {
        return Sha512::class;
    }

    protected function minimumKeyBytes(): int
    {
        return 64;
    }
}
