<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Algorithms;

use ArtTiger\JWTAuth\Abstracts\Algorithms\HmacAlgorithm;
use ArtTiger\JWTAuth\Enums\AlgorithmId;
use Lcobucci\JWT\Signer\Hmac\Sha384;

/**
 * HMAC using SHA-384 (HS384) — RFC 7518 §3.2.
 * Requires a shared secret of at least 48 bytes (384 bits).
 */
final class Hs384 extends HmacAlgorithm
{
    public function id(): AlgorithmId
    {
        return AlgorithmId::HS384;
    }

    /** @return class-string<Sha384> */
    public function signerClass(): string
    {
        return Sha384::class;
    }

    protected function minimumKeyBytes(): int
    {
        return 48;
    }
}
