<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Algorithms;

use ArtTiger\JWTAuth\Abstracts\Algorithms\EcdsaAlgorithm;
use ArtTiger\JWTAuth\Enums\AlgorithmId;
use Lcobucci\JWT\Signer\Ecdsa\Sha512;

/**
 * ECDSA using P-521 and SHA-512 (ES512) — RFC 7518 §3.4.
 * Requires an EC key pair on the NIST P-521 (secp521r1) curve (521 bits).
 * Note: the curve is P-521 (521 bits), not P-512 — the name 'ES512' refers
 * to the SHA-512 hash function, not the key size.
 */
final class Es512 extends EcdsaAlgorithm
{
    public function id(): AlgorithmId
    {
        return AlgorithmId::ES512;
    }

    /** @return class-string<Sha512> */
    public function signerClass(): string
    {
        return Sha512::class;
    }

    protected function minimumCurveBits(): int
    {
        return 521;
    }
}
