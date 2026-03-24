<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Algorithms;

use ArtTiger\JWTAuth\Abstracts\Algorithms\EcdsaAlgorithm;
use ArtTiger\JWTAuth\Enums\AlgorithmId;
use Lcobucci\JWT\Signer\Ecdsa\Sha256;

/**
 * ECDSA using P-256 and SHA-256 (ES256) — RFC 7518 §3.4.
 * Requires an EC key pair on the NIST P-256 (prime256v1) curve (256 bits).
 */
final class Es256 extends EcdsaAlgorithm
{
    public function id(): AlgorithmId
    {
        return AlgorithmId::ES256;
    }

    /** @return class-string<Sha256> */
    public function signerClass(): string
    {
        return Sha256::class;
    }

    protected function minimumCurveBits(): int
    {
        return 256;
    }
}
