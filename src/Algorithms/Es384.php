<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Algorithms;

use ArtTiger\JWTAuth\Abstracts\Algorithms\EcdsaAlgorithm;
use Lcobucci\JWT\Signer\Ecdsa\Sha384;

/**
 * ECDSA using P-384 and SHA-384 (ES384) — RFC 7518 §3.4.
 * Requires an EC key pair on the NIST P-384 (secp384r1) curve (384 bits).
 */
final class Es384 extends EcdsaAlgorithm
{
    public function id(): string
    {
        return 'ES384';
    }

    /** @return class-string<Sha384> */
    public function signerClass(): string
    {
        return Sha384::class;
    }

    protected function minimumCurveBits(): int
    {
        return 384;
    }
}
