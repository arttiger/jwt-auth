<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Algorithms;

use ArtTiger\JWTAuth\Abstracts\Algorithms\RsaAlgorithm;
use ArtTiger\JWTAuth\Enums\AlgorithmId;
use Lcobucci\JWT\Signer\Rsa\Sha256;

/**
 * RSASSA-PKCS1-v1_5 using SHA-256 (RS256) — RFC 7518 §3.3.
 * Requires an RSA key pair of at least 2048 bits.
 */
final class Rs256 extends RsaAlgorithm
{
    public function id(): AlgorithmId
    {
        return AlgorithmId::RS256;
    }

    /** @return class-string<Sha256> */
    public function signerClass(): string
    {
        return Sha256::class;
    }
}
