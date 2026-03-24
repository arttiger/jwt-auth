<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Algorithms;

use ArtTiger\JWTAuth\Abstracts\Algorithms\RsaAlgorithm;
use Lcobucci\JWT\Signer\Rsa\Sha384;

/**
 * RSASSA-PKCS1-v1_5 using SHA-384 (RS384) — RFC 7518 §3.3.
 * Requires an RSA key pair of at least 2048 bits.
 */
final class Rs384 extends RsaAlgorithm
{
    public function id(): string
    {
        return 'RS384';
    }

    /** @return class-string<Sha384> */
    public function signerClass(): string
    {
        return Sha384::class;
    }
}
