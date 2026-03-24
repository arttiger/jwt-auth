<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Algorithms;

use ArtTiger\JWTAuth\Exceptions\JWTException;
use Lcobucci\JWT\Signer;
use SensitiveParameter;

/**
 * Typed representation of a JWT signing algorithm (RFC 7518).
 *
 * Each concrete implementation encodes:
 *  - the RFC 7518 algorithm identifier (e.g. 'HS256')
 *  - whether the algorithm is symmetric or asymmetric
 *  - the Lcobucci JWT Signer class that implements it
 *  - the key-material constraints required for safe use
 */
interface Algorithm
{
    /**
     * RFC 7518 algorithm identifier, e.g. 'HS256', 'RS384', 'ES512'.
     */
    public function id(): string;

    /**
     * Returns true for RSA / ECDSA algorithms that require a public/private key pair.
     * Returns false for HMAC algorithms that use a shared secret.
     */
    public function isAsymmetric(): bool;

    /**
     * Returns the fully-qualified class name of the Lcobucci JWT Signer
     * that implements this algorithm.
     *
     * @return class-string<Signer>
     */
    public function signerClass(): string;

    /**
     * Validates that the supplied key material is safe for this algorithm.
     *
     * @param array<string, mixed> $keys Asymmetric key pair ('public', 'private', 'passphrase').
     *
     * @throws JWTException when the key material does not meet the algorithm's requirements.
     */
    public function validateKeyMaterial(
        #[SensitiveParameter] ?string $secret,
        #[SensitiveParameter] array   $keys,
    ): void;
}
