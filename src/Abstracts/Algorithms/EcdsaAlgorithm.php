<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Abstracts\Algorithms;

use ArtTiger\JWTAuth\Algorithms\Algorithm;
use ArtTiger\JWTAuth\Exceptions\JWTException;
use SensitiveParameter;

/**
 * Base class for ECDSA-based algorithms (ES256, ES384, ES512).
 *
 * Each ECDSA algorithm is bound to a specific NIST curve (RFC 7518 §3.4):
 *  - ES256 → P-256 (prime256v1) → 256 bits
 *  - ES384 → P-384 (secp384r1) → 384 bits
 *  - ES512 → P-521 (secp521r1) → 521 bits
 *
 * Using a key from the wrong curve will produce invalid signatures, so the
 * minimum bit-length is validated at construction time. If the PEM cannot be
 * parsed the check is skipped — the library will reject the key at runtime.
 */
abstract class EcdsaAlgorithm implements Algorithm
{
    /**
     * Minimum bit-length of the EC key for this algorithm.
     * Concrete classes return the exact curve size (256, 384, or 521).
     */
    abstract protected function minimumCurveBits(): int;

    public function isAsymmetric(): bool
    {
        return true;
    }

    /**
     * @param array<string, mixed> $keys
     *
     * @throws JWTException when the key pair is absent or uses the wrong curve.
     */
    public function validateKeyMaterial(
        #[SensitiveParameter] ?string $secret,
        #[SensitiveParameter] array $keys,
    ): void {
        $publicKey = isset($keys['public']) && is_string($keys['public']) ? $keys['public'] : null;
        $privateKey = isset($keys['private']) && is_string($keys['private']) ? $keys['private'] : null;

        if ($publicKey === null && $privateKey === null) {
            throw new JWTException(
                message: "Algorithm {$this->id()->value} requires a public/private key pair. "
                ."Set 'jwt.keys.public' and 'jwt.keys.private' in your configuration."
            );
        }

        $pem = $privateKey ?? $publicKey;
        if ($pem !== null && $pem !== '') {
            $this->assertCurveBits($pem);
        }
    }

    /**
     * @throws JWTException when the EC key uses a curve that is too small.
     */
    private function assertCurveBits(#[SensitiveParameter] string $pem): void
    {
        $resource = openssl_pkey_get_private($pem) ?: openssl_pkey_get_public($pem);

        if ($resource === false) {
            return; // passphrase-protected or file path — skip
        }

        $details = openssl_pkey_get_details($resource);

        if (! is_array($details) || ! isset($details['bits']) || ! is_int($details['bits'])) {
            return;
        }

        $required = $this->minimumCurveBits();

        if ($details['bits'] < $required) {
            throw new JWTException(
                message: "EC key for {$this->id()->value} must be at least {$required} bits "
                ."({$details['bits']} bits given). "
                .'Regenerate the key with the correct NIST curve.'
            );
        }
    }
}
