<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Abstracts\Algorithms;

use ArtTiger\JWTAuth\Algorithms\Algorithm;
use ArtTiger\JWTAuth\Exceptions\JWTException;
use SensitiveParameter;

/**
 * Base class for RSA-based algorithms (RS256, RS384, RS512).
 *
 * NIST SP 800-131A and industry best practice require RSA keys to be at least
 * 2048 bits. Keys smaller than this are considered cryptographically weak and
 * MUST NOT be used in new systems.
 *
 * If the PEM content cannot be parsed (e.g. it is a file path, or the private
 * key is passphrase-protected and the passphrase was not supplied), the length
 * check is skipped rather than failing — the underlying library will still
 * reject an unusable key at signing/verification time.
 */
abstract class RsaAlgorithm implements Algorithm
{
    private const int MINIMUM_BITS = 2048;

    public function isAsymmetric(): bool
    {
        return true;
    }

    /**
     * @param array<string, mixed> $keys
     *
     * @throws JWTException when the key pair is absent or the RSA key is too short.
     */
    public function validateKeyMaterial(
        #[SensitiveParameter] ?string $secret,
        #[SensitiveParameter] array $keys,
    ): void {
        $publicKey = isset($keys['public'])  && is_string($keys['public'])  ? $keys['public']  : null;
        $privateKey = isset($keys['private']) && is_string($keys['private']) ? $keys['private'] : null;

        if ($publicKey === null && $privateKey === null) {
            throw new JWTException(
                message: "Algorithm {$this->id()->value} requires a public/private key pair. "
                ."Set 'jwt.keys.public' and 'jwt.keys.private' in your configuration."
            );
        }

        // Prefer the private key for bit-length inspection; fall back to public.
        $pem = $privateKey ?? $publicKey;
        if ($pem !== null && $pem !== '') {
            $this->assertMinimumKeyBits($pem);
        }
    }

    /**
     * @throws JWTException when the RSA key is shorter than {@see MINIMUM_BITS}.
     */
    private function assertMinimumKeyBits(#[SensitiveParameter] string $pem): void
    {
        $resource = openssl_pkey_get_private($pem) ?: openssl_pkey_get_public($pem);

        if ($resource === false) {
            // Cannot parse — key may be passphrase-protected or a file path; skip.
            return;
        }

        $details = openssl_pkey_get_details($resource);

        if (! is_array($details) || ! isset($details['bits']) || ! is_int($details['bits'])) {
            return;
        }

        if ($details['bits'] < self::MINIMUM_BITS) {
            throw new JWTException(
                message: "RSA key for {$this->id()->value} must be at least ".self::MINIMUM_BITS." bits; "
                ."{$details['bits']} bits given. Regenerate the key with a stronger size."
            );
        }
    }
}
