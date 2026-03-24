<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Enums;

/**
 * RFC 7518 §3 cryptographic algorithm identifiers for JSON Web Signatures (JWS).
 *
 * Each case value is the exact "alg" header string used in the JWT header.
 * The "none" algorithm is intentionally excluded — unsigned tokens are not
 * supported and MUST NOT be used.
 */
enum AlgorithmId: string
{
    // ── HMAC with SHA-2 (RFC 7518 §3.2) ────────────────────────────────────

    /** HMAC using SHA-256 — requires a secret ≥ 32 bytes */
    case HS256 = 'HS256';

    /** HMAC using SHA-384 — requires a secret ≥ 48 bytes */
    case HS384 = 'HS384';

    /** HMAC using SHA-512 — requires a secret ≥ 64 bytes */
    case HS512 = 'HS512';

    // ── RSASSA-PKCS1-v1_5 (RFC 7518 §3.3) ──────────────────────────────────

    /** RSA with SHA-256 — requires an RSA key pair ≥ 2048 bits */
    case RS256 = 'RS256';

    /** RSA with SHA-384 — requires an RSA key pair ≥ 2048 bits */
    case RS384 = 'RS384';

    /** RSA with SHA-512 — requires an RSA key pair ≥ 2048 bits */
    case RS512 = 'RS512';

    // ── ECDSA (RFC 7518 §3.4) ───────────────────────────────────────────────

    /** ECDSA with P-256 and SHA-256 — curve must be NIST P-256 (prime256v1) */
    case ES256 = 'ES256';

    /** ECDSA with P-384 and SHA-384 — curve must be NIST P-384 (secp384r1) */
    case ES384 = 'ES384';

    /** ECDSA with P-521 and SHA-512 — curve must be NIST P-521 (secp521r1) */
    case ES512 = 'ES512';

    // ── Helpers ─────────────────────────────────────────────────────────────

    /**
     * Returns true for asymmetric algorithms (RSA, ECDSA) that require a
     * public/private key pair; false for symmetric (HMAC) algorithms.
     */
    public function isAsymmetric(): bool
    {
        return match($this) {
            self::RS256, self::RS384, self::RS512,
            self::ES256, self::ES384, self::ES512 => true,
            default                               => false,
        };
    }
}
