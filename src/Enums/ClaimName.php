<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Enums;

/**
 * RFC 7519 §4.1 registered claim names.
 *
 * Each case value is the exact string identifier used in the JWT payload
 * as mandated by the specification.  Using this enum instead of bare
 * string literals prevents typos and enables IDE autocompletion.
 */
enum ClaimName: string
{
    /** §4.1.1 — "iss" (Issuer) Claim */
    case Issuer     = 'iss';

    /** §4.1.2 — "sub" (Subject) Claim */
    case Subject    = 'sub';

    /** §4.1.3 — "aud" (Audience) Claim */
    case Audience   = 'aud';

    /** §4.1.4 — "exp" (Expiration Time) Claim */
    case Expiration = 'exp';

    /** §4.1.5 — "nbf" (Not Before) Claim */
    case NotBefore  = 'nbf';

    /** §4.1.6 — "iat" (Issued At) Claim */
    case IssuedAt   = 'iat';

    /** §4.1.7 — "jti" (JWT ID) Claim */
    case JwtId      = 'jti';
}
