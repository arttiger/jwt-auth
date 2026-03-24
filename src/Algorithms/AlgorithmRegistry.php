<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Algorithms;

use ArtTiger\JWTAuth\Exceptions\JWTException;

/**
 * Registry of all supported JWT signing algorithms.
 *
 * Provides a single lookup point so that callers never have to maintain their
 * own string→class maps or guard against unsupported algorithm identifiers.
 * The 'none' algorithm is intentionally excluded — unsigned tokens are not
 * supported and will be rejected at the signing/verification layer.
 */
final class AlgorithmRegistry
{
    /** @var array<string, Algorithm>|null */
    private static ?array $algorithms = null;

    /**
     * Returns all registered algorithms keyed by their RFC 7518 identifier.
     *
     * @return array<string, Algorithm>
     */
    public static function all(): array
    {
        if (self::$algorithms === null) {
            self::$algorithms = [
                'HS256' => new Hs256(),
                'HS384' => new Hs384(),
                'HS512' => new Hs512(),
                'RS256' => new Rs256(),
                'RS384' => new Rs384(),
                'RS512' => new Rs512(),
                'ES256' => new Es256(),
                'ES384' => new Es384(),
                'ES512' => new Es512(),
            ];
        }

        return self::$algorithms;
    }

    /**
     * Looks up a typed Algorithm by its RFC 7518 identifier.
     *
     * @throws JWTException when the identifier is not recognised or is 'none'.
     */
    public static function find(string $id): Algorithm
    {
        if (strtolower($id) === 'none') {
            throw new JWTException(
                'Algorithm "none" is explicitly not supported. '
                .'Unsigned tokens cannot be used with this library.'
            );
        }

        $all = self::all();

        if (! isset($all[$id])) {
            throw new JWTException(
                "Algorithm '{$id}' is not supported. "
                .'Supported algorithms: '.implode(', ', array_keys($all)).'.'
            );
        }

        return $all[$id];
    }

    /**
     * Returns true when the given identifier maps to a registered algorithm.
     */
    public static function supports(string $id): bool
    {
        return isset(self::all()[$id]);
    }
}
