<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Algorithms;

use ArtTiger\JWTAuth\Enums\AlgorithmId;
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
     * Returns all registered algorithms keyed by their RFC 7518 identifier string.
     *
     * @return array<string, Algorithm>
     */
    public static function all(): array
    {
        if (self::$algorithms === null) {
            self::$algorithms = [
                AlgorithmId::HS256->value => new Hs256(),
                AlgorithmId::HS384->value => new Hs384(),
                AlgorithmId::HS512->value => new Hs512(),
                AlgorithmId::RS256->value => new Rs256(),
                AlgorithmId::RS384->value => new Rs384(),
                AlgorithmId::RS512->value => new Rs512(),
                AlgorithmId::ES256->value => new Es256(),
                AlgorithmId::ES384->value => new Es384(),
                AlgorithmId::ES512->value => new Es512(),
            ];
        }

        return self::$algorithms;
    }

    /**
     * Looks up a typed Algorithm by its RFC 7518 identifier.
     *
     * Accepts either an {@see AlgorithmId} enum case or a plain string for
     * backward compatibility with config values.
     *
     * @throws JWTException when the identifier is 'none' or not recognised.
     */
    public static function find(AlgorithmId|string $id): Algorithm
    {
        $value = $id instanceof AlgorithmId ? $id->value : $id;

        if (strtolower($value) === 'none') {
            throw new JWTException(
                message: 'Algorithm "none" is explicitly not supported. '
                .'Unsigned tokens cannot be used with this library.'
            );
        }

        $all = self::all();

        if (! isset($all[$value])) {
            throw new JWTException(
                message: "Algorithm '{$value}' is not supported. "
                .'Supported algorithms: '.implode(', ', array_keys($all)).'.'
            );
        }

        return $all[$value];
    }

    /**
     * Returns true when the given identifier maps to a registered algorithm.
     */
    public static function supports(AlgorithmId|string $id): bool
    {
        $value = $id instanceof AlgorithmId ? $id->value : $id;

        return isset(self::all()[$value]);
    }
}
