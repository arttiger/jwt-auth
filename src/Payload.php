<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth;

use ArtTiger\JWTAuth\Collections\ClaimCollection;
use Stringable;
use BadMethodCallException;
use ArrayAccess;
use ArtTiger\JWTAuth\Abstracts\Claim;
use ArtTiger\JWTAuth\Exceptions\PayloadException;
use ArtTiger\JWTAuth\Validators\PayloadValidator;
use Countable;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Contracts\Support\Jsonable;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use JsonSerializable;

/**
 * @implements ArrayAccess<string, mixed>
 * @implements Arrayable<string, mixed>
 */
class Payload implements ArrayAccess, Arrayable, Countable, Jsonable, JsonSerializable, Stringable
{
    private ClaimCollection $claims;

    /**
     * Build the Payload.
     */
    public function __construct(ClaimCollection $claims, PayloadValidator $validator, bool $refreshFlow = false)
    {
        $validator->setRefreshFlow($refreshFlow)->validateCollection($claims);
        $this->claims = $claims;
    }

    /**
     * Get the collection of claim instances.
     */
    public function getClaims(): ClaimCollection
    {
        return $this->claims;
    }

    /**
     * Check whether the payload matches the given key/value pairs.
     *
     * @param array<string, mixed> $values
     */
    public function matches(array $values, bool $strict = false): bool
    {
        if (empty($values)) {
            return false;
        }

        $claims = $this->getClaims();

        foreach ($values as $key => $value) {
            $claimObj = $claims->get($key);
            if (! $claims->has($key) || null === $claimObj || ! $claimObj->matches($value, $strict)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Strictly match the payload against the given values.
     *
     * @param array<string, mixed> $values
     */
    public function matchesStrict(array $values): bool
    {
        return $this->matches($values, true);
    }

    /**
     * Get one or more claim values. Returns all claims as array when $claim is null.
     */
    public function get(mixed $claim = null): mixed
    {
        $claim = value($claim);

        if ($claim !== null) {
            if (is_array($claim)) {
                return array_map($this->get(...), $claim);
            }

            if (is_string($claim) || is_int($claim)) {
                return Arr::get($this->toArray(), $claim);
            }

            return null;
        }

        return $this->toArray();
    }

    /**
     * Get the underlying Claim instance by name.
     */
    public function getInternal(string $claim): ?Claim
    {
        return $this->claims->getByClaimName($claim);
    }

    /**
     * Determine whether the payload contains the given claim instance.
     */
    public function has(Claim $claim): bool
    {
        return $this->claims->has($claim->getName());
    }

    /**
     * Determine whether the payload has a claim by key name.
     */
    public function hasKey(string $claim): bool
    {
        return $this->offsetExists($claim);
    }

    /**
     * Get the claims as a plain key/value array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return $this->claims->toPlainArray();
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
     * Get the payload as JSON.
     */
    public function toJson(mixed $options = JSON_UNESCAPED_SLASHES): string
    {
        return json_encode($this->toArray(), (int) $options | JSON_THROW_ON_ERROR);
    }

    public function __toString(): string
    {
        return $this->toJson();
    }

    public function offsetExists(mixed $key): bool
    {
        return Arr::has($this->toArray(), $key);
    }

    public function offsetGet(mixed $key): mixed
    {
        return Arr::get($this->toArray(), $key);
    }

    /**
     * @throws PayloadException
     */
    public function offsetSet(mixed $key, mixed $value): void
    {
        throw new PayloadException(message: 'The payload is immutable');
    }

    /**
     * @throws PayloadException
     */
    public function offsetUnset(mixed $key): void
    {
        throw new PayloadException(message: 'The payload is immutable');
    }

    public function count(): int
    {
        return count($this->toArray());
    }

    /**
     * Invoke the Payload as a callable function.
     */
    public function __invoke(mixed $claim = null): mixed
    {
        return $this->get($claim);
    }

    /**
     * Magically get a claim value by method name (e.g. getExpiration()).
     *
     * @param array<mixed> $parameters
     *
     * @throws BadMethodCallException
     */
    public function __call(string $method, array $parameters): mixed
    {
        if (preg_match('/get(.+)\b/i', $method, $matches)) {
            foreach ($this->claims as $claim) {
                if ($claim::class === 'ArtTiger\\JWTAuth\\Claims\\'.$matches[1]) {
                    return $claim->getValue();
                }
            }
        }

        throw new BadMethodCallException(
            message: sprintf('The claim [%s] does not exist on the payload.', Str::after($method, 'get'))
        );
    }
}
