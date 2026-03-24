<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Collections;

use ArtTiger\JWTAuth\Abstracts\Claim;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;

/**
 * @extends Collection<array-key, Claim|non-empty-string>
 */
class ClaimCollection extends Collection
{
    /**
     * @param array<array-key, Claim|non-empty-string> $items
     */
    public function __construct(array $items = [])
    {
        parent::__construct($this->getArrayableItems($items));
    }

    /**
     * Get a Claim instance by its unique name.
     */
    public function getByClaimName(string $name): ?Claim
    {
        foreach ($this->items as $claim) {
            if ($claim->getName() === $name) {
                return $claim;
            }
        }

        return null;
    }

    /**
     * Validate each claim under a given context ('payload' or 'refresh').
     */
    public function validate(string $context = 'payload'): self
    {
        $args = func_get_args();
        array_shift($args);

        $this->each(function (Claim $claim) use ($context, $args): void {
            $method = 'validate'.Str::ucfirst($context);
            if (method_exists($claim, $method)) {
                $claim->$method(...$args);
            }
        });

        return $this;
    }

    /**
     * Determine if the collection contains all the given claim keys.
     *
     * @param string[] $claims
     */
    public function hasAllClaims(array $claims): bool
    {
        if (count($claims) === 0) {
            return false;
        }

        foreach ($claims as $claim) {
            if (! $this->has($claim)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Get the claims as a plain key/value array.
     *
     * @return array<string, mixed>
     */
    public function toPlainArray(): array
    {
        return $this->map(fn (Claim $claim): mixed => $claim->getValue())->toArray();
    }

    /**
     * @param mixed $items
     * @return array<string, Claim>
     */
    protected function getArrayableItems($items): array
    {
        return $this->sanitizeClaims($items);
    }

    /**
     * Ensure that the claims array is keyed by the claim name.
     *
     * @param mixed $items
     * @return array<string, Claim>
     */
    private function sanitizeClaims(mixed $items): array
    {
        if (! is_iterable($items)) {
            return [];
        }

        $claims = [];

        foreach ($items as $key => $value) {
            if ($value instanceof Claim) {
                $claimKey = is_string($key) ? $key : $value->getName();
                $claims[$claimKey] = $value;
            }
        }

        return $claims;
    }
}
