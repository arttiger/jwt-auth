<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Claims;

use Illuminate\Support\Collection as IlluminateCollection;
use Illuminate\Support\Str;

class Collection extends IlluminateCollection
{
    /**
     * Create a new collection.
     *
     * @return void
     */
    public function __construct($items = [])
    {
        parent::__construct($this->getArrayableItems($items));
    }

    /**
     * Get a Claim instance by it's unique name.
     */
    public function getByClaimName(string $name, ?callable $callback = null, $default = null): Claim
    {
        return $this->filter(function (Claim $claim) use ($name) {
            return $claim->getName() === $name;
        })->first($callback, $default);
    }

    /**
     * Validate each claim under a given context.
     */
    public function validate(string $context = 'payload'): static
    {
        $args = func_get_args();
        array_shift($args);

        $this->each(function ($claim) use ($context, $args) {
            call_user_func_array(
                [$claim, 'validate'.Str::ucfirst($context)],
                $args
            );
        });

        return $this;
    }

    /**
     * Determine if the Collection contains all the given keys.
     */
    public function hasAllClaims($claims): bool
    {
        if (!count($claims)) {
            return false;
        }

        foreach ($claims as $claim) {
            if (!$this->has($claim)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Get the claims as a key/val array.
     *
     * @return array
     */
    public function toPlainArray(): array
    {
        return $this->map(function (Claim $claim) {
            return $claim->getValue();
        })->toArray();
    }

    protected function getArrayableItems($items)
    {
        return $this->sanitizeClaims($items);
    }

    /**
     * Ensure that the given claims array is keyed by the claim name.
     *
     * @return array
     */
    private function sanitizeClaims($items)
    {
        $claims = [];
        foreach ($items as $key => $value) {
            if (!is_string($key) && $value instanceof Claim) {
                $key = $value->getName();
            }

            $claims[$key] = $value;
        }

        return $claims;
    }
}
