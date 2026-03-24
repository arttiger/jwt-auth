<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Claims;

use ArtTiger\JWTAuth\Abstracts\Claim;
use ArtTiger\JWTAuth\Enums\ClaimName;
use ArtTiger\JWTAuth\Exceptions\InvalidClaimException;
use ArtTiger\JWTAuth\Support\Utils;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

class Factory
{
    protected ?int $ttl = 60;

    protected int $leeway = 0;

    /**
     * @var array<non-empty-string, class-string<Claim>>
     */
    private array $classMap = [
        ClaimName::Issuer->value     => Issuer::class,
        ClaimName::Subject->value    => Subject::class,
        ClaimName::Audience->value   => Audience::class,
        ClaimName::Expiration->value => Expiration::class,
        ClaimName::NotBefore->value  => NotBefore::class,
        ClaimName::IssuedAt->value   => IssuedAt::class,
        ClaimName::JwtId->value      => JwtId::class,
    ];

    public function __construct(protected Request $request)
    {
    }

    /**
     * Get a Claim instance by name and value.
     *
     * @throws InvalidClaimException
     */
    public function get(string $name, mixed $value): Claim
    {
        if ($this->has($name)) {
            $claim = new $this->classMap[$name]($value);

            return $claim->setLeeway($this->leeway);
        }

        return new Custom($name, $value);
    }

    /**
     * Check whether the claim name is registered.
     */
    public function has(string $name): bool
    {
        return array_key_exists($name, $this->classMap);
    }

    /**
     * Generate the initial value and return the Claim instance.
     *
     * @throws InvalidClaimException
     */
    public function make(string $name): Claim
    {
        return $this->get($name, $this->$name());
    }

    public function iss(): string
    {
        return $this->request->url();
    }

    public function iat(): int
    {
        return Utils::now()->getTimestamp();
    }

    public function exp(): int
    {
        return Utils::now()->addMinutes($this->ttl ?? 60)->getTimestamp();
    }

    public function nbf(): int
    {
        return Utils::now()->getTimestamp();
    }

    public function jti(): string
    {
        return Str::random();
    }

    /**
     * Add a new claim mapping.
     *
     * @param non-empty-string       $name
     * @param class-string<Claim>    $classPath
     */
    public function extend(string $name, string $classPath): self
    {
        $this->classMap[$name] = $classPath;

        return $this;
    }

    public function setRequest(Request $request): self
    {
        $this->request = $request;

        return $this;
    }

    public function setTTL(?int $ttl): self
    {
        $this->ttl = $ttl;

        return $this;
    }

    public function getTTL(): ?int
    {
        return $this->ttl;
    }

    public function setLeeway(int $leeway): self
    {
        $this->leeway = $leeway;

        return $this;
    }
}
