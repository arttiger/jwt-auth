<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth;

use ArtTiger\JWTAuth\Abstracts\Claim;
use ArtTiger\JWTAuth\Collections\ClaimCollection;
use ArtTiger\JWTAuth\Claims\Factory as ClaimFactory;
use ArtTiger\JWTAuth\Enums\ClaimName;
use ArtTiger\JWTAuth\Support\CustomClaims;
use ArtTiger\JWTAuth\Support\RefreshFlow;
use ArtTiger\JWTAuth\Validators\PayloadValidator;

class Factory
{
    use CustomClaims;
    use RefreshFlow;

    /**
     * The default claims.
     *
     * @var string[]
     */
    protected array $defaultClaims = [
        ClaimName::Issuer->value,
        ClaimName::IssuedAt->value,
        ClaimName::Expiration->value,
        ClaimName::NotBefore->value,
        ClaimName::JwtId->value,
    ];

    /**
     * Intermediate staging collection (holds mixed values before resolving to Claims).
     */
    protected ClaimCollection $claims;

    public function __construct(protected ClaimFactory $claimFactory, protected PayloadValidator $validator)
    {
        $this->claims = new ClaimCollection();
    }

    /**
     * Create the Payload instance.
     */
    public function make(bool $resetClaims = false): Payload
    {
        if ($resetClaims) {
            $this->emptyClaims();
        }

        return $this->withClaims($this->buildClaimsCollection());
    }

    /**
     * Empty the claims collection.
     */
    public function emptyClaims(): self
    {
        $this->claims = new ClaimCollection();

        return $this;
    }

    /**
     * Add an array of claims to the Payload.
     *
     * @param array<string, mixed> $claims
     */
    protected function addClaims(array $claims): self
    {
        foreach ($claims as $name => $value) {
            $this->addClaim($name, $value);
        }

        return $this;
    }

    /**
     * Add a claim to the Payload.
     */
    protected function addClaim(string $name, mixed $value): self
    {
        $this->claims->put($name, $value);

        return $this;
    }

    /**
     * Build the default claims.
     */
    protected function buildClaims(): self
    {
        // Remove exp claim when TTL is null (non-expiring tokens)
        if ($this->claimFactory->getTTL() === null) {
            $expKey = array_search(ClaimName::Expiration->value, $this->defaultClaims, true);

            if ($expKey !== false) {
                unset($this->defaultClaims[$expKey]);
            }
        }

        // add the default claims
        foreach ($this->defaultClaims as $claim) {
            $this->addClaim($claim, $this->claimFactory->make($claim));
        }

        // add custom claims on top, allowing them to overwrite defaults
        return $this->addClaims($this->getCustomClaims());
    }

    protected function resolveClaims(): ClaimCollection
    {
        $items = [];

        foreach ($this->claims as $name => $value) {
            $items[$name] = $value instanceof Claim
                ? $value
                : $this->claimFactory->get($name, $value);
        }

        return new ClaimCollection($items);
    }

    public function buildClaimsCollection(): ClaimCollection
    {
        return $this->buildClaims()->resolveClaims();
    }

    public function withClaims(ClaimCollection $claims): Payload
    {
        return new Payload($claims, $this->validator, $this->refreshFlow);
    }

    /**
     * @param string[] $claims
     */
    public function setDefaultClaims(array $claims): self
    {
        $this->defaultClaims = $claims;

        return $this;
    }

    public function setTTL(?int $ttl): self
    {
        $this->claimFactory->setTTL($ttl);

        return $this;
    }

    public function getTTL(): ?int
    {
        return $this->claimFactory->getTTL();
    }

    /**
     * @return string[]
     */
    public function getDefaultClaims(): array
    {
        return $this->defaultClaims;
    }

    /**
     * Get the PayloadValidator instance.
     */
    public function validator(): PayloadValidator
    {
        return $this->validator;
    }

    /**
     * Magically add a claim.
     *
     * @param array<mixed> $parameters
     */
    public function __call(string $method, array $parameters): self
    {
        $this->addClaim($method, $parameters[0]);

        return $this;
    }
}
