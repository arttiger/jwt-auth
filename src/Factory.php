<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth;

use ArtTiger\JWTAuth\Claims\Claim;
use ArtTiger\JWTAuth\Claims\Collection;
use ArtTiger\JWTAuth\Claims\Factory as ClaimFactory;
use ArtTiger\JWTAuth\Support\CustomClaims;
use ArtTiger\JWTAuth\Support\RefreshFlow;
use ArtTiger\JWTAuth\Validators\PayloadValidator;

class Factory
{
    use CustomClaims;
    use RefreshFlow;

    /**
     * The claim factory.
     */
    protected ClaimFactory $claimFactory;

    /**
     * The validator.
     */
    protected PayloadValidator $validator;

    /**
     * The default claims.
     *
     * @var string[]
     */
    protected array $defaultClaims = [
        'iss',
        'iat',
        'exp',
        'nbf',
        'jti',
    ];

    /**
     * The claims collection.
     */
    protected Collection $claims;

    /**
     * Constructor.
     *
     * @return void
     */
    public function __construct(ClaimFactory $claimFactory, PayloadValidator $validator)
    {
        $this->claimFactory = $claimFactory;
        $this->validator = $validator;
        $this->claims = new Collection();
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
    public function emptyClaims(): static
    {
        $this->claims = new Collection();

        return $this;
    }

    /**
     * Add an array of claims to the Payload.
     */
    protected function addClaims(array $claims): static
    {
        foreach ($claims as $name => $value) {
            $this->addClaim($name, $value);
        }

        return $this;
    }

    /**
     * Add a claim to the Payload.
     *
     * @param string $name
     *
     * @return $this
     */
    protected function addClaim($name, $value): static
    {
        $this->claims->put($name, $value);

        return $this;
    }

    /**
     * Build the default claims.
     *
     * @return $this
     */
    protected function buildClaims()
    {
        // remove the exp claim if it exists and the ttl is null
        if (null === $this->claimFactory->getTTL() && $key = array_search('exp', $this->defaultClaims)) {
            unset($this->defaultClaims[$key]);
        }

        // add the default claims
        foreach ($this->defaultClaims as $claim) {
            $this->addClaim($claim, $this->claimFactory->make($claim));
        }

        // add custom claims on top, allowing them to overwrite defaults
        return $this->addClaims($this->getCustomClaims());
    }

    /**
     * Build out the Claim DTO's.
     *
     * @return Collection
     */
    protected function resolveClaims()
    {
        return $this->claims->map(function ($value, $name) {
            return $value instanceof Claim ? $value : $this->claimFactory->get($name, $value);
        });
    }

    /**
     * Build and get the Claims Collection.
     *
     * @return Collection
     */
    public function buildClaimsCollection()
    {
        return $this->buildClaims()->resolveClaims();
    }

    /**
     * Get a Payload instance with a claims collection.
     *
     * @return Payload
     */
    public function withClaims(Collection $claims)
    {
        return new Payload($claims, $this->validator, $this->refreshFlow);
    }

    /**
     * Set the default claims to be added to the Payload.
     *
     * @return $this
     */
    public function setDefaultClaims(array $claims)
    {
        $this->defaultClaims = $claims;

        return $this;
    }

    /**
     * Helper to set the ttl.
     *
     * @param int|null $ttl
     *
     * @return $this
     */
    public function setTTL($ttl)
    {
        $this->claimFactory->setTTL($ttl);

        return $this;
    }

    /**
     * Helper to get the ttl.
     *
     * @return int|null
     */
    public function getTTL()
    {
        return $this->claimFactory->getTTL();
    }

    /**
     * Get the default claims.
     *
     * @return array
     */
    public function getDefaultClaims()
    {
        return $this->defaultClaims;
    }

    /**
     * Get the PayloadValidator instance.
     *
     * @return PayloadValidator
     */
    public function validator()
    {
        return $this->validator;
    }

    /**
     * Magically add a claim.
     *
     * @param string $method
     * @param array  $parameters
     *
     * @return $this
     */
    public function __call($method, $parameters)
    {
        $this->addClaim($method, $parameters[0]);

        return $this;
    }
}
