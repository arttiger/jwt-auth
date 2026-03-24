<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth;

use ArtTiger\JWTAuth\Contracts\Providers\JWT;
use ArtTiger\JWTAuth\Exceptions\JWTException;
use ArtTiger\JWTAuth\Exceptions\TokenBlacklistedException;
use ArtTiger\JWTAuth\Support\CustomClaims;
use ArtTiger\JWTAuth\Support\RefreshFlow;
use ArtTiger\JWTAuth\Support\Utils;

class Manager
{
    use CustomClaims;
    use RefreshFlow;

    /**
     * The blacklist flag.
     */
    protected bool $blacklistEnabled = true;

    /**
     * The refresh iat flag.
     */
    protected bool $refreshIat = false;

    /**
     * the persistent claims.
     *
     * @var string[]
     */
    protected array $persistentClaims = [];

    /**
     * The blacklist exception flag.
     */
    protected bool $showBlackListException = true;

    /**
     * Constructor.
     *
     * @return void
     */
    public function __construct(
        protected JWT $provider,
        protected Blacklist $blacklist,
        protected Factory $payloadFactory,
    ) {
    }

    /**
     * Encode a Payload and return the Token.
     */
    public function encode(Payload $payload): Token
    {
        $token = $this->provider->encode($payload->toArray());

        return new Token($token);
    }

    /**
     * Decode a Token and return the Payload.
     *
     * @throws TokenBlacklistedException
     */
    public function decode(Token $token, bool $checkBlacklist = true): Payload
    {
        $payloadArray = $this->provider->decode($token->get());

        $payload = $this->payloadFactory
            ->setRefreshFlow($this->refreshFlow)
            ->customClaims($payloadArray)
            ->make();

        if (
            $checkBlacklist
            && $this->blacklistEnabled
            && $this->getBlackListExceptionEnabled()
            && $this->blacklist->has($payload)
        ) {
            throw new TokenBlacklistedException(message: 'The token has been blacklisted');
        }

        return $payload;
    }

    /**
     * Refresh a Token and return a new Token.
     */
    public function refresh(Token $token, bool $forceForever = false, bool $resetClaims = false): Token
    {
        $this->setRefreshFlow();

        $claims = $this->buildRefreshClaims($this->decode($token));

        if ($this->blacklistEnabled) {
            // Invalidate old token
            $this->invalidate($token, $forceForever);
        }

        // Return the new token
        return $this->encode(
            $this->payloadFactory->customClaims($claims)->make($resetClaims)
        );
    }

    /**
     * Invalidate a Token by adding it to the blacklist.
     *
     * @throws JWTException
     */
    public function invalidate(Token $token, bool $forceForever = false): bool
    {
        if (! $this->blacklistEnabled) {
            throw new JWTException(message: 'You must have the blacklist enabled to invalidate a token.');
        }

        $decoded = $this->decode($token, checkBlacklist: false);

        return $forceForever
            ? $this->blacklist->addForever($decoded)
            : $this->blacklist->add($decoded);
    }

    /**
     * Build the claims to go into the refreshed token.
     *
     * @return array<string, mixed>
     */
    protected function buildRefreshClaims(Payload $payload): array
    {
        // Get the claims to be persisted from the payload
        $persistentClaims = collect($payload->toArray())
            ->only($this->persistentClaims)
            ->toArray();

        // persist the relevant claims
        return array_merge(
            $this->customClaims,
            $persistentClaims,
            [
                'sub' => $payload['sub'],
                'iat' => $this->refreshIat ? Utils::now()->timestamp : $payload['iat'],
            ]
        );
    }

    /**
     * Get the Payload Factory instance.
     */
    public function getPayloadFactory(): Factory
    {
        return $this->payloadFactory;
    }

    /**
     * Get the JWTProvider instance.
     */
    public function getJWTProvider(): JWT
    {
        return $this->provider;
    }

    /**
     * Get the Blacklist instance.
     */
    public function getBlacklist(): Blacklist
    {
        return $this->blacklist;
    }

    /**
     * Set whether the blacklist is enabled.
     */
    public function setBlacklistEnabled(bool $enabled): self
    {
        $this->blacklistEnabled = $enabled;

        return $this;
    }

    /**
     * Configuration to set up if show the TokenBlacklistedException
     * can be throwable or not.
     */
    public function setBlackListExceptionEnabled(bool $showBlackListException = true): self
    {
        $this->showBlackListException = $showBlackListException;

        return $this;
    }

    /**
     * Get if the blacklist instance is enabled.
     */
    public function getBlackListExceptionEnabled(): bool
    {
        return $this->showBlackListException;
    }

    /**
     * Set the claims to be persisted when refreshing a token.
     */
    /**
     * @param string[] $claims
     */
    public function setPersistentClaims(array $claims): self
    {
        $this->persistentClaims = $claims;

        return $this;
    }

    /**
     * Set whether the refresh iat is enabled.
     */
    public function setRefreshIat(bool $refreshIat): self
    {
        $this->refreshIat = $refreshIat;

        return $this;
    }
}
