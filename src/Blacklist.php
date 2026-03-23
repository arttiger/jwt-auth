<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth;

use ArtTiger\JWTAuth\Contracts\Providers\Storage;
use ArtTiger\JWTAuth\Support\Utils;

class Blacklist
{
    /**
     * The storage.
     */
    protected Storage $storage;

    /**
     * The grace period when a token is blacklisted. In seconds.
     */
    protected int $gracePeriod = 0;

    /**
     * Number of minutes from issue date in which a JWT can be refreshed.
     */
    protected int $refreshTTL = 20160;

    /**
     * The unique key held within the blacklist.
     */
    protected string $key = 'jti';

    /**
     * Constructor.
     *
     * @return void
     */
    public function __construct(Storage $storage)
    {
        $this->storage = $storage;
    }

    /**
     * Add the token (jti claim) to the blacklist.
     */
    public function add(Payload $payload): bool
    {
        // if there is no exp claim then add the jwt to
        // the blacklist indefinitely
        if (!$payload->hasKey('exp')) {
            return $this->addForever($payload);
        }

        // if we have already added this token to the blacklist
        if (! empty($this->storage->get($this->getKey($payload)))) {
            return true;
        }

        $this->storage->add(
            $this->getKey($payload),
            ['valid_until' => $this->getGraceTimestamp()],
            $this->getMinutesUntilExpired($payload)
        );

        return true;
    }

    /**
     * Get the number of minutes until the token expiry.
     */
    protected function getMinutesUntilExpired(Payload $payload): int
    {
        $exp = Utils::timestamp($payload['exp']);
        $iat = Utils::timestamp($payload['iat']);

        // get the latter of the two expiration dates and find
        // the number of minutes until the expiration date,
        // plus 1 minute to avoid overlap
        $intermediateResult = $exp->max($iat->addMinutes($this->refreshTTL))->addMinute();

        // Handle Carbon 2 vs 3 deprecation of "Real" diff functions, see https://github.com/PHP-Open-Source-Saver/jwt-auth/issues/260
        if (method_exists($intermediateResult, 'diffInRealMinutes')) {
            return (int) round($intermediateResult->diffInRealMinutes(null, true));
        }

        return (int) round($intermediateResult->diffInMinutes(null, true));
    }

    /**
     * Add the token (jti claim) to the blacklist indefinitely.
     */
    public function addForever(Payload $payload): bool
    {
        $this->storage->forever($this->getKey($payload), 'forever');

        return true;
    }

    /**
     * Determine whether the token has been blacklisted.
     */
    public function has(Payload $payload): bool
    {
        $val = $this->storage->get($this->getKey($payload));

        // exit early if the token was blacklisted forever,
        if ('forever' === $val) {
            return true;
        }

        // check whether the expiry + grace has past
        return !empty($val) && !Utils::isFuture($val['valid_until']);
    }

    /**
     * Remove the token (jti claim) from the blacklist.
     */
    public function remove(Payload $payload): bool
    {
        return $this->storage->destroy($this->getKey($payload));
    }

    /**
     * Remove all tokens from the blacklist.
     */
    public function clear(): bool
    {
        $this->storage->flush();

        return true;
    }

    /**
     * Get the timestamp when the blacklist comes into effect
     * This defaults to immediate (0 seconds).
     */
    protected function getGraceTimestamp(): int
    {
        return Utils::now()->addSeconds($this->gracePeriod)->getTimestamp();
    }

    /**
     * Set the grace period.
     */
    public function setGracePeriod(int $gracePeriod): static
    {
        $this->gracePeriod = $gracePeriod;

        return $this;
    }

    /**
     * Get the grace period.
     */
    public function getGracePeriod(): int
    {
        return $this->gracePeriod;
    }

    /**
     * Get the unique key held within the blacklist.
     */
    public function getKey(Payload $payload)
    {
        return $payload($this->key);
    }

    /**
     * Set the unique key held within the blacklist.
     *
     * @param string $key
     *
     * @return $this
     */
    public function setKey(string $key): static
    {
        $this->key = value($key);

        return $this;
    }

    /**
     * Set the refresh time limit.
     */
    public function setRefreshTTL(int $ttl): static
    {
        $this->refreshTTL = $ttl;

        return $this;
    }

    /**
     * Get the refresh time limit.
     */
    public function getRefreshTTL(): int
    {
        return $this->refreshTTL;
    }
}
