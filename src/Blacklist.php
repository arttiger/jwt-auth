<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth;

use ArtTiger\JWTAuth\Contracts\Providers\Storage;
use ArtTiger\JWTAuth\Support\Utils;

class Blacklist
{
    /** The storage. */
    protected Storage $storage;

    /** Grace period when a token is blacklisted, in seconds. */
    protected int $gracePeriod = 0;

    /** Number of minutes from issue date in which a JWT can be refreshed. */
    protected int $refreshTTL = 20160;

    /** The unique key held within the blacklist (defaults to jti claim). */
    protected string $key = 'jti';

    public function __construct(Storage $storage)
    {
        $this->storage = $storage;
    }

    /**
     * Add the token (jti claim) to the blacklist.
     */
    public function add(Payload $payload): bool
    {
        // No exp claim → add indefinitely
        if (! $payload->hasKey('exp')) {
            return $this->addForever($payload);
        }

        $blacklistKey = $this->getKey($payload);

        if (! empty($this->storage->get($blacklistKey))) {
            return true;
        }

        $this->storage->add(
            $blacklistKey,
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
        $expValue = $payload->get('exp');
        $iatValue = $payload->get('iat');

        if (! is_int($expValue) || ! is_int($iatValue)) {
            return $this->refreshTTL + 1;
        }

        $exp = Utils::timestamp($expValue);
        $iat = Utils::timestamp($iatValue);

        $intermediate = $exp->max($iat->addMinutes($this->refreshTTL))->addMinute();

        // Handle Carbon 2 vs Carbon 3 diff API
        if (method_exists($intermediate, 'diffInRealMinutes')) {
            $diff = $intermediate->diffInRealMinutes(null, true);
        } else {
            $diff = $intermediate->diffInMinutes(null, true);
        }

        return (int) round(is_float($diff) || is_int($diff) ? $diff : 0);
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
        $value = $this->storage->get($this->getKey($payload));

        // exit early if the token was blacklisted forever,
        if ($value === 'forever') {
            return true;
        }

        if (! is_array($value) || ! isset($value['valid_until'])) {
            return false;
        }

        $validUntil = $value['valid_until'];

        return is_int($validUntil) && ! Utils::isFuture($validUntil);
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
    public function setGracePeriod(int $gracePeriod): self
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
    public function getKey(Payload $payload): string
    {
        $value = $payload($this->key);

        return is_string($value) ? $value : '';
    }

    /**
     * Set the unique key held within the blacklist.
     */
    public function setKey(string $key): self
    {
        $this->key = $key;

        return $this;
    }

    /**
     * Set the refresh time limit.
     */
    public function setRefreshTTL(int $ttl): self
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
