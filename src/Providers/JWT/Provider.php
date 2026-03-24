<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Providers\JWT;

use Illuminate\Support\Arr;
use ArtTiger\JWTAuth\Exceptions\JWTException;
use ArtTiger\JWTAuth\Exceptions\SecretMissingException;

abstract class Provider
{
    protected ?string $secret;

    /**
     * @var array<string, mixed>
     */
    protected array $keys;

    protected string $algo;

    /**
     * @param array<string, mixed> $keys
     *
     * @throws SecretMissingException
     */
    public function __construct(?string $secret, string $algo, array $keys)
    {
        if ($secret === null && (! isset($keys['public']) || ! isset($keys['private']))) {
            throw new SecretMissingException();
        }

        $this->secret = $secret;
        $this->algo = $algo;
        $this->keys = $keys;
    }

    public function setAlgo(string $algo): self
    {
        $this->algo = $algo;

        return $this;
    }

    public function getAlgo(): string
    {
        return $this->algo;
    }

    public function setSecret(?string $secret): self
    {
        $this->secret = $secret;

        return $this;
    }

    public function getSecret(): ?string
    {
        return $this->secret;
    }

    /**
     * @param array<string, mixed> $keys
     */
    public function setKeys(array $keys): self
    {
        $this->keys = $keys;

        return $this;
    }

    /**
     * @return array<string, mixed>
     */
    public function getKeys(): array
    {
        return $this->keys;
    }

    public function getPublicKey(): ?string
    {
        $value = Arr::get($this->keys, 'public');

        return is_string($value) ? $value : null;
    }

    public function getPrivateKey(): ?string
    {
        $value = Arr::get($this->keys, 'private');

        return is_string($value) ? $value : null;
    }

    public function getPassphrase(): ?string
    {
        $value = Arr::get($this->keys, 'passphrase');

        return is_string($value) ? $value : null;
    }

    protected function getSigningKey(): string
    {
        return $this->isAsymmetric() ? (string) $this->getPrivateKey() : (string) $this->getSecret();
    }

    protected function getVerificationKey(): string
    {
        return $this->isAsymmetric() ? (string) $this->getPublicKey() : (string) $this->getSecret();
    }

    /**
     * @throws JWTException
     */
    abstract protected function isAsymmetric(): bool;
}
