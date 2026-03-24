<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Providers\JWT;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use ArtTiger\JWTAuth\Algorithms\Algorithm;
use ArtTiger\JWTAuth\Algorithms\AlgorithmRegistry;
use ArtTiger\JWTAuth\Contracts\Providers\JWT;
use ArtTiger\JWTAuth\Exceptions\JWTException;
use ArtTiger\JWTAuth\Exceptions\TokenInvalidException;

class Lcobucci extends Provider implements JWT
{
    protected ?Builder $builder = null;

    protected Configuration $config;

    protected Signer $signer;

    protected Algorithm $algorithm;

    /**
     * @param array<string, mixed> $keys
     *
     * @throws JWTException when the algorithm is unsupported or the key material is invalid.
     */
    public function __construct(
        #[\SensitiveParameter] ?string $secret,
        string $algo,
        #[\SensitiveParameter] array $keys,
        ?Configuration $config = null,
    ) {
        parent::__construct($secret, $algo, $keys);

        $this->algorithm = AlgorithmRegistry::find($algo);
        $this->algorithm->validateKeyMaterial($secret, $keys);

        $this->generateConfig($config);
    }

    private function generateConfig(?Configuration $config = null): void
    {
        $this->signer = $this->getSigner();

        if ($config !== null) {
            $this->config = $config;
        } elseif ($this->isAsymmetric()) {
            $this->config = Configuration::forAsymmetricSigner(
                $this->signer,
                $this->getSigningInMemoryKey(),
                $this->getVerificationInMemoryKey()
            );
        } else {
            $this->config = Configuration::forSymmetricSigner(
                $this->signer,
                $this->getSigningInMemoryKey()
            );
        }

        if (count($this->config->validationConstraints()) === 0) {
            $this->config->setValidationConstraints(
                new SignedWith($this->signer, $this->getVerificationInMemoryKey())
            );
        }
    }

    public function setSecret(#[\SensitiveParameter] ?string $secret): static
    {
        $this->secret = $secret;
        $this->algorithm->validateKeyMaterial($secret, $this->keys);
        $this->generateConfig();

        return $this;
    }

    public function getConfig(): Configuration
    {
        return $this->config;
    }

    /**
     * @param array<string, mixed> $payload
     *
     * @throws JWTException
     */
    public function encode(array $payload): string
    {
        $this->builder = $this->config->builder();

        try {
            foreach ($payload as $key => $value) {
                $this->builder = $this->addClaim((string) $key, $value);
            }

            return $this->builder->getToken($this->config->signer(), $this->config->signingKey())->toString();
        } catch (\Exception $e) {
            throw new JWTException('Could not create token: '.$e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * @return array<string, mixed>
     *
     * @throws JWTException
     */
    public function decode(string $token): array
    {
        if ($token === '') {
            throw new TokenInvalidException('Token cannot be empty.');
        }

        try {
            $jwt = $this->config->parser()->parse($token);
        } catch (\Exception $e) {
            throw new TokenInvalidException('Could not decode token: '.$e->getMessage(), $e->getCode(), $e);
        }

        if (! $this->config->validator()->validate($jwt, ...$this->config->validationConstraints())) {
            throw new TokenInvalidException('Token Signature could not be verified.');
        }

        if (! ($jwt instanceof UnencryptedToken)) {
            throw new TokenInvalidException('Token is not an unencrypted JWT.');
        }

        $result = [];
        foreach ($jwt->claims()->all() as $claimKey => $claim) {
            if (! is_string($claimKey)) {
                continue;
            }
            if ($claim instanceof \DateTimeImmutable) {
                $result[$claimKey] = $claim->getTimestamp();
            } elseif (is_object($claim) && method_exists($claim, 'getValue')) {
                $result[$claimKey] = $claim->getValue();
            } else {
                $result[$claimKey] = $claim;
            }
        }

        return $result;
    }

    protected function addClaim(string $key, mixed $value): Builder
    {
        if ($this->builder === null) {
            $this->builder = $this->config->builder();
        }

        if ($key === '') {
            throw new JWTException('Claim key cannot be empty');
        }

        switch ($key) {
            case RegisteredClaims::ID:
                $strVal = is_string($value) ? $value : '';
                if ($strVal === '') {
                    throw new JWTException('JTI claim must be a non-empty string');
                }

                return $this->builder->identifiedBy($strVal);

            case RegisteredClaims::EXPIRATION_TIME:
                $ts = is_numeric($value) ? (int) $value : 0;

                return $this->builder->expiresAt(
                    \DateTimeImmutable::createFromFormat('U', (string) $ts) ?: new \DateTimeImmutable()
                );

            case RegisteredClaims::NOT_BEFORE:
                $ts = is_numeric($value) ? (int) $value : 0;

                return $this->builder->canOnlyBeUsedAfter(
                    \DateTimeImmutable::createFromFormat('U', (string) $ts) ?: new \DateTimeImmutable()
                );

            case RegisteredClaims::ISSUED_AT:
                $ts = is_numeric($value) ? (int) $value : 0;

                return $this->builder->issuedAt(
                    \DateTimeImmutable::createFromFormat('U', (string) $ts) ?: new \DateTimeImmutable()
                );

            case RegisteredClaims::ISSUER:
                $strVal = is_string($value) ? $value : '';
                if ($strVal === '') {
                    throw new JWTException('ISS claim must be a non-empty string');
                }

                return $this->builder->issuedBy($strVal);

            case RegisteredClaims::AUDIENCE:
                $audiences = [];
                foreach ((is_array($value) ? $value : [$value]) as $aud) {
                    $audStr = is_string($aud) ? $aud : '';
                    if ($audStr === '') {
                        throw new JWTException('Each AUD value must be a non-empty string');
                    }
                    $audiences[] = $audStr;
                }
                if (empty($audiences)) {
                    throw new JWTException('AUD claim must have at least one audience');
                }

                return $this->builder->permittedFor(...$audiences);

            case RegisteredClaims::SUBJECT:
                $strVal = is_string($value) ? $value : '';
                if ($strVal === '') {
                    throw new JWTException('SUB claim must be a non-empty string');
                }

                return $this->builder->relatedTo($strVal);

            default:
                return $this->builder->withClaim($key, $value);
        }
    }

    protected function getSigner(): Signer
    {
        $class = $this->algorithm->signerClass();

        return new $class();
    }

    protected function isAsymmetric(): bool
    {
        return $this->algorithm->isAsymmetric();
    }

    protected function getSigningKey(): string
    {
        return $this->isAsymmetric()
            ? (string) $this->getPrivateKey()
            : (string) $this->getSecret();
    }

    protected function getVerificationKey(): string
    {
        return $this->isAsymmetric()
            ? (string) $this->getPublicKey()
            : (string) $this->getSecret();
    }

    protected function getSigningInMemoryKey(): InMemory
    {
        $key = $this->getSigningKey();
        if ($key === '') {
            throw new JWTException('Signing key cannot be empty');
        }

        return $this->isAsymmetric()
            ? InMemory::plainText($key, $this->getPassphrase() ?? '')
            : InMemory::plainText($key);
    }

    protected function getVerificationInMemoryKey(): InMemory
    {
        $key = $this->getVerificationKey();
        if ($key === '') {
            throw new JWTException('Verification key cannot be empty');
        }

        return InMemory::plainText($key);
    }
}
