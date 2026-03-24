<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Providers\JWT;

use Exception;
use InvalidArgumentException;
use ReflectionClass;
use ReflectionException;
use Namshi\JOSE\JWS;
use Namshi\JOSE\Signer\OpenSSL\PublicKey;
use ArtTiger\JWTAuth\Contracts\Providers\JWT;
use ArtTiger\JWTAuth\Exceptions\JWTException;
use ArtTiger\JWTAuth\Exceptions\TokenInvalidException;

class Namshi extends Provider implements JWT
{
    /**
     * @param array<string, mixed> $keys
     */
    public function __construct(protected JWS $jws, ?string $secret, string $algo, array $keys)
    {
        parent::__construct($secret, $algo, $keys);
    }

    /**
     * @param array<string, mixed> $payload
     *
     * @throws JWTException
     */
    public function encode(array $payload): string
    {
        try {
            $this->jws->setPayload($payload);
            $this->jws->sign($this->getSigningKey(), $this->getPassphrase());

            return (string) $this->jws->getTokenString();
        } catch (Exception $exception) {
            throw new JWTException('Could not create token: '.$exception->getMessage(), $exception->getCode(), $exception);
        }
    }

    /**
     * @return array<string, mixed>
     *
     * @throws JWTException
     */
    public function decode(string $token): array
    {
        try {
            $jws = $this->jws->load($token, false);
        } catch (InvalidArgumentException $invalidArgumentException) {
            throw new TokenInvalidException('Could not decode token: '.$invalidArgumentException->getMessage(), $invalidArgumentException->getCode(), $invalidArgumentException);
        }

        if (! $jws->verify($this->getVerificationKey(), $this->getAlgo()->value)) {
            throw new TokenInvalidException('Token Signature could not be verified.');
        }

        $raw = $jws->getPayload();

        if (! is_array($raw)) {
            return [];
        }

        $result = [];
        foreach ($raw as $k => $v) {
            if (is_string($k)) {
                $result[$k] = $v;
            }
        }

        return $result;
    }

    protected function isAsymmetric(): bool
    {
        $className = sprintf('Namshi\\JOSE\\Signer\\OpenSSL\\%s', $this->getAlgo()->value);

        if (! class_exists($className)) {
            throw new JWTException('The given algorithm could not be found');
        }

        try {
            return (new ReflectionClass($className))->isSubclassOf(PublicKey::class);
        } catch (ReflectionException $reflectionException) {
            throw new JWTException('The given algorithm could not be found', $reflectionException->getCode(), $reflectionException);
        }
    }
}
