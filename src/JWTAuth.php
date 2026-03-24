<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth;

use ArtTiger\JWTAuth\Contracts\JWTSubject;
use ArtTiger\JWTAuth\Contracts\Providers\Auth;
use ArtTiger\JWTAuth\Exceptions\JWTException;
use ArtTiger\JWTAuth\Http\Parser\Parser;

class JWTAuth extends JWT
{
    public function __construct(Manager $manager, protected Auth $auth, Parser $parser)
    {
        parent::__construct($manager, $parser);
    }

    /**
     * @param array<string, mixed> $credentials
     */
    public function attempt(array $credentials): false|string
    {
        if (! $this->auth->byCredentials($credentials)) {
            return false;
        }

        return $this->fromUser($this->user());
    }

    public function authenticate(): JWTSubject|false
    {
        $id = $this->getPayload()->get('sub') ?? $this->getPayload()->get('id');

        if (! is_string($id) && ! is_int($id)) {
            return false;
        }

        if (! $this->auth->byId($id)) {
            return false;
        }

        return $this->user();
    }

    public function toUser(): JWTSubject|false
    {
        return $this->authenticate();
    }

    /**
     * @throws JWTException
     */
    public function user(): JWTSubject
    {
        $user = $this->auth->user();

        if ($user instanceof JWTSubject) {
            return $user;
        }

        throw new JWTException('Authenticated user does not implement JWTSubject');
    }
}
