<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Abstracts\Http;

use ArtTiger\JWTAuth\Exceptions\JWTException;
use ArtTiger\JWTAuth\JWTAuth;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;

abstract class Middleware
{
    public function __construct(protected JWTAuth $auth)
    {
    }

    /**
     * @throws UnauthorizedHttpException
     */
    public function checkForToken(Request $request): void
    {
        if (! $this->auth->parser()->setRequest($request)->hasToken()) {
            throw new UnauthorizedHttpException('jwt-auth', message: 'Token not provided');
        }
    }

    /**
     * @throws UnauthorizedHttpException
     */
    public function authenticate(Request $request): void
    {
        $this->checkForToken($request);

        try {
            if (! $this->auth->parseToken()->authenticate()) {
                throw new UnauthorizedHttpException('jwt-auth', message: 'User not found');
            }
        } catch (JWTException $jwtException) {
            throw new UnauthorizedHttpException(
                'jwt-auth',
                message: $jwtException->getMessage(),
                previous: $jwtException,
                code: $jwtException->getCode(),
            );
        }
    }

    protected function setAuthenticationHeader(Response $response, ?string $token = null): Response
    {
        $token = $token ?: $this->auth->refresh();
        $response->headers->set('Authorization', 'Bearer '.$token);

        return $response;
    }
}
