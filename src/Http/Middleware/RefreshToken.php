<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Http\Middleware;

use ArtTiger\JWTAuth\Abstracts\Http\Middleware;
use ArtTiger\JWTAuth\Exceptions\JWTException;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;

class RefreshToken extends Middleware
{
    /**
     * @param Closure(Request): Response $next
     *
     * @throws UnauthorizedHttpException
     */
    public function handle(Request $request, Closure $next): Response
    {
        $this->checkForToken($request);

        try {
            $token = $this->auth->parseToken()->refresh();
        } catch (JWTException $jwtException) {
            throw new UnauthorizedHttpException(
                'jwt-auth',
                message: $jwtException->getMessage(),
                previous: $jwtException,
                code: $jwtException->getCode(),
            );
        }

        $response = $next($request);

        return $this->setAuthenticationHeader($response, $token);
    }
}
