<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Http\Middleware;

use ArtTiger\JWTAuth\Abstracts\Http\Middleware;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;

class AuthenticateAndRenew extends Middleware
{
    /**
     * @param Closure(Request): Response $next
     *
     * @throws UnauthorizedHttpException
     */
    public function handle(Request $request, Closure $next): Response
    {
        $this->authenticate($request);

        $response = $next($request);

        return $this->setAuthenticationHeader($response);
    }
}
