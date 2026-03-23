<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Http\Middleware;

use ArtTiger\JWTAuth\Abstracts\Http\Middleware;
use Closure;
use Exception;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class Check extends Middleware
{
    /**
     * @param Closure(Request): Response $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        if ($this->auth->parser()->setRequest($request)->hasToken()) {
            try {
                $this->auth->parseToken()->authenticate();
            } catch (Exception) {
                // continue without authentication
            }
        }

        return $next($request);
    }
}
