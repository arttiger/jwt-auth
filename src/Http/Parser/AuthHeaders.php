<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Http\Parser;

use Illuminate\Http\Request;
use ArtTiger\JWTAuth\Contracts\Http\Parser as ParserContract;

class AuthHeaders implements ParserContract
{
    /**
     * The header name.
    */
    protected string $header = 'authorization';

    /**
     * The header prefix.
     */
    protected string $prefix = 'bearer';

    /**
     * Attempt to parse the token from some other possible headers.
     */
    protected function fromAltHeaders(Request $request): ?string
    {
        $value = $request->server->get('HTTP_AUTHORIZATION') ?: $request->server->get('REDIRECT_HTTP_AUTHORIZATION');

        return is_string($value) ? $value : null;
    }

    /**
     * Try to parse the token from the request header.
     */
    public function parse(Request $request): ?string
    {
        $header = $request->headers->get($this->header) ?: $this->fromAltHeaders($request);

        if ($header !== null) {
            $position = strripos($header, $this->prefix);

            if ($position !== false) {
                $header = substr($header, $position + strlen($this->prefix));
                $token = str_contains($header, ',') ? strstr($header, ',', before_needle: true) : $header;

                return $token !== false ? trim($token) : null;
            }
        }

        return null;
    }

    /**
     * Set the header name.
     */
    public function setHeaderName(string $headerName): self
    {
        $this->header = $headerName;

        return $this;
    }

    /**
     * Set the header prefix.
     */
    public function setHeaderPrefix(string $headerPrefix): self
    {
        $this->prefix = $headerPrefix;

        return $this;
    }
}
