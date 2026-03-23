<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Http\Parser;

use ArtTiger\JWTAuth\Contracts\Http\Parser as ParserContract;
use ArtTiger\JWTAuth\Exceptions\TokenInvalidException;
use ArtTiger\JWTAuth\Traits\KeyTrait;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;

class Cookies implements ParserContract
{
    use KeyTrait;

    /**
     * Decrypt or not the cookie while parsing.
     */
    private bool $decrypt;

    public function __construct(bool $decrypt = true)
    {
        $this->decrypt = $decrypt;
    }

    /**
     * Try to parse the token from the request cookies.
     *
     * @throws TokenInvalidException
     */
    public function parse(Request $request): ?string
    {
        if ($this->decrypt && $request->hasCookie($this->key)) {
            try {
                $raw = $request->cookie($this->key);
                if (! is_string($raw)) {
                    return null;
                }
                $decrypted = Crypt::decrypt($raw);

                return is_string($decrypted) ? $decrypted : null;
            } catch (DecryptException $ex) {
                throw new TokenInvalidException(message: 'Token has not decrypted successfully.');
            }
        }

        $cookie = $request->cookie($this->key);

        return is_string($cookie) ? $cookie : null;
    }
}
