<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test\Http\Parser;

use ArtTiger\JWTAuth\Http\Parser\QueryString;
use ArtTiger\JWTAuth\Test\AbstractTestCase;
use Illuminate\Http\Request;

class QueryStringTest extends AbstractTestCase
{
    private QueryString $parser;

    protected function setUp(): void
    {
        parent::setUp();

        $this->parser = new QueryString();
    }

    public function testParsesDefaultTokenQueryParameter(): void
    {
        $request = Request::create('/api/test?token=header.payload.signature');

        $token = $this->parser->parse($request);

        $this->assertSame('header.payload.signature', $token);
    }

    public function testReturnsNullWhenNoTokenQueryParameter(): void
    {
        $request = Request::create('/api/test');

        $token = $this->parser->parse($request);

        $this->assertNull($token);
    }

    public function testReturnsEmptyStringWhenTokenParameterIsEmpty(): void
    {
        // QueryString::parse checks is_string($value) — an empty string IS a string,
        // so it returns '' rather than null.
        $request = Request::create('/api/test?token=');

        $token = $this->parser->parse($request);

        $this->assertSame('', $token);
    }

    public function testUsesCustomKeyName(): void
    {
        $request = Request::create('/api/test?jwt=header.payload.signature');

        $this->parser->setKey('jwt');
        $token = $this->parser->parse($request);

        $this->assertSame('header.payload.signature', $token);
    }

    public function testReturnsNullWhenCustomKeyNotPresent(): void
    {
        $request = Request::create('/api/test?token=header.payload.signature');

        // Key is 'jwt' but query has 'token'
        $this->parser->setKey('jwt');
        $token = $this->parser->parse($request);

        $this->assertNull($token);
    }

    public function testGetKeyReturnsDefaultTokenKey(): void
    {
        $this->assertSame('token', $this->parser->getKey());
    }

    public function testSetKeyReturnsSelf(): void
    {
        $result = $this->parser->setKey('jwt');

        $this->assertSame($this->parser, $result);
    }

    public function testGetKeyReturnsUpdatedKey(): void
    {
        $this->parser->setKey('api_token');

        $this->assertSame('api_token', $this->parser->getKey());
    }

    public function testParsesTokenWithSpecialBase64UrlCharacters(): void
    {
        $token = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc-def_xyz';
        $request = Request::create('/api/test?token=' . urlencode($token));

        $parsed = $this->parser->parse($request);

        $this->assertSame($token, $parsed);
    }
}
