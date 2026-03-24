<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test\Http\Parser;

use ArtTiger\JWTAuth\Http\Parser\AuthHeaders;
use ArtTiger\JWTAuth\Test\AbstractTestCase;
use Illuminate\Http\Request;

class AuthHeadersTest extends AbstractTestCase
{
    private AuthHeaders $parser;

    protected function setUp(): void
    {
        parent::setUp();

        $this->parser = new AuthHeaders();
    }

    public function testParsesStandardBearerAuthorizationHeader(): void
    {
        $request = Request::create('/api/test', 'GET', [], [], [], [
            'HTTP_AUTHORIZATION' => 'Bearer header.payload.signature',
        ]);

        $token = $this->parser->parse($request);

        $this->assertSame('header.payload.signature', $token);
    }

    public function testParsesUppercaseBearerPrefix(): void
    {
        $request = Request::create('/api/test', 'GET', [], [], [], [
            'HTTP_AUTHORIZATION' => 'BEARER header.payload.signature',
        ]);

        $token = $this->parser->parse($request);

        $this->assertSame('header.payload.signature', $token);
    }

    public function testParsesCaseInsensitiveBearerPrefix(): void
    {
        $request = Request::create('/api/test', 'GET', [], [], [], [
            'HTTP_AUTHORIZATION' => 'Bearer header.payload.signature',
        ]);

        $token = $this->parser->parse($request);

        $this->assertSame('header.payload.signature', $token);
    }

    public function testReturnsNullWhenNoAuthorizationHeader(): void
    {
        $request = Request::create('/api/test', 'GET');

        $token = $this->parser->parse($request);

        $this->assertNull($token);
    }

    public function testReturnsNullWhenAuthorizationHeaderHasWrongPrefix(): void
    {
        $request = Request::create('/api/test', 'GET', [], [], [], [
            'HTTP_AUTHORIZATION' => 'Basic dXNlcjpwYXNz',
        ]);

        $token = $this->parser->parse($request);

        $this->assertNull($token);
    }

    public function testUsesCustomHeaderName(): void
    {
        $request = Request::create('/api/test', 'GET', [], [], [], [
            'HTTP_X_AUTH_TOKEN' => 'Bearer header.payload.signature',
        ]);

        $this->parser->setHeaderName('x-auth-token');

        $token = $this->parser->parse($request);

        $this->assertSame('header.payload.signature', $token);
    }

    public function testUsesCustomPrefix(): void
    {
        $request = Request::create('/api/test', 'GET', [], [], [], [
            'HTTP_AUTHORIZATION' => 'Token header.payload.signature',
        ]);

        $this->parser->setHeaderPrefix('token');

        $token = $this->parser->parse($request);

        $this->assertSame('header.payload.signature', $token);
    }

    public function testExtractsFirstPartBeforeCommaWhenTokenContainsComma(): void
    {
        // When the Authorization header contains a comma (e.g. multi-value),
        // only the portion before the comma is used.
        $request = Request::create('/api/test', 'GET', [], [], [], [
            'HTTP_AUTHORIZATION' => 'Bearer header.payload.signature, extra',
        ]);

        $token = $this->parser->parse($request);

        $this->assertSame('header.payload.signature', $token);
    }

    public function testFallsBackToHttpAuthorizationServerVar(): void
    {
        // Simulate environments where the header is passed via server variable
        // (e.g. Apache mod_rewrite scenarios).
        $request = Request::create('/api/test', 'GET');
        $request->server->set('HTTP_AUTHORIZATION', 'Bearer header.payload.signature');

        $token = $this->parser->parse($request);

        $this->assertSame('header.payload.signature', $token);
    }

    public function testFallsBackToRedirectHttpAuthorizationServerVar(): void
    {
        $request = Request::create('/api/test', 'GET');
        $request->server->set('REDIRECT_HTTP_AUTHORIZATION', 'Bearer header.payload.signature');

        $token = $this->parser->parse($request);

        $this->assertSame('header.payload.signature', $token);
    }

    public function testTrimsWhitespaceAroundToken(): void
    {
        $request = Request::create('/api/test', 'GET', [], [], [], [
            'HTTP_AUTHORIZATION' => 'Bearer   header.payload.signature  ',
        ]);

        $token = $this->parser->parse($request);

        $this->assertSame('header.payload.signature', $token);
    }

    public function testSetHeaderNameReturnsSelf(): void
    {
        $result = $this->parser->setHeaderName('x-custom');

        $this->assertSame($this->parser, $result);
    }

    public function testSetHeaderPrefixReturnsSelf(): void
    {
        $result = $this->parser->setHeaderPrefix('token');

        $this->assertSame($this->parser, $result);
    }
}
