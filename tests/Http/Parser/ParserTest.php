<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test\Http\Parser;

use ArtTiger\JWTAuth\Contracts\Http\Parser as ParserContract;
use ArtTiger\JWTAuth\Http\Parser\AuthHeaders;
use ArtTiger\JWTAuth\Http\Parser\Parser;
use ArtTiger\JWTAuth\Http\Parser\QueryString;
use ArtTiger\JWTAuth\Test\AbstractTestCase;
use Illuminate\Http\Request;
use Mockery;

class ParserTest extends AbstractTestCase
{
    private Request $request;

    protected function setUp(): void
    {
        parent::setUp();

        $this->request = Request::create('/api/test');
    }

    public function testParseTokenReturnsTokenFromFirstMatchingParser(): void
    {
        $mockParser = Mockery::mock(ParserContract::class);
        $mockParser->shouldReceive('parse')->once()->andReturn('header.payload.signature');

        $parser = new Parser($this->request, [$mockParser]);

        $token = $parser->parseToken();

        $this->assertSame('header.payload.signature', $token);
    }

    public function testParseTokenReturnsNullWhenNoParserMatches(): void
    {
        $mockParser1 = Mockery::mock(ParserContract::class);
        $mockParser1->shouldReceive('parse')->once()->andReturn(null);

        $mockParser2 = Mockery::mock(ParserContract::class);
        $mockParser2->shouldReceive('parse')->once()->andReturn(null);

        $parser = new Parser($this->request, [$mockParser1, $mockParser2]);

        $this->assertNull($parser->parseToken());
    }

    public function testParseTokenReturnsNullWithEmptyChain(): void
    {
        $parser = new Parser($this->request, []);

        $this->assertNull($parser->parseToken());
    }

    public function testParseTokenStopsAtFirstSuccessfulParser(): void
    {
        $firstParser = Mockery::mock(ParserContract::class);
        $firstParser->shouldReceive('parse')->once()->andReturn('first.token.found');

        // Second parser should NOT be called
        $secondParser = Mockery::mock(ParserContract::class);
        $secondParser->shouldNotReceive('parse');

        $parser = new Parser($this->request, [$firstParser, $secondParser]);

        $token = $parser->parseToken();

        $this->assertSame('first.token.found', $token);
    }

    public function testParseTokenSkipsNullResultsAndReturnsFirstNonNull(): void
    {
        $firstParser = Mockery::mock(ParserContract::class);
        $firstParser->shouldReceive('parse')->once()->andReturn(null);

        $secondParser = Mockery::mock(ParserContract::class);
        $secondParser->shouldReceive('parse')->once()->andReturn('second.token.found');

        $parser = new Parser($this->request, [$firstParser, $secondParser]);

        $token = $parser->parseToken();

        $this->assertSame('second.token.found', $token);
    }

    public function testHasTokenReturnsTrueWhenTokenFound(): void
    {
        $mockParser = Mockery::mock(ParserContract::class);
        $mockParser->shouldReceive('parse')->andReturn('header.payload.signature');

        $parser = new Parser($this->request, [$mockParser]);

        $this->assertTrue($parser->hasToken());
    }

    public function testHasTokenReturnsFalseWhenNoTokenFound(): void
    {
        $mockParser = Mockery::mock(ParserContract::class);
        $mockParser->shouldReceive('parse')->andReturn(null);

        $parser = new Parser($this->request, [$mockParser]);

        $this->assertFalse($parser->hasToken());
    }

    public function testAddParserAppendsToChain(): void
    {
        $initial = Mockery::mock(ParserContract::class);
        $added = Mockery::mock(ParserContract::class);

        $parser = new Parser($this->request, [$initial]);
        $parser->addParser($added);

        $chain = $parser->getChain();

        $this->assertCount(2, $chain);
        $this->assertSame($initial, $chain[0]);
        $this->assertSame($added, $chain[1]);
    }

    public function testAddParserAcceptsArray(): void
    {
        $p1 = Mockery::mock(ParserContract::class);
        $p2 = Mockery::mock(ParserContract::class);

        $parser = new Parser($this->request);
        $parser->addParser([$p1, $p2]);

        $this->assertCount(2, $parser->getChain());
    }

    public function testSetChainReplacesExistingChain(): void
    {
        $initial = Mockery::mock(ParserContract::class);
        $replacement = Mockery::mock(ParserContract::class);

        $parser = new Parser($this->request, [$initial]);
        $parser->setChain([$replacement]);

        $chain = $parser->getChain();

        $this->assertCount(1, $chain);
        $this->assertSame($replacement, $chain[0]);
    }

    public function testSetRequestUpdatesTheRequest(): void
    {
        $mockParser = Mockery::mock(ParserContract::class);
        $newRequest = Request::create('/api/new?token=header.payload.signature');

        $parser = new Parser($this->request, [$mockParser]);

        $mockParser->shouldReceive('parse')->with($newRequest)->andReturn('header.payload.signature');

        $parser->setRequest($newRequest);
        $token = $parser->parseToken();

        $this->assertSame('header.payload.signature', $token);
    }

    public function testWorksWithRealAuthHeadersParser(): void
    {
        $request = Request::create('/api/test', 'GET', [], [], [], [
            'HTTP_AUTHORIZATION' => 'Bearer header.payload.signature',
        ]);

        $parser = new Parser($request, [new AuthHeaders()]);

        $this->assertSame('header.payload.signature', $parser->parseToken());
    }

    public function testWorksWithRealQueryStringParser(): void
    {
        $request = Request::create('/api/test?token=header.payload.signature');

        $parser = new Parser($request, [new QueryString()]);

        $this->assertSame('header.payload.signature', $parser->parseToken());
    }

    public function testGetChainReturnsAllParsers(): void
    {
        $p1 = Mockery::mock(ParserContract::class);
        $p2 = Mockery::mock(ParserContract::class);

        $parser = new Parser($this->request, [$p1, $p2]);

        $chain = $parser->getChain();

        $this->assertCount(2, $chain);
    }
}
