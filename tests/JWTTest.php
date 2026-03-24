<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test;

use ArtTiger\JWTAuth\Exceptions\JWTException;
use ArtTiger\JWTAuth\Factory;
use ArtTiger\JWTAuth\Http\Parser\Parser;
use ArtTiger\JWTAuth\JWT;
use ArtTiger\JWTAuth\Manager;
use ArtTiger\JWTAuth\Payload;
use ArtTiger\JWTAuth\Test\Stubs\UserStub;
use ArtTiger\JWTAuth\Token;
use ArtTiger\JWTAuth\Validators\PayloadValidator;
use BadMethodCallException;
use Mockery;
use Mockery\MockInterface;

class JWTTest extends AbstractTestCase
{
    private MockInterface&Manager $manager;
    private MockInterface&Parser $parser;
    private JWT $jwt;

    private const string VALID_TOKEN = 'header.payload.signature';

    protected function setUp(): void
    {
        parent::setUp();

        $this->manager = Mockery::mock(Manager::class);
        $this->parser = Mockery::mock(Parser::class);

        $this->jwt = new JWT($this->manager, $this->parser);
    }

    /**
     * @param array<string, \ArtTiger\JWTAuth\Abstracts\Claim>|null $overrides
     */
    private function makePayload(?array $overrides = []): Payload
    {
        $validator = Mockery::mock(PayloadValidator::class);
        $validator->shouldReceive('setRefreshFlow')->andReturnSelf();
        $validator->shouldReceive('validateCollection')->andReturn(null);

        return new Payload($this->makeValidCollection($overrides ?? []), $validator);
    }

    private function makeToken(string $value = self::VALID_TOKEN): Token
    {
        return new Token($value);
    }

    public function testFromUserReturnTokenString(): void
    {
        $user = new UserStub();
        $payload = $this->makePayload();
        $factory = Mockery::mock(Factory::class);

        $this->manager->shouldReceive('getPayloadFactory')->andReturn($factory);
        $factory->shouldReceive('customClaims')->andReturnSelf();
        $factory->shouldReceive('make')->andReturn($payload);
        $this->manager->shouldReceive('encode')->andReturn($this->makeToken());

        $result = $this->jwt->fromUser($user);

        $this->assertSame(self::VALID_TOKEN, $result);
    }

    public function testFromSubjectIsAliasForFromUser(): void
    {
        $user = new UserStub();
        $payload = $this->makePayload();
        $factory = Mockery::mock(Factory::class);

        $this->manager->shouldReceive('getPayloadFactory')->andReturn($factory);
        $factory->shouldReceive('customClaims')->andReturnSelf();
        $factory->shouldReceive('make')->andReturn($payload);
        $this->manager->shouldReceive('encode')->andReturn($this->makeToken());

        $result = $this->jwt->fromSubject($user);

        $this->assertSame(self::VALID_TOKEN, $result);
    }

    public function testSetTokenStoresToken(): void
    {
        $result = $this->jwt->setToken(self::VALID_TOKEN);

        $this->assertSame($this->jwt, $result);
        $this->assertInstanceOf(Token::class, $this->jwt->getToken());
    }

    public function testSetTokenAcceptsTokenInstance(): void
    {
        $token = $this->makeToken();

        $this->jwt->setToken($token);

        $this->assertSame($token, $this->jwt->getToken());
    }

    public function testGetTokenReturnsNullWhenNoTokenSetAndParserReturnsNull(): void
    {
        // The JWT::$token property is declared as ?Token but not initialized.
        // getToken() checks `if ($this->token === null)` — accessing uninitialized
        // typed property raises Error in PHP 8+. We always unset to ensure null state.
        $this->jwt->unsetToken();

        $this->parser->shouldReceive('parseToken')->andReturn(null);

        $this->assertNull($this->jwt->getToken());
    }

    public function testGetTokenTriesParseTokenWhenNoneSet(): void
    {
        $this->jwt->unsetToken();

        $this->parser->shouldReceive('parseToken')->once()->andReturn(self::VALID_TOKEN);

        $token = $this->jwt->getToken();

        $this->assertInstanceOf(Token::class, $token);
        $this->assertSame(self::VALID_TOKEN, $token->get());
    }

    public function testUnsetTokenRemovesStoredToken(): void
    {
        $this->jwt->setToken(self::VALID_TOKEN);

        $result = $this->jwt->unsetToken();

        $this->assertSame($this->jwt, $result);
        $this->parser->shouldReceive('parseToken')->andReturn(null);
        $this->assertNull($this->jwt->getToken());
    }

    public function testParseTokenReadsFromParser(): void
    {
        $this->parser->shouldReceive('parseToken')->once()->andReturn(self::VALID_TOKEN);

        $result = $this->jwt->parseToken();

        $this->assertSame($this->jwt, $result);
        $this->assertInstanceOf(Token::class, $this->jwt->getToken());
    }

    public function testParseTokenThrowsWhenParserReturnsNull(): void
    {
        $this->parser->shouldReceive('parseToken')->once()->andReturn(null);

        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('The token could not be parsed from the request');

        $this->jwt->parseToken();
    }

    public function testCheckReturnsTrueForValidToken(): void
    {
        $payload = $this->makePayload();

        $this->jwt->setToken(self::VALID_TOKEN);
        $this->manager->shouldReceive('decode')->andReturn($payload);

        $result = $this->jwt->check();

        $this->assertTrue($result);
    }

    public function testCheckReturnsFalseOnException(): void
    {
        $this->jwt->setToken(self::VALID_TOKEN);
        $this->manager->shouldReceive('decode')->andThrow(new JWTException('Token expired'));

        $result = $this->jwt->check();

        $this->assertFalse($result);
    }

    public function testCheckWithGetPayloadTrueReturnsPayload(): void
    {
        $payload = $this->makePayload();

        $this->jwt->setToken(self::VALID_TOKEN);
        $this->manager->shouldReceive('decode')->andReturn($payload);

        $result = $this->jwt->check(getPayload: true);

        $this->assertInstanceOf(Payload::class, $result);
    }

    public function testGetPayloadCallsManagerDecode(): void
    {
        $payload = $this->makePayload();

        $this->jwt->setToken(self::VALID_TOKEN);
        $this->manager->shouldReceive('decode')->once()->andReturn($payload);

        $result = $this->jwt->getPayload();

        $this->assertSame($payload, $result);
    }

    public function testGetClaimReadsFromPayload(): void
    {
        // getClaim('sub') calls payload()->get('sub'). Due to the toPlainArray/map bug
        // in Claims\Collection, get() returns null for all keys. We verify the delegation
        // using a mocked Payload.
        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('get')->with('sub')->andReturn('1');

        $this->jwt->setToken(self::VALID_TOKEN);
        $this->manager->shouldReceive('decode')->andReturn($payload);

        $result = $this->jwt->getClaim('sub');

        $this->assertSame('1', $result);
    }

    public function testInvalidateCallsManagerInvalidateAndReturnsSelf(): void
    {
        $this->jwt->setToken(self::VALID_TOKEN);

        $this->manager->shouldReceive('invalidate')
            ->with(Mockery::type(Token::class), false)
            ->once()
            ->andReturn(true);

        $result = $this->jwt->invalidate();

        $this->assertSame($this->jwt, $result);
    }

    public function testRefreshCallsManagerRefreshAndReturnsTokenString(): void
    {
        $newToken = new Token('new.refreshed.token');

        $this->jwt->setToken(self::VALID_TOKEN);

        $this->manager->shouldReceive('customClaims')->andReturnSelf();
        $this->manager->shouldReceive('refresh')
            ->with(Mockery::type(Token::class), false, false)
            ->once()
            ->andReturn($newToken);

        $result = $this->jwt->refresh();

        $this->assertSame('new.refreshed.token', $result);
    }

    public function testLockSubjectFalseRemovesPrvFromClaims(): void
    {
        $user = new UserStub();

        $this->jwt->lockSubject(false);

        $factory = Mockery::mock(Factory::class);
        $this->manager->shouldReceive('getPayloadFactory')->andReturn($factory);

        // With lockSubject(false), prv claim should not be included
        $factory->shouldReceive('customClaims')
            ->withArgs(function (array $claims): bool {
                return !array_key_exists('prv', $claims);
            })
            ->andReturnSelf();

        $payload = $this->makePayload();
        $factory->shouldReceive('make')->andReturn($payload);
        $this->manager->shouldReceive('encode')->andReturn($this->makeToken());

        $this->jwt->fromUser($user);
    }

    public function testCheckSubjectModelReturnsTrueWhenNoPrvClaim(): void
    {
        // checkSubjectModel calls payload()->get('prv'); if null → returns true
        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('get')->with('prv')->andReturn(null);

        $this->jwt->setToken(self::VALID_TOKEN);
        $this->manager->shouldReceive('decode')->andReturn($payload);

        $result = $this->jwt->checkSubjectModel(UserStub::class);

        $this->assertTrue($result);
    }

    public function testCheckSubjectModelReturnsTrueForMatchingClassHash(): void
    {
        $user = new UserStub();
        $prv = sha1(get_class($user));

        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('get')->with('prv')->andReturn($prv);

        $this->jwt->setToken(self::VALID_TOKEN);
        $this->manager->shouldReceive('decode')->andReturn($payload);

        $result = $this->jwt->checkSubjectModel($user);

        $this->assertTrue($result);
    }

    public function testCheckSubjectModelReturnsFalseForWrongClass(): void
    {
        $wrongHash = sha1('Wrong\\ClassName');

        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('get')->with('prv')->andReturn($wrongHash);

        $this->jwt->setToken(self::VALID_TOKEN);
        $this->manager->shouldReceive('decode')->andReturn($payload);

        $user = new UserStub();
        $result = $this->jwt->checkSubjectModel($user);

        $this->assertFalse($result);
    }

    public function testSetRequestDelegatesToParser(): void
    {
        $request = \Illuminate\Http\Request::create('/api/test');

        $this->parser->shouldReceive('setRequest')->with($request)->once()->andReturnSelf();

        $result = $this->jwt->setRequest($request);

        $this->assertSame($this->jwt, $result);
    }

    public function testManagerReturnsManagerInstance(): void
    {
        $this->assertSame($this->manager, $this->jwt->manager());
    }

    public function testParserReturnsParserInstance(): void
    {
        $this->assertSame($this->parser, $this->jwt->parser());
    }

    public function testFactoryReturnsFactoryFromManager(): void
    {
        $factory = Mockery::mock(Factory::class);
        $this->manager->shouldReceive('getPayloadFactory')->once()->andReturn($factory);

        $this->assertSame($factory, $this->jwt->factory());
    }

    public function testBlacklistReturnsBlacklistFromManager(): void
    {
        $blacklist = Mockery::mock(\ArtTiger\JWTAuth\Blacklist::class);
        $this->manager->shouldReceive('getBlacklist')->once()->andReturn($blacklist);

        $this->assertSame($blacklist, $this->jwt->blacklist());
    }

    public function testMagicCallDelegatesToManager(): void
    {
        $this->manager->shouldReceive('setBlacklistEnabled')->with(false)->once()->andReturn($this->manager);

        $this->jwt->setBlacklistEnabled(false);
    }

    public function testMagicCallThrowsBadMethodCallExceptionForUnknownMethod(): void
    {
        $this->expectException(BadMethodCallException::class);
        $this->expectExceptionMessage('nonExistentMethod');

        $this->jwt->__call('nonExistentMethod', []);
    }
}
