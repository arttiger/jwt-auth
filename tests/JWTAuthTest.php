<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test;

use ArtTiger\JWTAuth\Contracts\JWTSubject;
use ArtTiger\JWTAuth\Contracts\Providers\Auth;
use ArtTiger\JWTAuth\Exceptions\JWTException;
use ArtTiger\JWTAuth\Factory;
use ArtTiger\JWTAuth\Http\Parser\Parser;
use ArtTiger\JWTAuth\JWTAuth;
use ArtTiger\JWTAuth\Manager;
use ArtTiger\JWTAuth\Payload;
use ArtTiger\JWTAuth\Test\Stubs\UserStub;
use ArtTiger\JWTAuth\Token;
use ArtTiger\JWTAuth\Validators\PayloadValidator;
use Mockery;

class JWTAuthTest extends AbstractTestCase
{
    private Manager $manager;
    private Auth $auth;
    private Parser $parser;
    private JWTAuth $jwtAuth;

    private const VALID_TOKEN = 'header.payload.signature';

    protected function setUp(): void
    {
        parent::setUp();

        $this->manager = Mockery::mock(Manager::class);
        $this->auth = Mockery::mock(Auth::class);
        $this->parser = Mockery::mock(Parser::class);

        $this->jwtAuth = new JWTAuth($this->manager, $this->auth, $this->parser);
    }

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

    private function setupFromUserMocks(string $tokenString = self::VALID_TOKEN): void
    {
        $factory = Mockery::mock(Factory::class);
        $this->manager->shouldReceive('getPayloadFactory')->andReturn($factory);
        $factory->shouldReceive('customClaims')->andReturnSelf();
        $factory->shouldReceive('make')->andReturn($this->makePayload());
        $this->manager->shouldReceive('encode')->andReturn(new Token($tokenString));
    }

    public function testAttemptWithValidCredentialsReturnsTokenString(): void
    {
        $credentials = ['email' => 'test@example.com', 'password' => 'secret'];
        $user = new UserStub();

        $this->auth->shouldReceive('byCredentials')->with($credentials)->once()->andReturn(true);
        $this->auth->shouldReceive('user')->andReturn($user);

        $this->setupFromUserMocks();

        $result = $this->jwtAuth->attempt($credentials);

        $this->assertIsString($result);
        $this->assertSame(self::VALID_TOKEN, $result);
    }

    public function testAttemptWithInvalidCredentialsReturnsFalse(): void
    {
        $credentials = ['email' => 'test@example.com', 'password' => 'wrong'];

        $this->auth->shouldReceive('byCredentials')->with($credentials)->once()->andReturn(false);

        $result = $this->jwtAuth->attempt($credentials);

        $this->assertFalse($result);
    }

    public function testAuthenticateDecodesPayloadGetsSubCallsByIdAndReturnsUser(): void
    {
        // Use a mocked Payload so get('sub') returns the expected value.
        // Due to the toPlainArray/map bug, real Payload::get() always returns null.
        $user = new UserStub();
        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('get')->with('sub')->andReturn('1');

        $this->jwtAuth->setToken(self::VALID_TOKEN);
        $this->manager->shouldReceive('decode')->andReturn($payload);
        $this->auth->shouldReceive('byId')->with('1')->once()->andReturn(true);
        $this->auth->shouldReceive('user')->andReturn($user);

        $result = $this->jwtAuth->authenticate();

        $this->assertInstanceOf(JWTSubject::class, $result);
        $this->assertSame($user, $result);
    }

    public function testAuthenticateReturnsFalseWhenByIdFails(): void
    {
        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('get')->with('sub')->andReturn('1');

        $this->jwtAuth->setToken(self::VALID_TOKEN);
        $this->manager->shouldReceive('decode')->andReturn($payload);
        $this->auth->shouldReceive('byId')->andReturn(false);

        $result = $this->jwtAuth->authenticate();

        $this->assertFalse($result);
    }

    public function testAuthenticateReturnsFalseWhenSubIsNotStringOrInt(): void
    {
        // JWTAuth::authenticate() tries get('sub') ?? get('id').
        // When both return null, is_string/is_int both fail → returns false.
        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('get')->with('sub')->andReturn(null);
        $payload->shouldReceive('get')->with('id')->andReturn(null);

        $this->jwtAuth->setToken(self::VALID_TOKEN);
        $this->manager->shouldReceive('decode')->andReturn($payload);

        $result = $this->jwtAuth->authenticate();

        $this->assertFalse($result);
    }

    public function testUserReturnsJwtSubjectInstance(): void
    {
        $user = new UserStub();

        $this->auth->shouldReceive('user')->once()->andReturn($user);

        $result = $this->jwtAuth->user();

        $this->assertInstanceOf(JWTSubject::class, $result);
        $this->assertSame($user, $result);
    }

    public function testUserThrowsJwtExceptionWhenAuthUserIsNotJwtSubject(): void
    {
        // auth()->user() returns a plain object that does NOT implement JWTSubject
        $plainObject = new \stdClass();

        $this->auth->shouldReceive('user')->once()->andReturn($plainObject);

        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('Authenticated user does not implement JWTSubject');

        $this->jwtAuth->user();
    }

    public function testUserThrowsJwtExceptionWhenAuthUserIsNull(): void
    {
        $this->auth->shouldReceive('user')->once()->andReturn(null);

        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('Authenticated user does not implement JWTSubject');

        $this->jwtAuth->user();
    }

    public function testToUserIsAliasForAuthenticate(): void
    {
        $user = new UserStub();
        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('get')->with('sub')->andReturn('1');

        $this->jwtAuth->setToken(self::VALID_TOKEN);
        $this->manager->shouldReceive('decode')->andReturn($payload);
        $this->auth->shouldReceive('byId')->andReturn(true);
        $this->auth->shouldReceive('user')->andReturn($user);

        $result = $this->jwtAuth->toUser();

        $this->assertSame($user, $result);
    }

    public function testAuthenticateUsesSubClaimForByIdCall(): void
    {
        $user = new UserStub();
        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('get')->with('sub')->andReturn('1');

        $this->jwtAuth->setToken(self::VALID_TOKEN);
        $this->manager->shouldReceive('decode')->andReturn($payload);

        // Verify byId is called with the sub value '1'
        $this->auth->shouldReceive('byId')->with('1')->once()->andReturn(true);
        $this->auth->shouldReceive('user')->andReturn($user);

        $this->jwtAuth->authenticate();
    }

    public function testAttemptCallsFromUserAfterSuccessfulCredentials(): void
    {
        $credentials = ['email' => 'admin@example.com', 'password' => 'pass'];
        $user = new UserStub();

        $this->auth->shouldReceive('byCredentials')->andReturn(true);
        $this->auth->shouldReceive('user')->andReturn($user);

        $factory = Mockery::mock(Factory::class);
        $this->manager->shouldReceive('getPayloadFactory')->andReturn($factory);
        $factory->shouldReceive('customClaims')->andReturnSelf();
        $factory->shouldReceive('make')->andReturn($this->makePayload());
        $this->manager->shouldReceive('encode')
            ->once()
            ->andReturn($this->makeToken());

        $result = $this->jwtAuth->attempt($credentials);

        $this->assertSame(self::VALID_TOKEN, $result);
    }
}
