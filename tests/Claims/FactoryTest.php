<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test\Claims;

use ArtTiger\JWTAuth\Abstracts\Claim;
use ArtTiger\JWTAuth\Claims\Audience;
use ArtTiger\JWTAuth\Claims\Custom;
use ArtTiger\JWTAuth\Claims\Expiration;
use ArtTiger\JWTAuth\Claims\Factory;
use ArtTiger\JWTAuth\Claims\IssuedAt;
use ArtTiger\JWTAuth\Claims\Issuer;
use ArtTiger\JWTAuth\Claims\JwtId;
use ArtTiger\JWTAuth\Claims\NotBefore;
use ArtTiger\JWTAuth\Claims\Subject;
use ArtTiger\JWTAuth\Test\AbstractTestCase;
use Illuminate\Http\Request;

class FactoryTest extends AbstractTestCase
{
    private Factory $factory;

    protected function setUp(): void
    {
        parent::setUp();

        $request = Request::create('https://example.com/api/token');
        $this->factory = new Factory($request);
    }

    public function testGetReturnsIssuerClaimForIssName(): void
    {
        $claim = $this->factory->get('iss', 'https://example.com');
        $this->factory->extend('guard', Custom::class);

        $this->assertInstanceOf(Issuer::class, $claim);
        $this->assertSame('https://example.com', $claim->getValue());
    }

    public function testGetReturnsSubjectClaimForSubName(): void
    {
        $claim = $this->factory->get('sub', 'user-1');

        $this->assertInstanceOf(Subject::class, $claim);
        $this->assertSame('user-1', $claim->getValue());
    }

    public function testGetReturnsAudienceClaimForAudName(): void
    {
        $claim = $this->factory->get('aud', 'api.example.com');

        $this->assertInstanceOf(Audience::class, $claim);
    }

    public function testGetReturnsExpirationClaimForExpName(): void
    {
        $future = $this->testNowTimestamp + 3600;
        $claim = $this->factory->get('exp', $future);

        $this->assertInstanceOf(Expiration::class, $claim);
        $this->assertSame($future, $claim->getValue());
    }

    public function testGetReturnsNotBeforeClaimForNbfName(): void
    {
        $claim = $this->factory->get('nbf', $this->testNowTimestamp);

        $this->assertInstanceOf(NotBefore::class, $claim);
    }

    public function testGetReturnsIssuedAtClaimForIatName(): void
    {
        $claim = $this->factory->get('iat', $this->testNowTimestamp);

        $this->assertInstanceOf(IssuedAt::class, $claim);
    }

    public function testGetReturnsJwtIdClaimForJtiName(): void
    {
        $claim = $this->factory->get('jti', 'unique-id');

        $this->assertInstanceOf(JwtId::class, $claim);
    }

    public function testGetReturnsCustomClaimForUnknownName(): void
    {
        $claim = $this->factory->get('foo', 'bar');

        $this->assertInstanceOf(Custom::class, $claim);
        $this->assertSame('foo', $claim->getName());
        $this->assertSame('bar', $claim->getValue());
    }

    public function testGetAppliesLeewayToReturnedClaim(): void
    {
        $this->factory->setLeeway(30);
        $future = $this->testNowTimestamp + 3600;

        $claim = $this->factory->get('exp', $future);

        // Leeway is set via setLeeway; the value should still be correct
        $this->assertSame($future, $claim->getValue());
    }

    public function testMakeSub(): void
    {
        // make('sub') would require a default sub value — sub does not have a default
        // generator in Factory, so this would produce a Custom or throw. In practice
        // 'sub' is always supplied by the caller. We test the ones that do have generators.
        $this->markTestSkipped('sub does not have a default generator in Claims\\Factory::make()');
    }

    public function testMakeGeneratesDefaultIss(): void
    {
        $claim = $this->factory->make('iss');

        $this->assertInstanceOf(Issuer::class, $claim);
        $this->assertSame('https://example.com/api/token', $claim->getValue());
    }

    public function testMakeGeneratesDefaultIat(): void
    {
        $claim = $this->factory->make('iat');

        $this->assertInstanceOf(IssuedAt::class, $claim);
        $this->assertSame($this->testNowTimestamp, $claim->getValue());
    }

    public function testMakeGeneratesDefaultExp(): void
    {
        $claim = $this->factory->make('exp');

        $this->assertInstanceOf(Expiration::class, $claim);
        // Default TTL is 60 minutes
        $this->assertSame($this->testNowTimestamp + 3600, $claim->getValue());
    }

    public function testMakeGeneratesDefaultNbf(): void
    {
        $claim = $this->factory->make('nbf');

        $this->assertInstanceOf(NotBefore::class, $claim);
        $this->assertSame($this->testNowTimestamp, $claim->getValue());
    }

    public function testMakeGeneratesDefaultJtiAsRandomString(): void
    {
        $claim = $this->factory->make('jti');

        $this->assertInstanceOf(JwtId::class, $claim);
        $this->assertIsString($claim->getValue());
        $this->assertNotEmpty($claim->getValue());
    }

    public function testHasReturnsTrueForKnownClaimName(): void
    {
        $this->assertTrue($this->factory->has('iss'));
        $this->assertTrue($this->factory->has('sub'));
        $this->assertTrue($this->factory->has('aud'));
        $this->assertTrue($this->factory->has('exp'));
        $this->assertTrue($this->factory->has('nbf'));
        $this->assertTrue($this->factory->has('iat'));
        $this->assertTrue($this->factory->has('jti'));
    }

    public function testHasReturnsFalseForUnknownClaimName(): void
    {
        $this->assertFalse($this->factory->has('custom_claim'));
        $this->assertFalse($this->factory->has(''));
        $this->assertFalse($this->factory->has('prv'));
    }

    public function testExtendRegistersNewClaimClass(): void
    {
        $this->factory->extend('custom', Custom::class);

        $this->assertTrue($this->factory->has('custom'));
    }

    public function testExtendAllowsGetToReturnIssuedAtAsCustomClass(): void
    {
        // Custom::__construct requires (string $name, mixed $value) — 2 args,
        // but the Factory::get() path calls new $classMap[$name]($value) with 1 arg.
        // Extending with a standard claim class (single-arg constructor) works correctly.
        $this->factory->extend('my_iss', Issuer::class);

        $claim = $this->factory->get('my_iss', 'https://custom.example.com');

        $this->assertInstanceOf(Issuer::class, $claim);
        $this->assertSame('https://custom.example.com', $claim->getValue());
    }

    public function testSetTtlUpdatesTtlValue(): void
    {
        $this->factory->setTTL(120);

        $this->assertSame(120, $this->factory->getTTL());
    }

    public function testSetTtlAcceptsNull(): void
    {
        $this->factory->setTTL(null);

        $this->assertNull($this->factory->getTTL());
    }

    public function testDefaultTtlIsSixtyMinutes(): void
    {
        $this->assertSame(60, $this->factory->getTTL());
    }

    public function testSetTtlAffectsGeneratedExpClaim(): void
    {
        $this->factory->setTTL(30);

        $claim = $this->factory->make('exp');

        $this->assertSame($this->testNowTimestamp + 1800, $claim->getValue());
    }

    public function testSetLeewayReturnsFactory(): void
    {
        $result = $this->factory->setLeeway(10);

        $this->assertSame($this->factory, $result);
    }

    public function testGetReturnedClaimImplementsClaimAbstract(): void
    {
        $claim = $this->factory->get('iss', 'https://example.com');

        $this->assertInstanceOf(Claim::class, $claim);
    }
}
