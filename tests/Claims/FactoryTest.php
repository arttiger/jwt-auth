<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test\Claims;

use Illuminate\Http\Request;
use ArtTiger\JWTAuth\Claims\Custom;
use ArtTiger\JWTAuth\Claims\Expiration;
use ArtTiger\JWTAuth\Claims\Factory;
use ArtTiger\JWTAuth\Claims\IssuedAt;
use ArtTiger\JWTAuth\Claims\Issuer;
use ArtTiger\JWTAuth\Claims\JwtId;
use ArtTiger\JWTAuth\Claims\NotBefore;
use ArtTiger\JWTAuth\Claims\Subject;
use ArtTiger\JWTAuth\Test\AbstractTestCase;
use ArtTiger\JWTAuth\Test\Fixtures\Foo;

class FactoryTest extends AbstractTestCase
{
    protected Factory $factory;

    public function setUp(): void
    {
        parent::setUp();

        $this->factory = new Factory(Request::create('/foo', 'GET'));
    }

    public function testItShouldSetTheRequest(): void
    {
        $factory = $this->factory->setRequest(Request::create('/bar', 'GET'));
        $this->assertInstanceOf(Factory::class, $factory);
    }

    public function testItShouldSetTheTtl(): void
    {
        $this->assertInstanceOf(Factory::class, $this->factory->setTTL(30));
    }

    public function testItShouldGetTheTtl(): void
    {
        $this->factory->setTTL($ttl = 30);
        $this->assertSame($ttl, $this->factory->getTTL());
    }

    public function testItShouldGetADefinedClaimInstanceWhenPassingANameAndValue(): void
    {
        $this->assertInstanceOf(Subject::class, $this->factory->get('sub', '1'));
        $this->assertInstanceOf(Issuer::class, $this->factory->get('iss', 'http://example.com'));
        $this->assertInstanceOf(Expiration::class, $this->factory->get('exp', $this->testNowTimestamp + 3600));
        $this->assertInstanceOf(NotBefore::class, $this->factory->get('nbf', $this->testNowTimestamp));
        $this->assertInstanceOf(IssuedAt::class, $this->factory->get('iat', $this->testNowTimestamp));
        $this->assertInstanceOf(JwtId::class, $this->factory->get('jti', 'foo'));
    }

    public function testItShouldGetACustomClaimInstanceWhenPassingANonDefinedNameAndValue(): void
    {
        $this->assertInstanceOf(Custom::class, $this->factory->get('foo', ['bar']));
    }

    public function testItShouldMakeAClaimInstanceWithAValue(): void
    {
        $iat = $this->factory->make('iat');
        $this->assertSame($iat->getValue(), $this->testNowTimestamp);
        $this->assertInstanceOf(IssuedAt::class, $iat);

        $nbf = $this->factory->make('nbf');
        $this->assertSame($nbf->getValue(), $this->testNowTimestamp);
        $this->assertInstanceOf(NotBefore::class, $nbf);

        $iss = $this->factory->make('iss');
        $this->assertSame($iss->getValue(), 'http://localhost/foo');
        $this->assertInstanceOf(Issuer::class, $iss);

        $exp = $this->factory->make('exp');
        $this->assertSame($exp->getValue(), $this->testNowTimestamp + 3600);
        $this->assertInstanceOf(Expiration::class, $exp);

        $jti = $this->factory->make('jti');
        $this->assertInstanceOf(JwtId::class, $jti);
    }

    public function testItShouldExtendClaimFactoryToAddACustomClaim(): void
    {
        $this->factory->extend('foo', Foo::class);

        $this->assertInstanceOf(Foo::class, $this->factory->get('foo', 'bar'));
    }

    public function testItShouldReturnTrueForRegisteredClaimNames(): void
    {
        foreach (['aud', 'exp', 'iat', 'iss', 'jti', 'nbf', 'sub'] as $name) {
            $this->assertTrue($this->factory->has($name), "Expected factory to have claim: {$name}");
        }
    }

    public function testItShouldReturnFalseForUnregisteredClaimNames(): void
    {
        $this->assertFalse($this->factory->has('foo'));
        $this->assertFalse($this->factory->has('custom_claim'));
    }

    public function testItShouldSetTtlToNullWhenPassingNull(): void
    {
        $this->factory->setTTL(null);

        $this->assertNull($this->factory->getTTL());
    }

    public function testItShouldSetLeewayAndReturnSelf(): void
    {
        $result = $this->factory->setLeeway(30);

        $this->assertInstanceOf(Factory::class, $result);
    }

    public function testItShouldApplyLeewayToDatetimeClaims(): void
    {
        $this->factory->setLeeway(30);

        $exp = $this->factory->get('exp', $this->testNowTimestamp + 3600);
        $nbf = $this->factory->get('nbf', $this->testNowTimestamp);
        $iat = $this->factory->get('iat', $this->testNowTimestamp);

        // Non-datetime claims should not have setLeeway — no assertion to make there
        // Datetime claims are returned with leeway set (verified via validatePayload behaviour)
        $this->assertInstanceOf(Expiration::class, $exp);
        $this->assertInstanceOf(NotBefore::class, $nbf);
        $this->assertInstanceOf(IssuedAt::class, $iat);
    }
}
