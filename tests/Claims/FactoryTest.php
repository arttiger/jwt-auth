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
        $this->assertInstanceOf(Subject::class, $this->factory->get('sub', 1));
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
}
