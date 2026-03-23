<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test\Claims;

use ArtTiger\JWTAuth\Claims\Collection;
use ArtTiger\JWTAuth\Claims\Expiration;
use ArtTiger\JWTAuth\Claims\IssuedAt;
use ArtTiger\JWTAuth\Claims\Issuer;
use ArtTiger\JWTAuth\Claims\JwtId;
use ArtTiger\JWTAuth\Claims\NotBefore;
use ArtTiger\JWTAuth\Claims\Subject;
use ArtTiger\JWTAuth\Test\AbstractTestCase;

class CollectionTest extends AbstractTestCase
{
    public function testItShouldSanitizeTheClaimsToAssociativeArray(): void
    {
        $collection = $this->getCollection();

        $this->assertSame(['sub', 'iss', 'exp', 'nbf', 'iat', 'jti'], array_keys($collection->toArray()));
    }

    private function getCollection(): Collection
    {
        $claims = [
            new Subject('1'),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ];

        return new Collection($claims);
    }

    public function testItShouldDetermineIfACollectionContainsAllTheGivenClaims(): void
    {
        $collection = $this->getCollection();

        $this->assertFalse($collection->hasAllClaims(['sub', 'iss', 'exp', 'nbf', 'iat', 'jti', 'abc']));
        $this->assertFalse($collection->hasAllClaims(['foo', 'bar']));
        $this->assertFalse($collection->hasAllClaims([]));

        $this->assertTrue($collection->hasAllClaims(['sub', 'iss']));
        $this->assertTrue($collection->hasAllClaims(['sub', 'iss', 'exp', 'nbf', 'iat', 'jti']));
    }

    public function testItShouldGetAClaimInstanceByName(): void
    {
        $collection = $this->getCollection();

        $this->assertInstanceOf(Expiration::class, $collection->getByClaimName('exp'));
        $this->assertInstanceOf(Subject::class, $collection->getByClaimName('sub'));
    }

    public function testItShouldReturnNullWhenClaimNotFoundByName(): void
    {
        $collection = $this->getCollection();

        $this->assertNull($collection->getByClaimName('nonexistent'));
    }

    public function testItShouldGetAPlainArray(): void
    {
        $collection = $this->getCollection();
        $plain = $collection->toPlainArray();

        $this->assertSame('1', $plain['sub']);
        $this->assertSame('http://example.com', $plain['iss']);
        $this->assertSame('foo', $plain['jti']);
        $this->assertSame($this->testNowTimestamp + 3600, $plain['exp']);
    }

    public function testItShouldAcceptStringKeyedClaims(): void
    {
        $claims = [
            'sub' => new Subject('1'),
            'iss' => new Issuer('http://example.com'),
        ];

        $collection = new Collection($claims);
        $this->assertSame(['sub', 'iss'], array_keys($collection->toArray()));
    }

    public function testItShouldValidatePayloadAndReturnSelf(): void
    {
        $collection = $this->getCollection();

        $result = $collection->validate('payload');

        $this->assertSame($collection, $result);
    }
}
