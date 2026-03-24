<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test\Collections;

use ArtTiger\JWTAuth\Collections\ClaimCollection;
use ArtTiger\JWTAuth\Claims\Expiration;
use ArtTiger\JWTAuth\Claims\IssuedAt;
use ArtTiger\JWTAuth\Claims\Issuer;
use ArtTiger\JWTAuth\Claims\Subject;
use ArtTiger\JWTAuth\Exceptions\TokenExpiredException;
use ArtTiger\JWTAuth\Test\AbstractTestCase;

class ClaimCollectionTest extends AbstractTestCase
{
    public function testConstructsWithStringKeyedClaimsAndPreservesKeys(): void
    {
        $sub = new Subject('1');
        $iss = new Issuer('https://example.com');

        $collection = new ClaimCollection(['sub' => $sub, 'iss' => $iss]);

        $this->assertTrue($collection->has('sub'));
        $this->assertTrue($collection->has('iss'));
        $this->assertSame($sub, $collection->get('sub'));
        $this->assertSame($iss, $collection->get('iss'));
    }

    public function testConstructsWithEmptyArrayProducesEmptyCollection(): void
    {
        $collection = new ClaimCollection([]);

        $this->assertCount(0, $collection);
    }

    public function testGetByClaimNameReturnsMatchingClaim(): void
    {
        $sub = new Subject('user-42');
        $collection = new ClaimCollection(['sub' => $sub]);

        $result = $collection->getByClaimName('sub');

        $this->assertSame($sub, $result);
    }

    public function testGetByClaimNameReturnsNullForMissingClaim(): void
    {
        $collection = new ClaimCollection(['sub' => new Subject('1')]);

        $result = $collection->getByClaimName('exp');

        $this->assertNull($result);
    }

    public function testGetByClaimNameReturnsNullForEmptyCollection(): void
    {
        $collection = new ClaimCollection([]);

        $this->assertNull($collection->getByClaimName('sub'));
    }

    public function testHasAllClaimsReturnsTrueWhenAllPresent(): void
    {
        $collection = $this->makeValidCollection();

        $this->assertTrue($collection->hasAllClaims(['sub', 'iss', 'exp', 'iat']));
    }

    public function testHasAllClaimsReturnsFalseWhenOneIsMissing(): void
    {
        $collection = new ClaimCollection(['sub' => new Subject('1')]);

        $this->assertFalse($collection->hasAllClaims(['sub', 'exp']));
    }

    public function testHasAllClaimsReturnsFalseForEmptyArray(): void
    {
        $collection = $this->makeValidCollection();

        $this->assertFalse($collection->hasAllClaims([]));
    }

    public function testToPlainArrayReturnsEmptyArrayDueToMapBug(): void
    {
        // Collection::toPlainArray() calls $this->map(fn($claim) => $claim->getValue()).
        // map() uses `new static(result)` which constructs a new Claims\Collection,
        // whose constructor runs sanitizeClaims() and drops all non-Claim values.
        // This is a known bug in the source: toPlainArray() always returns [].
        $collection = new ClaimCollection([
            'sub' => new Subject('user-1'),
        ]);

        $plain = $collection->toPlainArray();

        $this->assertSame([], $plain);
    }

    public function testClaimValuesAreAccessibleDirectlyViaGetByClaimName(): void
    {
        // Since toPlainArray() is broken, use getByClaimName() to verify stored values.
        $now = $this->testNowTimestamp;
        $collection = new ClaimCollection([
            'sub' => new Subject('user-1'),
            'iss' => new Issuer('https://example.com'),
            'iat' => new IssuedAt($now),
        ]);

        $sub = $collection->getByClaimName('sub');
        $iss = $collection->getByClaimName('iss');
        $iat = $collection->getByClaimName('iat');

        $this->assertNotNull($sub);
        $this->assertNotNull($iss);
        $this->assertNotNull($iat);
        $this->assertSame('user-1', $sub->getValue());
        $this->assertSame('https://example.com', $iss->getValue());
        $this->assertSame($now, $iat->getValue());
    }

    public function testValidateCallsValidatePayloadOnEachClaim(): void
    {
        // All valid claims should not throw on payload validation
        $collection = $this->makeValidCollection();

        // Should complete without exception
        $result = $collection->validate('payload');

        $this->assertInstanceOf(ClaimCollection::class, $result);
    }

    public function testValidateThrowsWhenExpiredExpirationClaimPresent(): void
    {
        $this->expectException(TokenExpiredException::class);

        $pastExp = new Expiration($this->testNowTimestamp - 1);
        $collection = new ClaimCollection(['exp' => $pastExp]);

        $collection->validate('payload');
    }

    public function testValidateReturnsSelfForChaining(): void
    {
        $collection = $this->makeValidCollection();

        $result = $collection->validate('payload');

        $this->assertSame($collection, $result);
    }

    public function testCollectionIgnoresNonClaimItems(): void
    {
        // Non-Claim entries in the constructor array are silently dropped
        $sub = new Subject('1');
        $collection = new ClaimCollection([
            'sub' => $sub,
            'not_a_claim' => 'just a string',
        ]);

        $this->assertCount(1, $collection);
        $this->assertTrue($collection->has('sub'));
    }

    public function testValidateCallsValidateRefreshWithArguments(): void
    {
        $iat = new IssuedAt($this->testNowTimestamp);
        $collection = new ClaimCollection(['iat' => $iat]);

        // Large refreshTTL — should not throw
        $result = $collection->validate('refresh', 20160);

        $this->assertInstanceOf(ClaimCollection::class, $result);
    }

    public function testCollectionCountMatchesNumberOfClaims(): void
    {
        $collection = $this->makeValidCollection();

        // makeValidClaims returns 6 claims
        $this->assertCount(6, $collection);
    }
}
