<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test\Validators;

use ArtTiger\JWTAuth\Abstracts\Claim;
use ArtTiger\JWTAuth\Claims\Issuer;
use ArtTiger\JWTAuth\Collections\ClaimCollection;
use ArtTiger\JWTAuth\Claims\Expiration;
use ArtTiger\JWTAuth\Claims\IssuedAt;
use ArtTiger\JWTAuth\Claims\JwtId;
use ArtTiger\JWTAuth\Claims\NotBefore;
use ArtTiger\JWTAuth\Claims\Subject;
use ArtTiger\JWTAuth\Exceptions\TokenExpiredException;
use ArtTiger\JWTAuth\Exceptions\TokenInvalidException;
use ArtTiger\JWTAuth\Test\AbstractTestCase;
use ArtTiger\JWTAuth\Validators\PayloadValidator;

class PayloadValidatorTest extends AbstractTestCase
{
    private PayloadValidator $validator;

    protected function setUp(): void
    {
        parent::setUp();

        $this->validator = new PayloadValidator();
    }

    /**
     * @param array<string, Claim>|null $overrides
     */
    private function makeFullCollection(?array $overrides = []): ClaimCollection
    {
        return $this->makeValidCollection($overrides ?? []);
    }

    public function testValidCollectionPassesWithoutException(): void
    {
        $collection = $this->makeFullCollection();

        // Should not throw
        $this->validator->validateCollection($collection);

        $this->addToAssertionCount(1);
    }

    public function testThrowsWhenRequiredClaimIsMissing(): void
    {
        // Build a collection without 'sub'
        $claims = [
            'iss' => new Issuer('https://example.com'),
            'iat' => new IssuedAt($this->testNowTimestamp),
            'exp' => new Expiration($this->testNowTimestamp + 3600),
            'nbf' => new NotBefore($this->testNowTimestamp),
            'jti' => new JwtId('test-id'),
            // sub is intentionally missing
        ];
        $collection = new ClaimCollection($claims);

        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('JWT payload does not contain the required claims');

        $this->validator->validateCollection($collection);
    }

    public function testThrowsWhenMultipleRequiredClaimsAreMissing(): void
    {
        // Only have sub
        $collection = new ClaimCollection(['sub' => new Subject('1')]);

        $this->expectException(TokenInvalidException::class);

        $this->validator->validateCollection($collection);
    }

    public function testThrowsTokenExpiredExceptionForExpiredExpClaim(): void
    {
        $pastExp = new Expiration($this->testNowTimestamp - 1);
        $collection = $this->makeFullCollection(['exp' => $pastExp]);

        $this->expectException(TokenExpiredException::class);
        $this->expectExceptionMessage('Token has expired');

        $this->validator->validateCollection($collection);
    }

    public function testThrowsTokenInvalidExceptionForFutureNbfClaim(): void
    {
        $futureNbf = new NotBefore($this->testNowTimestamp + 3600);
        $collection = $this->makeFullCollection(['nbf' => $futureNbf]);

        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Not Before (nbf) timestamp cannot be in the future');

        $this->validator->validateCollection($collection);
    }

    public function testSetRequiredClaimsWithEmptyArraySkipsStructureCheck(): void
    {
        // With empty required claims, even a collection with only one claim passes
        $this->validator->setRequiredClaims([]);
        $collection = new ClaimCollection(['sub' => new Subject('1')]);

        // Should not throw — no required claims to check
        $this->validator->validateCollection($collection);

        $this->addToAssertionCount(1);
    }

    public function testSetRequiredClaimsLimitsWhichClaimsAreRequired(): void
    {
        // Only require 'sub' — other missing claims should not trigger exception
        $this->validator->setRequiredClaims(['sub']);
        $collection = new ClaimCollection(['sub' => new Subject('user-1')]);

        // Should not throw
        $this->validator->validateCollection($collection);

        $this->addToAssertionCount(1);
    }

    public function testSetRefreshTtlIsStoredAndUsed(): void
    {
        $this->validator->setRefreshTTL(100);

        // Verify through reflection or behavior: set refresh flow and use a
        // collection with an iat that would be expired under a 1-minute TTL
        $oldIat = new IssuedAt($this->testNowTimestamp - 3600); // 1 hour ago
        $collection = $this->makeFullCollection(['iat' => $oldIat]);

        $this->validator->setRefreshFlow(true);
        $this->validator->setRequiredClaims([]);

        // refreshTTL = 100 minutes, iat is 60 min ago → still valid
        $this->validator->setRefreshTTL(100);

        // Should not throw
        $this->validator->validateCollection($collection);

        $this->addToAssertionCount(1);
    }

    public function testRefreshFlowWithExpiredIatThrowsTokenExpiredException(): void
    {
        $oldIat = new IssuedAt($this->testNowTimestamp - 3600); // 1 hour ago
        $collection = $this->makeFullCollection(['iat' => $oldIat]);

        $this->validator->setRefreshFlow(true);
        $this->validator->setRefreshTTL(1); // 1 minute — already past

        $this->expectException(TokenExpiredException::class);
        $this->expectExceptionMessage('Token has expired and can no longer be refreshed');

        $this->validator->validateCollection($collection);
    }

    public function testRefreshFlowWithNullRefreshTtlDoesNotValidateRefreshExpiry(): void
    {
        $veryOldIat = new IssuedAt($this->testNowTimestamp - 86400); // 1 day ago
        $collection = $this->makeFullCollection(['iat' => $veryOldIat]);

        $this->validator->setRefreshFlow(true);
        $this->validator->setRefreshTTL(null); // null = no limit

        // Should not throw
        $this->validator->validateCollection($collection);

        $this->addToAssertionCount(1);
    }

    public function testSetRequiredClaimsReturnsSelf(): void
    {
        $result = $this->validator->setRequiredClaims(['sub']);

        $this->assertSame($this->validator, $result);
    }

    public function testSetRefreshTtlReturnsSelf(): void
    {
        $result = $this->validator->setRefreshTTL(20160);

        $this->assertSame($this->validator, $result);
    }
}
