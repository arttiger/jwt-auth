<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test\Claims;

use ArtTiger\JWTAuth\Claims\IssuedAt;
use ArtTiger\JWTAuth\Exceptions\InvalidClaimException;
use ArtTiger\JWTAuth\Exceptions\TokenExpiredException;
use ArtTiger\JWTAuth\Exceptions\TokenInvalidException;
use ArtTiger\JWTAuth\Test\AbstractTestCase;
use Carbon\Carbon;

class IssuedAtTest extends AbstractTestCase
{
    public function testConstructsWithCurrentTimestamp(): void
    {
        $claim = new IssuedAt($this->testNowTimestamp);

        $this->assertSame($this->testNowTimestamp, $claim->getValue());
    }

    public function testConstructsWithPastTimestamp(): void
    {
        $past = $this->testNowTimestamp - 3600;
        $claim = new IssuedAt($past);

        $this->assertSame($past, $claim->getValue());
    }

    public function testClaimNameIsIat(): void
    {
        $claim = new IssuedAt($this->testNowTimestamp);

        $this->assertSame('iat', $claim->getName());
    }

    public function testThrowsInvalidClaimExceptionForFutureTimestampOnConstruction(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('iat');

        new IssuedAt($this->testNowTimestamp + 3600);
    }

    public function testThrowsForNonNumericStringOnConstruction(): void
    {
        $this->expectException(InvalidClaimException::class);

        new IssuedAt('not-a-number');
    }

    public function testValidatePayloadReturnsTrueForCurrentTimestamp(): void
    {
        $claim = new IssuedAt($this->testNowTimestamp);

        $this->assertTrue($claim->validatePayload());
    }

    public function testValidatePayloadThrowsTokenInvalidExceptionForFutureIat(): void
    {
        // Create with a past timestamp, then advance Carbon so it looks future
        $claim = new IssuedAt($this->testNowTimestamp);

        // Roll time back so the original iat is now "in the future"
        Carbon::setTestNow(Carbon::now()->subHour());

        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Issued At (iat) timestamp cannot be in the future');

        $claim->validatePayload();
    }

    public function testValidateRefreshDoesNotThrowWhenWithinRefreshTtl(): void
    {
        $claim = new IssuedAt($this->testNowTimestamp);

        // refreshTTL = 20160 minutes (2 weeks). iat is now, so iat + 20160 min is far future.
        $result = $claim->validateRefresh(20160);

        $this->assertTrue($result);
    }

    public function testValidateRefreshThrowsTokenExpiredExceptionWhenBeyondRefreshTtl(): void
    {
        // iat was 3 hours ago
        $oldIat = $this->testNowTimestamp - (3 * 3600);
        $claim = new IssuedAt($oldIat);

        // refreshTTL = 1 minute means iat + 60s is already past
        $this->expectException(TokenExpiredException::class);
        $this->expectExceptionMessage('Token has expired and can no longer be refreshed');

        $claim->validateRefresh(1);
    }

    public function testValidateRefreshAtExactBoundaryPassesBecauseNowIsNotPast(): void
    {
        // iat was exactly refreshTTL minutes ago → iat + refreshTTL*60 == now.
        // isPast(now) returns false (current second is not past), so no exception.
        $refreshTTL = 60; // minutes
        $oldIat = $this->testNowTimestamp - ($refreshTTL * 60);
        $claim = new IssuedAt($oldIat);

        $result = $claim->validateRefresh($refreshTTL);

        $this->assertTrue($result);
    }

    public function testGetValueReturnsInt(): void
    {
        $claim = new IssuedAt($this->testNowTimestamp);

        $this->assertIsInt($claim->getValue());
    }
}
