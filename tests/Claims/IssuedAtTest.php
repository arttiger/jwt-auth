<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test\Claims;

use ArtTiger\JWTAuth\Abstracts\Claim;
use ArtTiger\JWTAuth\Claims\IssuedAt;
use ArtTiger\JWTAuth\Exceptions\InvalidClaimException;
use ArtTiger\JWTAuth\Exceptions\TokenExpiredException;
use ArtTiger\JWTAuth\Exceptions\TokenInvalidException;
use ArtTiger\JWTAuth\Test\AbstractTestCase;
use ReflectionProperty;

class IssuedAtTest extends AbstractTestCase
{
    public function testItShouldThrowAnExceptionWhenPassingAFutureTimestamp(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('Invalid value provided for claim [iat]');

        new IssuedAt($this->testNowTimestamp + 3600);
    }

    public function testItShouldThrowAnExceptionWhenPassingANonNumericValue(): void
    {
        $this->expectException(InvalidClaimException::class);

        new IssuedAt('not-a-timestamp');
    }

    public function testItShouldCreateWithCurrentTimestamp(): void
    {
        $iat = new IssuedAt($this->testNowTimestamp);

        $this->assertSame($this->testNowTimestamp, $iat->getValue());
        $this->assertSame('iat', $iat->getName());
    }

    public function testValidatePayloadReturnsTrueForPastTimestamp(): void
    {
        $iat = new IssuedAt($this->testNowTimestamp);

        $this->assertTrue($iat->validatePayload());
    }

    public function testValidatePayloadThrowsTokenInvalidExceptionWhenIatIsFuture(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Issued At (iat) timestamp cannot be in the future');

        $iat = new IssuedAt($this->testNowTimestamp);

        // Bypass validateCreate by setting the private value directly via reflection
        $prop = new ReflectionProperty(Claim::class, 'value');
        $prop->setValue($iat, $this->testNowTimestamp + 3600);

        $iat->validatePayload();
    }

    public function testValidateRefreshReturnsTrueWhenWithinRefreshTtl(): void
    {
        $iat = new IssuedAt($this->testNowTimestamp);

        $this->assertTrue($iat->validateRefresh(60));
    }

    public function testValidateRefreshThrowsExceptionWhenExpiredForRefresh(): void
    {
        $this->expectException(TokenExpiredException::class);
        $this->expectExceptionMessage('Token has expired and can no longer be refreshed');

        // iat is 2 hours in the past, refreshTTL is 1 minute — well past refresh window
        $iat = new IssuedAt($this->testNowTimestamp - 7200);
        $iat->validateRefresh(1);
    }
}
