<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test\Claims;

use ArtTiger\JWTAuth\Claims\NotBefore;
use ArtTiger\JWTAuth\Exceptions\InvalidClaimException;
use ArtTiger\JWTAuth\Exceptions\TokenInvalidException;
use ArtTiger\JWTAuth\Test\AbstractTestCase;

class NotBeforeTest extends AbstractTestCase
{
    public function testConstructsWithCurrentTimestamp(): void
    {
        $claim = new NotBefore($this->testNowTimestamp);

        $this->assertSame($this->testNowTimestamp, $claim->getValue());
    }

    public function testConstructsWithPastTimestamp(): void
    {
        $past = $this->testNowTimestamp - 3600;
        $claim = new NotBefore($past);

        $this->assertSame($past, $claim->getValue());
    }

    public function testClaimNameIsNbf(): void
    {
        $claim = new NotBefore($this->testNowTimestamp);

        $this->assertSame('nbf', $claim->getName());
    }

    public function testConstructsWithFutureTimestamp(): void
    {
        // NotBefore's validateCreate (from DatetimeTrait) only checks numeric;
        // it does NOT prohibit future values on construction — only validatePayload does.
        $future = $this->testNowTimestamp + 3600;
        $claim = new NotBefore($future);

        $this->assertSame($future, $claim->getValue());
    }

    public function testThrowsForNonNumericStringOnConstruction(): void
    {
        $this->expectException(InvalidClaimException::class);

        new NotBefore('invalid');
    }

    public function testValidatePayloadReturnsTrueForPastTimestamp(): void
    {
        $past = $this->testNowTimestamp - 3600;
        $claim = new NotBefore($past);

        $this->assertTrue($claim->validatePayload());
    }

    public function testValidatePayloadReturnsTrueForCurrentTimestamp(): void
    {
        // Exactly now: isFuture returns false for the exact current second
        $claim = new NotBefore($this->testNowTimestamp);

        $this->assertTrue($claim->validatePayload());
    }

    public function testValidatePayloadThrowsTokenInvalidExceptionForFutureTimestamp(): void
    {
        $future = $this->testNowTimestamp + 3600;
        $claim = new NotBefore($future);

        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Not Before (nbf) timestamp cannot be in the future');

        $claim->validatePayload();
    }

    public function testValidatePayloadThrowsForSlightlyFutureTimestamp(): void
    {
        // Even 1 second in the future should fail
        $slightlyFuture = $this->testNowTimestamp + 1;
        $claim = new NotBefore($slightlyFuture);

        $this->expectException(TokenInvalidException::class);

        $claim->validatePayload();
    }

    public function testSetLeewayAllowsSlightlyFutureNbf(): void
    {
        // With leeway=60, a nbf 30s in the future should pass
        $slightlyFuture = $this->testNowTimestamp + 30;
        $claim = new NotBefore($slightlyFuture);
        $claim->setLeeway(60);

        $result = $claim->validatePayload();

        $this->assertTrue($result);
    }

    public function testGetValueReturnsInt(): void
    {
        $claim = new NotBefore($this->testNowTimestamp);

        $this->assertSame($this->testNowTimestamp, $claim->getValue());
    }

    public function testToArrayUsesNbfKey(): void
    {
        $claim = new NotBefore($this->testNowTimestamp);

        $this->assertSame(['nbf' => $this->testNowTimestamp], $claim->toArray());
    }
}
