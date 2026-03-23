<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test\Claims;

use ArtTiger\JWTAuth\Claims\NotBefore;
use ArtTiger\JWTAuth\Exceptions\InvalidClaimException;
use ArtTiger\JWTAuth\Exceptions\TokenInvalidException;
use ArtTiger\JWTAuth\Test\AbstractTestCase;

class NotBeforeTest extends AbstractTestCase
{
    public function testItShouldThrowAnExceptionWhenPassingAnInvalidValue(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('Invalid value provided for claim [nbf]');

        new NotBefore('foo');
    }

    public function testItShouldCreateWithValidTimestamp(): void
    {
        $nbf = new NotBefore($this->testNowTimestamp);

        $this->assertSame($this->testNowTimestamp, $nbf->getValue());
        $this->assertSame('nbf', $nbf->getName());
    }

    public function testValidatePayloadReturnsTrueWhenNbfIsInThePast(): void
    {
        $nbf = new NotBefore($this->testNowTimestamp - 60);

        $this->assertTrue($nbf->validatePayload());
    }

    public function testValidatePayloadReturnsTrueForCurrentTimestamp(): void
    {
        $nbf = new NotBefore($this->testNowTimestamp);

        $this->assertTrue($nbf->validatePayload());
    }

    public function testValidatePayloadThrowsExceptionWhenNbfIsInTheFuture(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Not Before (nbf) timestamp cannot be in the future');

        $nbf = new NotBefore($this->testNowTimestamp + 3600);
        $nbf->validatePayload();
    }

    public function testValidatePayloadWithLeewayAllowsSlightlyFutureNbf(): void
    {
        // nbf is 30s in the future, but leeway is 60s — should pass validation
        $nbf = new NotBefore($this->testNowTimestamp + 30);
        $nbf->setLeeway(60);

        $this->assertTrue($nbf->validatePayload());
    }
}
