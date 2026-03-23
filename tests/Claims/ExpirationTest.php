<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test\Claims;

use ArtTiger\JWTAuth\Claims\Expiration;
use ArtTiger\JWTAuth\Exceptions\InvalidClaimException;
use ArtTiger\JWTAuth\Exceptions\TokenExpiredException;
use ArtTiger\JWTAuth\Test\AbstractTestCase;

class ExpirationTest extends AbstractTestCase
{
    public function testItShouldThrowAnExceptionWhenPassingANonNumericValue(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('Invalid value provided for claim [exp]');

        new Expiration('not-a-timestamp');
    }

    public function testItShouldCreateWithFutureTimestamp(): void
    {
        $exp = new Expiration($this->testNowTimestamp + 3600);

        $this->assertSame($this->testNowTimestamp + 3600, $exp->getValue());
        $this->assertSame('exp', $exp->getName());
    }

    public function testValidatePayloadReturnsTrueWhenNotExpired(): void
    {
        $exp = new Expiration($this->testNowTimestamp + 3600);

        $this->assertTrue($exp->validatePayload());
    }

    public function testValidatePayloadThrowsExceptionWhenExpired(): void
    {
        $this->expectException(TokenExpiredException::class);
        $this->expectExceptionMessage('Token has expired');

        $exp = new Expiration($this->testNowTimestamp - 3600);
        $exp->validatePayload();
    }

    public function testValidatePayloadWithLeewayAllowsSlightlyExpiredToken(): void
    {
        // expired 30s ago but leeway is 60s — should still be valid
        $exp = new Expiration($this->testNowTimestamp - 30);
        $exp->setLeeway(60);

        $this->assertTrue($exp->validatePayload());
    }
}
