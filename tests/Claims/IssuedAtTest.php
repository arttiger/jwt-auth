<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test\Claims;

use ArtTiger\JWTAuth\Claims\IssuedAt;
use ArtTiger\JWTAuth\Exceptions\InvalidClaimException;
use ArtTiger\JWTAuth\Test\AbstractTestCase;

class IssuedAtTest extends AbstractTestCase
{
    public function testItShouldThrowAnExceptionWhenPassingAFutureTimestamp(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('Invalid value provided for claim [iat]');

        new IssuedAt($this->testNowTimestamp + 3600);
    }
}
