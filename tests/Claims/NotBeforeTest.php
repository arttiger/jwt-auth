<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test\Claims;

use ArtTiger\JWTAuth\Claims\NotBefore;
use ArtTiger\JWTAuth\Exceptions\InvalidClaimException;
use ArtTiger\JWTAuth\Test\AbstractTestCase;

class NotBeforeTest extends AbstractTestCase
{
    public function testItShouldThrowAnExceptionWhenPassingAnInvalidValue(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('Invalid value provided for claim [nbf]');

        new NotBefore('foo');
    }
}
