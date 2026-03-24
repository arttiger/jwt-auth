<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test\Validators;

use ArtTiger\JWTAuth\Exceptions\TokenInvalidException;
use ArtTiger\JWTAuth\Test\AbstractTestCase;
use ArtTiger\JWTAuth\Validators\TokenValidator;

class TokenValidatorTest extends AbstractTestCase
{
    private TokenValidator $validator;

    protected function setUp(): void
    {
        parent::setUp();

        $this->validator = new TokenValidator();
    }

    public function testValidTokenReturnsInputString(): void
    {
        $token = 'header.payload.signature';

        $result = $this->validator->validate($token);

        $this->assertSame($token, $result);
    }

    public function testThrowsWrongNumberOfSegmentsForOneSegment(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Wrong number of segments');

        $this->validator->validate('onlyone');
    }

    public function testThrowsWrongNumberOfSegmentsForTwoSegments(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Wrong number of segments');

        $this->validator->validate('header.payload');
    }

    public function testThrowsWrongNumberOfSegmentsForFourSegments(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Wrong number of segments');

        $this->validator->validate('a.b.c.d');
    }

    public function testThrowsWrongNumberOfSegmentsForFiveSegments(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Wrong number of segments');

        $this->validator->validate('a.b.c.d.e');
    }

    public function testThrowsMalformedForEmptyFirstSegment(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Malformed token');

        $this->validator->validate('.payload.signature');
    }

    public function testThrowsMalformedForEmptyMiddleSegment(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Malformed token');

        $this->validator->validate('header..signature');
    }

    public function testThrowsMalformedForEmptyLastSegment(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Malformed token');

        $this->validator->validate('header.payload.');
    }

    public function testThrowsMalformedForSegmentWithOnlyWhitespace(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Malformed token');

        $this->validator->validate('header.   .signature');
    }

    public function testThrowsMalformedForLeadingWhitespaceInSegment(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Malformed token');

        $this->validator->validate(' header.payload.signature');
    }

    public function testThrowsMalformedForTrailingWhitespaceInSegment(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Malformed token');

        $this->validator->validate('header.payload.signature ');
    }

    public function testValidTokenWithNumericSegmentsIsAccepted(): void
    {
        $token = '123.456.789';

        $result = $this->validator->validate($token);

        $this->assertSame($token, $result);
    }
}
