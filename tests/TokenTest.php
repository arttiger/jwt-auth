<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test;

use ArtTiger\JWTAuth\Exceptions\TokenInvalidException;
use ArtTiger\JWTAuth\Token;

class TokenTest extends AbstractTestCase
{
    private const string VALID_TOKEN = 'header.payload.signature';

    public function testConstructsWithValidThreeSegmentToken(): void
    {
        $token = new Token(self::VALID_TOKEN);

        $this->assertInstanceOf(Token::class, $token);
    }

    public function testGetReturnsOriginalTokenString(): void
    {
        $token = new Token(self::VALID_TOKEN);

        $this->assertSame(self::VALID_TOKEN, $token->get());
    }

    public function testToStringReturnsTokenString(): void
    {
        $token = new Token(self::VALID_TOKEN);

        $this->assertSame(self::VALID_TOKEN, (string) $token);
    }

    public function testToStringMatchesGet(): void
    {
        $token = new Token(self::VALID_TOKEN);

        $this->assertSame($token->get(), (string) $token);
    }

    public function testThrowsForSingleSegmentToken(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Wrong number of segments');

        new Token('onlyone');
    }

    public function testThrowsForTwoSegmentToken(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Wrong number of segments');

        new Token('header.payload');
    }

    public function testThrowsForFourSegmentToken(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Wrong number of segments');

        new Token('header.payload.signature.extra');
    }

    public function testThrowsForTokenWithLeadingWhitespaceInSegment(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Malformed token');

        new Token(' header.payload.signature');
    }

    public function testThrowsForTokenWithTrailingWhitespaceInSegment(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Malformed token');

        new Token('header.payload.signature ');
    }

    public function testThrowsForTokenWithEmptyMiddleSegment(): void
    {
        $this->expectException(TokenInvalidException::class);

        new Token('header..signature');
    }

    public function testThrowsForTokenWithEmptyFirstSegment(): void
    {
        $this->expectException(TokenInvalidException::class);

        new Token('.payload.signature');
    }

    public function testThrowsForTokenWithEmptyLastSegment(): void
    {
        $this->expectException(TokenInvalidException::class);

        new Token('header.payload.');
    }

    public function testAcceptsTokenWithBase64UrlCharacters(): void
    {
        // Real JWT base64url segments contain alphanumeric, +, /, - and _
        $token = new Token('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c');

        $this->assertSame(
            'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
            $token->get()
        );
    }
}
