<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test\Claims;

use ArtTiger\JWTAuth\Claims\JwtId;
use ArtTiger\JWTAuth\Exceptions\InvalidClaimException;
use ArtTiger\JWTAuth\Test\AbstractTestCase;

class JwtIdTest extends AbstractTestCase
{
    public function testConstructsWithValidString(): void
    {
        $jwtId = new JwtId('unique-id-abc123');

        $this->assertSame('unique-id-abc123', $jwtId->getValue());
    }

    public function testConstructsWithUuidString(): void
    {
        $uuid = 'f81d4fae-7dec-11d0-a765-00a0c91e6bf6';
        $jwtId = new JwtId($uuid);

        $this->assertSame($uuid, $jwtId->getValue());
    }

    public function testConstructsWithEmptyString(): void
    {
        // JwtId::validateCreate only requires a string type; empty is allowed
        $jwtId = new JwtId('');

        $this->assertSame('', $jwtId->getValue());
    }

    public function testClaimNameIsJti(): void
    {
        $jwtId = new JwtId('some-id');

        $this->assertSame('jti', $jwtId->getName());
    }

    public function testThrowsForIntegerInput(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('jti');

        new JwtId(12345);
    }

    public function testThrowsForNullInput(): void
    {
        $this->expectException(InvalidClaimException::class);

        new JwtId(null);
    }

    public function testThrowsForArrayInput(): void
    {
        $this->expectException(InvalidClaimException::class);

        new JwtId([]);
    }

    public function testThrowsForBooleanInput(): void
    {
        $this->expectException(InvalidClaimException::class);

        new JwtId(false);
    }

    public function testToArrayUsesJtiKey(): void
    {
        $jwtId = new JwtId('my-jwt-id');

        $this->assertSame(['jti' => 'my-jwt-id'], $jwtId->toArray());
    }
}
