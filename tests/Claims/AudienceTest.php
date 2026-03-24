<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test\Claims;

use ArtTiger\JWTAuth\Claims\Audience;
use ArtTiger\JWTAuth\Exceptions\InvalidClaimException;
use ArtTiger\JWTAuth\Test\AbstractTestCase;

class AudienceTest extends AbstractTestCase
{
    public function testConstructsWithSingleStringValue(): void
    {
        $audience = new Audience('api.example.com');

        $this->assertSame('api.example.com', $audience->getValue());
    }

    public function testConstructsWithArrayOfStrings(): void
    {
        $audiences = ['api.example.com', 'admin.example.com'];
        $audience = new Audience($audiences);

        $this->assertSame($audiences, $audience->getValue());
    }

    public function testConstructsWithSingleElementArray(): void
    {
        $audience = new Audience(['single']);

        $this->assertSame(['single'], $audience->getValue());
    }

    public function testClaimNameIsAud(): void
    {
        $audience = new Audience('aud');

        $this->assertSame('aud', $audience->getName());
    }

    public function testThrowsForEmptyArray(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('aud');

        new Audience([]);
    }

    public function testThrowsForArrayContainingNonString(): void
    {
        $this->expectException(InvalidClaimException::class);

        new Audience(['valid', 123]);
    }

    public function testThrowsForArrayContainingNull(): void
    {
        $this->expectException(InvalidClaimException::class);

        new Audience(['valid', null]);
    }

    public function testThrowsForArrayContainingOnlyIntegers(): void
    {
        $this->expectException(InvalidClaimException::class);

        new Audience([1, 2, 3]);
    }

    public function testThrowsForIntegerInput(): void
    {
        $this->expectException(InvalidClaimException::class);

        new Audience(42);
    }

    public function testThrowsForNullInput(): void
    {
        $this->expectException(InvalidClaimException::class);

        new Audience(null);
    }

    public function testThrowsForBooleanInput(): void
    {
        $this->expectException(InvalidClaimException::class);

        new Audience(true);
    }

    public function testToArrayUsesAudKey(): void
    {
        $audience = new Audience('example.com');

        $this->assertSame(['aud' => 'example.com'], $audience->toArray());
    }

    public function testToArrayWithArrayValuePreservesArray(): void
    {
        $audiences = ['a.example.com', 'b.example.com'];
        $audience = new Audience($audiences);

        $this->assertSame(['aud' => $audiences], $audience->toArray());
    }
}
