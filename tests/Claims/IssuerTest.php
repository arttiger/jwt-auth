<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test\Claims;

use ArtTiger\JWTAuth\Claims\Issuer;
use ArtTiger\JWTAuth\Exceptions\InvalidClaimException;
use ArtTiger\JWTAuth\Test\AbstractTestCase;

class IssuerTest extends AbstractTestCase
{
    public function testConstructsWithValidString(): void
    {
        $issuer = new Issuer('https://example.com');

        $this->assertSame('https://example.com', $issuer->getValue());
    }

    public function testConstructsWithEmptyString(): void
    {
        // RFC 7519 §4.1.1: iss is a StringOrURI; an empty string is technically
        // valid since the Issuer::validateCreate only requires it to be a string.
        $issuer = new Issuer('');

        $this->assertSame('', $issuer->getValue());
    }

    public function testClaimNameIsIss(): void
    {
        $issuer = new Issuer('issuer');

        $this->assertSame('iss', $issuer->getName());
    }

    public function testThrowsForIntegerInput(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('iss');

        new Issuer(123);
    }

    public function testThrowsForArrayInput(): void
    {
        $this->expectException(InvalidClaimException::class);

        new Issuer(['array']);
    }

    public function testThrowsForNullInput(): void
    {
        $this->expectException(InvalidClaimException::class);

        new Issuer(null);
    }

    public function testThrowsForBooleanInput(): void
    {
        $this->expectException(InvalidClaimException::class);

        new Issuer(true);
    }

    public function testToArrayUsesIssKey(): void
    {
        $issuer = new Issuer('https://example.com');

        $this->assertSame(['iss' => 'https://example.com'], $issuer->toArray());
    }
}
