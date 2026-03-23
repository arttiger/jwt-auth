<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test\Claims;

use ArtTiger\JWTAuth\Claims\Audience;
use ArtTiger\JWTAuth\Claims\Custom;
use ArtTiger\JWTAuth\Claims\Issuer;
use ArtTiger\JWTAuth\Claims\JwtId;
use ArtTiger\JWTAuth\Claims\Subject;
use ArtTiger\JWTAuth\Exceptions\InvalidClaimException;
use ArtTiger\JWTAuth\Test\AbstractTestCase;

class SimpleClaimsTest extends AbstractTestCase
{
    // --- Audience ---

    public function testAudienceAcceptsSingleString(): void
    {
        $aud = new Audience('api');

        $this->assertSame('aud', $aud->getName());
        $this->assertSame('api', $aud->getValue());
        $this->assertSame(['aud' => 'api'], $aud->toArray());
    }

    public function testAudienceAcceptsArrayOfStrings(): void
    {
        $aud = new Audience(['api', 'admin']);

        $this->assertSame(['api', 'admin'], $aud->getValue());
    }

    public function testAudienceThrowsForNonStringScalar(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('Invalid value provided for claim [aud]');

        new Audience(42);
    }

    public function testAudienceThrowsForEmptyArray(): void
    {
        $this->expectException(InvalidClaimException::class);

        new Audience([]);
    }

    public function testAudienceThrowsForArrayWithNonStringItem(): void
    {
        $this->expectException(InvalidClaimException::class);

        new Audience(['valid', 123]);
    }

    // --- Subject ---

    public function testSubjectAcceptsString(): void
    {
        $sub = new Subject('user-42');

        $this->assertSame('sub', $sub->getName());
        $this->assertSame('user-42', $sub->getValue());
        $this->assertSame(['sub' => 'user-42'], $sub->toArray());
    }

    public function testSubjectThrowsForNonString(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('Invalid value provided for claim [sub]');

        new Subject(42);
    }

    // --- Issuer ---

    public function testIssuerAcceptsString(): void
    {
        $iss = new Issuer('http://example.com');

        $this->assertSame('iss', $iss->getName());
        $this->assertSame('http://example.com', $iss->getValue());
        $this->assertSame(['iss' => 'http://example.com'], $iss->toArray());
    }

    public function testIssuerThrowsForNonString(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('Invalid value provided for claim [iss]');

        new Issuer(null);
    }

    // --- JwtId ---

    public function testJwtIdAcceptsString(): void
    {
        $jti = new JwtId('unique-id-123');

        $this->assertSame('jti', $jti->getName());
        $this->assertSame('unique-id-123', $jti->getValue());
        $this->assertSame(['jti' => 'unique-id-123'], $jti->toArray());
    }

    public function testJwtIdThrowsForNonString(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('Invalid value provided for claim [jti]');

        new JwtId(true);
    }

    // --- Custom ---

    public function testCustomClaimAcceptsAnyValue(): void
    {
        $custom = new Custom('role', 'admin');

        $this->assertSame('role', $custom->getName());
        $this->assertSame('admin', $custom->getValue());
        $this->assertSame(['role' => 'admin'], $custom->toArray());
    }

    public function testCustomClaimCanStoreArrayValue(): void
    {
        $custom = new Custom('permissions', ['read', 'write']);

        $this->assertSame(['read', 'write'], $custom->getValue());
    }
}
