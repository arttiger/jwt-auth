<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test\Claims;

use ArtTiger\JWTAuth\Claims\Subject;
use ArtTiger\JWTAuth\Exceptions\InvalidClaimException;
use ArtTiger\JWTAuth\Test\AbstractTestCase;

class SubjectTest extends AbstractTestCase
{
    public function testConstructsWithValidNonEmptyString(): void
    {
        $subject = new Subject('user-123');

        $this->assertSame('user-123', $subject->getValue());
    }

    public function testConstructsWithNumericStringIdentifier(): void
    {
        $subject = new Subject('42');

        $this->assertSame('42', $subject->getValue());
    }

    public function testClaimNameIsSub(): void
    {
        $subject = new Subject('user-1');

        $this->assertSame('sub', $subject->getName());
    }

    public function testThrowsForEmptyString(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('sub');

        new Subject('');
    }

    public function testThrowsForNonStringInteger(): void
    {
        $this->expectException(InvalidClaimException::class);

        new Subject(123);
    }

    public function testThrowsForNullValue(): void
    {
        $this->expectException(InvalidClaimException::class);

        new Subject(null);
    }

    public function testThrowsForArrayValue(): void
    {
        $this->expectException(InvalidClaimException::class);

        new Subject([]);
    }

    public function testAcceptsValidUriWithColon(): void
    {
        $subject = new Subject('https://example.com/users/1');

        $this->assertSame('https://example.com/users/1', $subject->getValue());
    }

    public function testThrowsForUrnStyleUriNotValidatedByFilterVarUrl(): void
    {
        // Subject::validateCreate uses FILTER_VALIDATE_URL which does NOT accept URN syntax.
        // urn:uuid: URIs are rejected, causing an InvalidClaimException.
        $this->expectException(\ArtTiger\JWTAuth\Exceptions\InvalidClaimException::class);

        new Subject('urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6');
    }

    public function testThrowsForStringWithColonThatIsNotValidUri(): void
    {
        $this->expectException(InvalidClaimException::class);

        // Contains ':' but is not a valid URI
        new Subject('not:a:valid:uri::here');
    }

    public function testThrowsForStringWithColonAndNoScheme(): void
    {
        $this->expectException(InvalidClaimException::class);

        new Subject(':invalid-start');
    }

    public function testToArrayUsesSubKey(): void
    {
        $subject = new Subject('user-1');

        $this->assertSame(['sub' => 'user-1'], $subject->toArray());
    }
}
