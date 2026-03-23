<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test\Claims;

use Illuminate\Contracts\Support\Arrayable;
use ArtTiger\JWTAuth\Claims\Expiration;
use ArtTiger\JWTAuth\Exceptions\InvalidClaimException;
use ArtTiger\JWTAuth\Test\AbstractTestCase;

class ClaimTest extends AbstractTestCase
{
    protected Expiration $claim;

    /**
     * @throws InvalidClaimException
     */
    public function setUp(): void
    {
        parent::setUp();

        $this->claim = new Expiration($this->testNowTimestamp);
    }

    public function testItShouldThrowAnExceptionWhenPassingAnInvalidValue(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('Invalid value provided for claim [exp]');

        $this->claim->setValue('foo');
    }

    public function testItShouldConvertTheClaimToAnArray(): void
    {
        $this->assertSame(['exp' => $this->testNowTimestamp], $this->claim->toArray());
    }

    public function testItShouldGetTheClaimAsAString(): void
    {
        $this->assertJsonStringEqualsJsonString((string) $this->claim, $this->claim->toJson());
    }

    public function testItShouldGetTheObjectAsJson(): void
    {
        $encoded = json_encode($this->claim);
        $this->assertNotFalse($encoded);
        $this->assertJsonStringEqualsJsonString($encoded, $this->claim->toJson());
    }

    public function testItShouldImplementArrayable(): void
    {
        $this->assertInstanceOf(Arrayable::class, $this->claim);
    }

    public function testItShouldGetTheClaimValue(): void
    {
        $this->assertSame($this->testNowTimestamp, $this->claim->getValue());
    }

    public function testItShouldGetAndSetTheClaimName(): void
    {
        $this->assertSame('exp', $this->claim->getName());

        $this->claim->setName('custom_name');
        $this->assertSame('custom_name', $this->claim->getName());
    }

    public function testItShouldMatchTheValueStrictly(): void
    {
        $this->assertTrue($this->claim->matches($this->testNowTimestamp));
        $this->assertFalse($this->claim->matches($this->testNowTimestamp + 1));
        $this->assertFalse($this->claim->matches((string) $this->testNowTimestamp));
    }

    public function testItShouldMatchTheValueLoosely(): void
    {
        $this->assertTrue($this->claim->matches($this->testNowTimestamp, false));
        $this->assertTrue($this->claim->matches((string) $this->testNowTimestamp, false));
        $this->assertFalse($this->claim->matches($this->testNowTimestamp + 1, false));
    }

    public function testItShouldJsonSerialize(): void
    {
        $this->assertSame(['exp' => $this->testNowTimestamp], $this->claim->jsonSerialize());
    }
}
