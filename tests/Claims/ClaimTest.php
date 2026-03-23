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
        $this->assertJsonStringEqualsJsonString(json_encode($this->claim), $this->claim->toJson());
    }

    public function testItShouldImplementArrayable(): void
    {
        $this->assertInstanceOf(Arrayable::class, $this->claim);
    }
}
