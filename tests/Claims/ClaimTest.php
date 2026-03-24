<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test\Claims;

use ArtTiger\JWTAuth\Claims\Expiration;
use ArtTiger\JWTAuth\Exceptions\InvalidClaimException;
use ArtTiger\JWTAuth\Test\AbstractTestCase;
use Illuminate\Contracts\Support\Arrayable;

/**
 * Tests the abstract Claim base class using Expiration as the concrete subject.
 */
class ClaimTest extends AbstractTestCase
{
    private int $futureTimestamp;

    protected function setUp(): void
    {
        parent::setUp();

        $this->futureTimestamp = $this->testNowTimestamp + 3600;
    }

    public function testConstructsWithValidValue(): void
    {
        $claim = new Expiration($this->futureTimestamp);

        $this->assertSame($this->futureTimestamp, $claim->getValue());
    }

    public function testGetNameReturnsClaimName(): void
    {
        $claim = new Expiration($this->futureTimestamp);

        $this->assertSame('exp', $claim->getName());
    }

    public function testSetValueUpdatesStoredValue(): void
    {
        $claim = new Expiration($this->futureTimestamp);
        $newTimestamp = $this->futureTimestamp + 1000;

        $claim->setValue($newTimestamp);

        $this->assertSame($newTimestamp, $claim->getValue());
    }

    public function testSetValueThrowsForNonNumericInput(): void
    {
        $this->expectException(InvalidClaimException::class);

        new Expiration('not-a-number');
    }

    public function testSetValueThrowsForArrayInput(): void
    {
        $this->expectException(InvalidClaimException::class);

        new Expiration([]);
    }

    public function testSetNameChangesName(): void
    {
        $claim = new Expiration($this->futureTimestamp);

        $claim->setName('custom_exp');

        $this->assertSame('custom_exp', $claim->getName());
    }

    public function testToArrayReturnsKeyValuePair(): void
    {
        $claim = new Expiration($this->futureTimestamp);

        $result = $claim->toArray();

        $this->assertSame(['exp' => $this->futureTimestamp], $result);
    }

    public function testToJsonReturnsJsonString(): void
    {
        $claim = new Expiration($this->futureTimestamp);

        $json = $claim->toJson();

        $this->assertJson($json);
        $decoded = json_decode($json, true);
        $this->assertIsArray($decoded);
        $this->assertSame($this->futureTimestamp, $decoded['exp']);
    }

    public function testToStringReturnsJson(): void
    {
        $claim = new Expiration($this->futureTimestamp);

        $this->assertSame($claim->toJson(), (string) $claim);
    }

    public function testMatchesStrictReturnsTrueForIdenticalValue(): void
    {
        $claim = new Expiration($this->futureTimestamp);

        $this->assertTrue($claim->matches($this->futureTimestamp, true));
    }

    public function testMatchesStrictReturnsFalseForDifferentType(): void
    {
        $claim = new Expiration($this->futureTimestamp);

        // String representation of the integer should fail strict comparison
        $this->assertFalse($claim->matches((string) $this->futureTimestamp, true));
    }

    public function testMatchesLooseReturnsTrueForStringNumericEquivalent(): void
    {
        $claim = new Expiration($this->futureTimestamp);

        // Loose comparison: int == string of same number
        $this->assertTrue($claim->matches((string) $this->futureTimestamp, false));
    }

    public function testMatchesReturnsFalseForWrongValue(): void
    {
        $claim = new Expiration($this->futureTimestamp);

        $this->assertFalse($claim->matches($this->futureTimestamp + 999, true));
    }

    public function testImplementsArrayableInterface(): void
    {
        $claim = new Expiration($this->futureTimestamp);

        $this->assertInstanceOf(Arrayable::class, $claim);
    }

    public function testJsonSerializeReturnsArray(): void
    {
        $claim = new Expiration($this->futureTimestamp);

        $this->assertSame(['exp' => $this->futureTimestamp], $claim->jsonSerialize());
    }

    public function testValidatePayloadReturnsTrueForFutureTimestamp(): void
    {
        $claim = new Expiration($this->futureTimestamp);

        $result = $claim->validatePayload();

        $this->assertTrue($result);
    }

    public function testValidateRefreshReturnsTrueByDefault(): void
    {
        $claim = new Expiration($this->futureTimestamp);

        // Base Claim::validateRefresh just returns getValue(); Expiration inherits it.
        // Only the datetime-based overrides on IssuedAt differ.
        $result = $claim->validateRefresh(20160);

        $this->assertSame($this->futureTimestamp, $result);
    }
}
