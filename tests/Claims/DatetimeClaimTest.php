<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test\Claims;

use ArtTiger\JWTAuth\Claims\Collection;
use ArtTiger\JWTAuth\Claims\Expiration;
use ArtTiger\JWTAuth\Claims\IssuedAt;
use ArtTiger\JWTAuth\Claims\Issuer;
use ArtTiger\JWTAuth\Claims\JwtId;
use ArtTiger\JWTAuth\Claims\NotBefore;
use ArtTiger\JWTAuth\Claims\Subject;
use ArtTiger\JWTAuth\Exceptions\InvalidClaimException;
use ArtTiger\JWTAuth\Payload;
use ArtTiger\JWTAuth\Test\AbstractTestCase;
use ArtTiger\JWTAuth\Validators\PayloadValidator;
use Carbon\Carbon;
use DateInterval;
use DateTime;
use PHPUnit\Framework\MockObject\MockObject;

class DatetimeClaimTest extends AbstractTestCase
{
    /** @var PayloadValidator&MockObject */
    protected PayloadValidator $validator;

    /** @var array<string, \ArtTiger\JWTAuth\Abstracts\Claim> */
    protected array $claimsTimestamp;

    /**
     * @throws InvalidClaimException
     */
    public function setUp(): void
    {
        parent::setUp();

        $validator = $this->createMock(PayloadValidator::class);
        $validator->method('setRefreshFlow')->willReturnSelf();
        $validator->method('validateCollection')->willReturnSelf();
        $this->validator = $validator;

        $this->claimsTimestamp = [
            'sub' => new Subject('1'),
            'iss' => new Issuer('http://example.com'),
            'exp' => new Expiration($this->testNowTimestamp + 3600),
            'nbf' => new NotBefore($this->testNowTimestamp),
            'iat' => new IssuedAt($this->testNowTimestamp),
            'jti' => new JwtId('foo'),
        ];
    }

    /**
     * @throws InvalidClaimException
     */
    public function testItShouldHandleCarbonClaims(): void
    {
        $testCarbon = Carbon::createFromTimestampUTC($this->testNowTimestamp);
        $testCarbonCopy = clone $testCarbon;

        $this->assertInstanceOf(Carbon::class, $testCarbon);
        $this->assertInstanceOf(DateTime::class, $testCarbon);
        $this->assertInstanceOf(\DateTimeInterface::class, $testCarbon);

        $claimsDatetime = [
            'sub' => new Subject('1'),
            'iss' => new Issuer('http://example.com'),
            'exp' => new Expiration($testCarbonCopy->addHour()),
            'nbf' => new NotBefore($testCarbon),
            'iat' => new IssuedAt($testCarbon),
            'jti' => new JwtId('foo'),
        ];

        $payloadTimestamp = new Payload(Collection::make($this->claimsTimestamp), $this->validator);
        $payloadDatetime = new Payload(Collection::make($claimsDatetime), $this->validator);

        $this->assertEquals($payloadTimestamp, $payloadDatetime);
    }

    public function testItShouldHandleDatetimeClaims(): void
    {
        $testDateTime = DateTime::createFromFormat('U', (string) $this->testNowTimestamp);
        $this->assertInstanceOf(DateTime::class, $testDateTime);
        $testDateTimeCopy = clone $testDateTime;
        $this->assertInstanceOf(\DateTimeInterface::class, $testDateTime);

        $claimsDatetime = [
            'sub' => new Subject('1'),
            'iss' => new Issuer('http://example.com'),
            'exp' => new Expiration($testDateTimeCopy->modify('+3600 seconds')),
            'nbf' => new NotBefore($testDateTime),
            'iat' => new IssuedAt($testDateTime),
            'jti' => new JwtId('foo'),
        ];

        $payloadTimestamp = new Payload(Collection::make($this->claimsTimestamp), $this->validator);
        $payloadDatetime = new Payload(Collection::make($claimsDatetime), $this->validator);

        $this->assertEquals($payloadTimestamp, $payloadDatetime);
    }

    public function testItShouldHandleDatetimeImmutableClaims(): void
    {
        $testDateTimeImmutable = \DateTimeImmutable::createFromFormat('U', (string) $this->testNowTimestamp);

        $this->assertInstanceOf(\DateTimeImmutable::class, $testDateTimeImmutable);
        $this->assertInstanceOf(\DateTimeInterface::class, $testDateTimeImmutable);

        $claimsDatetime = [
            'sub' => new Subject('1'),
            'iss' => new Issuer('http://example.com'),
            'exp' => new Expiration($testDateTimeImmutable->modify('+3600 seconds')),
            'nbf' => new NotBefore($testDateTimeImmutable),
            'iat' => new IssuedAt($testDateTimeImmutable),
            'jti' => new JwtId('foo'),
        ];

        $payloadTimestamp = new Payload(Collection::make($this->claimsTimestamp), $this->validator);
        $payloadDatetime = new Payload(Collection::make($claimsDatetime), $this->validator);

        $this->assertEquals($payloadTimestamp, $payloadDatetime);
    }

    /**
     * @throws InvalidClaimException
     */
    public function testItShouldHandleDatetintervalClaims(): void
    {
        $testDateInterval = new DateInterval('PT1H');

        $this->assertInstanceOf(DateInterval::class, $testDateInterval);

        $claimsDateInterval = [
            'sub' => new Subject('1'),
            'iss' => new Issuer('http://example.com'),
            'exp' => new Expiration($testDateInterval),
            'nbf' => new NotBefore($this->testNowTimestamp),
            'iat' => new IssuedAt($this->testNowTimestamp),
            'jti' => new JwtId('foo'),
        ];

        $payloadTimestamp = new Payload(Collection::make($this->claimsTimestamp), $this->validator);
        $payloadDateInterval = new Payload(Collection::make($claimsDateInterval), $this->validator);

        $this->assertEquals($payloadTimestamp, $payloadDateInterval);
    }
}
