<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test;

use ArtTiger\JWTAuth\Abstracts\Claim;
use ArtTiger\JWTAuth\Collections\ClaimCollection;
use ArtTiger\JWTAuth\Claims\Expiration;
use ArtTiger\JWTAuth\Claims\IssuedAt;
use ArtTiger\JWTAuth\Claims\Issuer;
use ArtTiger\JWTAuth\Claims\JwtId;
use ArtTiger\JWTAuth\Claims\NotBefore;
use ArtTiger\JWTAuth\Claims\Subject;
use Carbon\Carbon;
use Mockery;
use PHPUnit\Framework\TestCase;

abstract class AbstractTestCase extends TestCase
{
    protected int $testNowTimestamp;

    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow('2024-01-01 00:00:00');
        $this->testNowTimestamp = Carbon::now()->getTimestamp();
    }

    protected function tearDown(): void
    {
        Mockery::close();
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * Build a string-keyed array of Claim instances suitable for
     * passing directly to `new Collection([...])`.
     *
     * @param array<string, Claim> $overrides  Claim instances to replace defaults.
     * @return array<string, Claim>
     */
    protected function makeValidClaims(array $overrides = []): array
    {
        $now = $this->testNowTimestamp;

        $defaults = [
            'sub' => new Subject('1'),
            'iss' => new Issuer('https://example.com'),
            'iat' => new IssuedAt($now),
            'exp' => new Expiration($now + 3600),
            'nbf' => new NotBefore($now),
            'jti' => new JwtId('test-jti-id'),
        ];

        foreach ($overrides as $key => $value) {
            $defaults[$key] = $value;
        }

        return $defaults;
    }

    /**
     * Build a Collection from the valid claim set, with optional overrides.
     *
     * @param array<string, Claim> $overrides
     */
    protected function makeValidCollection(array $overrides = []): ClaimCollection
    {
        return new ClaimCollection($this->makeValidClaims($overrides));
    }
}
