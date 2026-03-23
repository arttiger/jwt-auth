<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test;

use Carbon\Carbon;
use Mockery;
use PHPUnit\Framework\TestCase;

abstract class AbstractTestCase extends TestCase
{
    protected int $testNowTimestamp;

    public function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow($now = Carbon::now());
        $this->testNowTimestamp = $now->getTimestamp();
    }

    public function tearDown(): void
    {
        Carbon::setTestNow();
        Mockery::close();

        parent::tearDown();
    }
}
