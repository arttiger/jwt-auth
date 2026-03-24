<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test;

use ArtTiger\JWTAuth\Blacklist;
use ArtTiger\JWTAuth\Contracts\Providers\Storage;
use ArtTiger\JWTAuth\Payload;
use Mockery;

class BlacklistTest extends AbstractTestCase
{
    private Storage $storage;
    private Blacklist $blacklist;

    protected function setUp(): void
    {
        parent::setUp();

        $this->storage = Mockery::mock(Storage::class);
        $this->blacklist = new Blacklist($this->storage);
    }

    /**
     * Create a mocked Payload configured to simulate a normal token with an exp claim.
     */
    private function mockPayloadWithJti(string $jti = 'test-jti-id', bool $hasExp = true, ?int $expValue = null, ?int $iatValue = null): Payload
    {
        $now = $this->testNowTimestamp;
        $payload = Mockery::mock(Payload::class);

        // getKey() calls $payload($this->key) = __invoke('jti') = get('jti')
        $payload->shouldReceive('__invoke')->with('jti')->andReturn($jti);

        // hasKey is used in add() to check for 'exp'
        $payload->shouldReceive('hasKey')->with('exp')->andReturn($hasExp);

        // get() is called in getMinutesUntilExpired for 'exp' and 'iat'
        $expVal = $expValue ?? ($now + 3600);
        $iatVal = $iatValue ?? $now;
        $payload->shouldReceive('get')->with('exp')->andReturn($hasExp ? $expVal : null);
        $payload->shouldReceive('get')->with('iat')->andReturn($iatVal);

        return $payload;
    }

    public function testAddCallsStorageAddWithJtiKey(): void
    {
        $payload = $this->mockPayloadWithJti('test-jti-id', hasExp: true);

        $this->storage->shouldReceive('get')->with('test-jti-id')->once()->andReturn(null);
        $this->storage->shouldReceive('add')
            ->once()
            ->withArgs(function (string $key, array $value, int $minutes): bool {
                return $key === 'test-jti-id'
                    && isset($value['valid_until'])
                    && is_int($value['valid_until'])
                    && $minutes > 0;
            });

        $result = $this->blacklist->add($payload);

        $this->assertTrue($result);
    }

    public function testAddReturnsTrueWhenTokenAlreadyInStorage(): void
    {
        $payload = $this->mockPayloadWithJti('test-jti-id', hasExp: true);

        // Token already in storage
        $this->storage->shouldReceive('get')->with('test-jti-id')->once()->andReturn(['valid_until' => 12345]);
        $this->storage->shouldNotReceive('add');

        $result = $this->blacklist->add($payload);

        $this->assertTrue($result);
    }

    public function testAddCallsAddForeverWhenNoExpClaim(): void
    {
        $payload = $this->mockPayloadWithJti('test-jti-id', hasExp: false);

        $this->storage->shouldReceive('forever')->with('test-jti-id', 'forever')->once();

        $result = $this->blacklist->add($payload);

        $this->assertTrue($result);
    }

    public function testAddForeverCallsStorageForever(): void
    {
        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('__invoke')->with('jti')->andReturn('test-jti-id');

        $this->storage->shouldReceive('forever')->with('test-jti-id', 'forever')->once();

        $result = $this->blacklist->addForever($payload);

        $this->assertTrue($result);
    }

    public function testHasReturnsTrueForForeverBlacklistedToken(): void
    {
        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('__invoke')->with('jti')->andReturn('test-jti-id');

        $this->storage->shouldReceive('get')->with('test-jti-id')->andReturn('forever');

        $this->assertTrue($this->blacklist->has($payload));
    }

    public function testHasReturnsFalseWhenGracePeriodIsActiveAndValidUntilIsInFuture(): void
    {
        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('__invoke')->with('jti')->andReturn('test-jti-id');

        // valid_until is in the future → grace period still active → not yet blacklisted
        $futureTimestamp = $this->testNowTimestamp + 60;
        $this->storage->shouldReceive('get')->with('test-jti-id')->andReturn(['valid_until' => $futureTimestamp]);

        $this->assertFalse($this->blacklist->has($payload));
    }

    public function testHasReturnsTrueWhenValidUntilIsInPast(): void
    {
        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('__invoke')->with('jti')->andReturn('test-jti-id');

        // valid_until is in the past → grace period ended → IS blacklisted
        $pastTimestamp = $this->testNowTimestamp - 60;
        $this->storage->shouldReceive('get')->with('test-jti-id')->andReturn(['valid_until' => $pastTimestamp]);

        $this->assertTrue($this->blacklist->has($payload));
    }

    public function testHasReturnsFalseWhenStorageReturnsNull(): void
    {
        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('__invoke')->with('jti')->andReturn('test-jti-id');

        $this->storage->shouldReceive('get')->with('test-jti-id')->andReturn(null);

        $this->assertFalse($this->blacklist->has($payload));
    }

    public function testHasReturnsFalseWhenStorageReturnsEmptyArray(): void
    {
        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('__invoke')->with('jti')->andReturn('test-jti-id');

        $this->storage->shouldReceive('get')->with('test-jti-id')->andReturn([]);

        $this->assertFalse($this->blacklist->has($payload));
    }

    public function testHasReturnsFalseWhenStorageReturnsArrayWithoutValidUntil(): void
    {
        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('__invoke')->with('jti')->andReturn('test-jti-id');

        $this->storage->shouldReceive('get')->with('test-jti-id')->andReturn(['other_key' => 'value']);

        $this->assertFalse($this->blacklist->has($payload));
    }

    public function testRemoveCallsStorageDestroy(): void
    {
        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('__invoke')->with('jti')->andReturn('test-jti-id');

        $this->storage->shouldReceive('destroy')->with('test-jti-id')->once()->andReturn(true);

        $result = $this->blacklist->remove($payload);

        $this->assertTrue($result);
    }

    public function testClearCallsStorageFlush(): void
    {
        $this->storage->shouldReceive('flush')->once();

        $result = $this->blacklist->clear();

        $this->assertTrue($result);
    }

    public function testGetGracePeriodReturnsDefaultZero(): void
    {
        $this->assertSame(0, $this->blacklist->getGracePeriod());
    }

    public function testSetGracePeriodUpdatesGracePeriod(): void
    {
        $this->blacklist->setGracePeriod(30);

        $this->assertSame(30, $this->blacklist->getGracePeriod());
    }

    public function testGetRefreshTtlReturnsDefault(): void
    {
        $this->assertSame(20160, $this->blacklist->getRefreshTTL());
    }

    public function testSetRefreshTtlUpdatesRefreshTtl(): void
    {
        $this->blacklist->setRefreshTTL(1440);

        $this->assertSame(1440, $this->blacklist->getRefreshTTL());
    }

    public function testSetKeyChangesKeyUsedForLookup(): void
    {
        $this->blacklist->setKey('sub');

        $payload = Mockery::mock(Payload::class);
        // Now the blacklist uses 'sub' as the key
        $payload->shouldReceive('__invoke')->with('sub')->andReturn('user-1');

        $this->storage->shouldReceive('forever')->with('user-1', 'forever')->once();

        $this->blacklist->addForever($payload);
    }

    public function testAddWithGracePeriodSetsValidUntilInFuture(): void
    {
        $this->blacklist->setGracePeriod(30);
        $expectedValidUntil = $this->testNowTimestamp + 30;

        $payload = $this->mockPayloadWithJti('test-jti-id', hasExp: true);

        $this->storage->shouldReceive('get')->with('test-jti-id')->once()->andReturn(null);
        $this->storage->shouldReceive('add')
            ->once()
            ->withArgs(function (string $key, array $value, int $minutes) use ($expectedValidUntil): bool {
                return $key === 'test-jti-id' && $value['valid_until'] === $expectedValidUntil;
            });

        $this->blacklist->add($payload);
    }

    public function testGetKeyReturnsEmptyStringWhenInvokeReturnsNonString(): void
    {
        // Blacklist::getKey returns '' when payload invocation returns non-string
        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('__invoke')->with('jti')->andReturn(null);

        $key = $this->blacklist->getKey($payload);

        $this->assertSame('', $key);
    }
}
