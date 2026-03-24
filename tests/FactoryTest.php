<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test;

use ArtTiger\JWTAuth\Claims\Collection;
use ArtTiger\JWTAuth\Claims\Expiration;
use ArtTiger\JWTAuth\Claims\Factory as ClaimFactory;
use ArtTiger\JWTAuth\Claims\IssuedAt;
use ArtTiger\JWTAuth\Claims\Issuer;
use ArtTiger\JWTAuth\Claims\JwtId;
use ArtTiger\JWTAuth\Claims\NotBefore;
use ArtTiger\JWTAuth\Claims\Subject;
use ArtTiger\JWTAuth\Factory;
use ArtTiger\JWTAuth\Payload;
use ArtTiger\JWTAuth\Validators\PayloadValidator;
use Mockery;
use Mockery\MockInterface;

class FactoryTest extends AbstractTestCase
{
    private MockInterface&ClaimFactory $claimFactory;
    private MockInterface&PayloadValidator $validator;
    private Factory $factory;

    protected function setUp(): void
    {
        parent::setUp();

        $this->claimFactory = Mockery::mock(ClaimFactory::class);
        $this->validator = Mockery::mock(PayloadValidator::class);
        $this->factory = new Factory($this->claimFactory, $this->validator);
    }

    private function setupClaimFactoryForValidPayload(): void
    {
        $now = $this->testNowTimestamp;

        $this->claimFactory->shouldReceive('getTTL')->andReturn(60);
        $this->claimFactory->shouldReceive('make')->with('iss')->andReturn(new Issuer('https://example.com'));
        $this->claimFactory->shouldReceive('make')->with('iat')->andReturn(new IssuedAt($now));
        $this->claimFactory->shouldReceive('make')->with('exp')->andReturn(new Expiration($now + 3600));
        $this->claimFactory->shouldReceive('make')->with('nbf')->andReturn(new NotBefore($now));
        $this->claimFactory->shouldReceive('make')->with('jti')->andReturn(new JwtId('test-jti'));
        $this->claimFactory->shouldReceive('get')->andReturnUsing(
            function (string $name, mixed $value): \ArtTiger\JWTAuth\Abstracts\Claim {
                $strVal = is_scalar($value) ? (string) $value : '';

                return match ($name) {
                    'sub' => new Subject($strVal),
                    default => new \ArtTiger\JWTAuth\Claims\Custom($name, $value),
                };
            }
        );

        $this->validator->shouldReceive('setRefreshFlow')->andReturnSelf();
        $this->validator->shouldReceive('validateCollection')->andReturn(null);
    }

    public function testMakeReturnsPayloadInstance(): void
    {
        $this->setupClaimFactoryForValidPayload();

        $payload = $this->factory->make();

        $this->assertInstanceOf(Payload::class, $payload);
    }

    public function testMakeWithResetClaimsEmptiesStagingBeforeBuilding(): void
    {
        $this->setupClaimFactoryForValidPayload();

        // Add a custom claim first
        $this->factory->customClaims(['custom' => 'value']);

        // make(true) should reset and not include the custom claim
        $payload = $this->factory->make(true);

        $this->assertInstanceOf(Payload::class, $payload);
    }

    public function testCustomClaimsSetsCustomClaimsArray(): void
    {
        $this->factory->customClaims(['sub' => '42']);

        // Verify via getCustomClaims() that the value was stored
        $this->assertSame(['sub' => '42'], $this->factory->getCustomClaims());
    }

    public function testClaimsIsAliasForCustomClaims(): void
    {
        $result = $this->factory->claims(['foo' => 'bar']);

        $this->assertSame($this->factory, $result);
        $this->assertSame(['foo' => 'bar'], $this->factory->getCustomClaims());
    }

    public function testSetTtlDelegatesToClaimFactory(): void
    {
        $this->claimFactory->shouldReceive('setTTL')->with(120)->once()->andReturnSelf();

        $result = $this->factory->setTTL(120);

        $this->assertSame($this->factory, $result);
    }

    public function testGetTtlDelegatesToClaimFactory(): void
    {
        $this->claimFactory->shouldReceive('getTTL')->once()->andReturn(90);

        $this->assertSame(90, $this->factory->getTTL());
    }

    public function testGetDefaultClaimsReturnsDefaultArray(): void
    {
        $defaults = $this->factory->getDefaultClaims();

        $this->assertContains('iss', $defaults);
        $this->assertContains('iat', $defaults);
        $this->assertContains('exp', $defaults);
        $this->assertContains('nbf', $defaults);
        $this->assertContains('jti', $defaults);
    }

    public function testSetDefaultClaimsChangesDefaults(): void
    {
        $this->factory->setDefaultClaims(['iss', 'iat']);

        $this->assertSame(['iss', 'iat'], $this->factory->getDefaultClaims());
    }

    public function testEmptyClaimsClearsStagingCollection(): void
    {
        $this->factory->customClaims(['foo' => 'bar']);

        $result = $this->factory->emptyClaims();

        $this->assertSame($this->factory, $result);
        // After emptyClaims, customClaims are still in the customClaims array,
        // but the staging collection is cleared. We verify by making sure
        // a subsequent make() builds from scratch.
        $this->setupClaimFactoryForValidPayload();
        $payload = $this->factory->make();
        $this->assertInstanceOf(Payload::class, $payload);
    }

    public function testMagicCallReturnsSelf(): void
    {
        // Magic __call adds to the internal staging collection, not to customClaims.
        // Verify that it returns $this for fluent chaining.
        $result = $this->factory->__call('role', ['admin']);

        $this->assertSame($this->factory, $result);
    }

    public function testMagicCallAddedClaimAppearsInBuildClaimsCollection(): void
    {
        $now = $this->testNowTimestamp;

        $this->claimFactory->shouldReceive('getTTL')->andReturn(60);
        $this->claimFactory->shouldReceive('make')->with('iss')->andReturn(new \ArtTiger\JWTAuth\Claims\Issuer('https://example.com'));
        $this->claimFactory->shouldReceive('make')->with('iat')->andReturn(new \ArtTiger\JWTAuth\Claims\IssuedAt($now));
        $this->claimFactory->shouldReceive('make')->with('exp')->andReturn(new \ArtTiger\JWTAuth\Claims\Expiration($now + 3600));
        $this->claimFactory->shouldReceive('make')->with('nbf')->andReturn(new \ArtTiger\JWTAuth\Claims\NotBefore($now));
        $this->claimFactory->shouldReceive('make')->with('jti')->andReturn(new \ArtTiger\JWTAuth\Claims\JwtId('test-jti'));
        $this->claimFactory->shouldReceive('get')
            ->with('role', 'admin')
            ->andReturn(new \ArtTiger\JWTAuth\Claims\Custom('role', 'admin'));

        $this->factory->__call('role', ['admin']);
        $collection = $this->factory->buildClaimsCollection();

        $this->assertNotNull($collection->getByClaimName('role'));
        $this->assertSame('admin', $collection->getByClaimName('role')->getValue());
    }

    public function testWithClaimsReturnsPayloadFromCollection(): void
    {
        $collection = $this->makeValidCollection();

        $this->validator->shouldReceive('setRefreshFlow')->andReturnSelf();
        $this->validator->shouldReceive('validateCollection')->andReturn(null);

        $payload = $this->factory->withClaims($collection);

        $this->assertInstanceOf(Payload::class, $payload);
    }

    public function testValidatorReturnsPayloadValidatorInstance(): void
    {
        $this->assertSame($this->validator, $this->factory->validator());
    }

    public function testMakeWithNullTtlOmitsExpClaim(): void
    {
        $now = $this->testNowTimestamp;

        $this->claimFactory->shouldReceive('getTTL')->andReturn(null);
        // When TTL is null, 'exp' is removed from defaultClaims before iteration
        $this->claimFactory->shouldReceive('make')->with('iss')->andReturn(new Issuer('https://example.com'));
        $this->claimFactory->shouldReceive('make')->with('iat')->andReturn(new IssuedAt($now));
        $this->claimFactory->shouldReceive('make')->with('nbf')->andReturn(new NotBefore($now));
        $this->claimFactory->shouldReceive('make')->with('jti')->andReturn(new JwtId('test-jti'));
        $this->claimFactory->shouldReceive('get')->andReturnUsing(
            fn (string $name, mixed $value) => new \ArtTiger\JWTAuth\Claims\Custom($name, $value)
        );

        $this->validator->shouldReceive('setRefreshFlow')->andReturnSelf();
        $this->validator->shouldReceive('validateCollection')->andReturn(null);

        $payload = $this->factory->make();

        // No exp claim in payload
        $this->assertNull($payload->get('exp'));
    }

    public function testBuildClaimsCollectionReturnsCollection(): void
    {
        $now = $this->testNowTimestamp;

        $this->claimFactory->shouldReceive('getTTL')->andReturn(60);
        $this->claimFactory->shouldReceive('make')->with('iss')->andReturn(new Issuer('https://example.com'));
        $this->claimFactory->shouldReceive('make')->with('iat')->andReturn(new IssuedAt($now));
        $this->claimFactory->shouldReceive('make')->with('exp')->andReturn(new Expiration($now + 3600));
        $this->claimFactory->shouldReceive('make')->with('nbf')->andReturn(new NotBefore($now));
        $this->claimFactory->shouldReceive('make')->with('jti')->andReturn(new JwtId('test-jti'));

        $collection = $this->factory->buildClaimsCollection();

        $this->assertInstanceOf(Collection::class, $collection);
    }
}
