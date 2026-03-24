<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test;

use ArtTiger\JWTAuth\JWTUserProvider;
use ArtTiger\JWTAuth\Test\Stubs\AuthUserStub;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Mockery;
use Mockery\MockInterface;

/**
 * Tests for JWTUserProvider.
 *
 * JWTUserProvider is a thin delegation wrapper around an arbitrary UserProvider.
 * It explicitly disables remember-token semantics (retrieveByToken always returns
 * null; updateRememberToken is a no-op) and adds getModel() / getProvider() helpers.
 */
class JWTUserProviderTest extends AbstractTestCase
{
    /** @var MockInterface&UserProvider */
    private MockInterface $inner;

    private JWTUserProvider $provider;

    protected function setUp(): void
    {
        parent::setUp();

        $this->inner    = Mockery::mock(UserProvider::class);
        $this->provider = new JWTUserProvider($this->inner);
    }

    // -------------------------------------------------------------------------
    // retrieveById
    // -------------------------------------------------------------------------

    public function testRetrieveByIdDelegatesToInnerProvider(): void
    {
        $user = new AuthUserStub(42);

        $this->inner->shouldReceive('retrieveById')
            ->with(42)
            ->once()
            ->andReturn($user);

        $result = $this->provider->retrieveById(42);

        $this->assertSame($user, $result);
    }

    public function testRetrieveByIdReturnsNullWhenInnerReturnsNull(): void
    {
        $this->inner->shouldReceive('retrieveById')
            ->with(99)
            ->once()
            ->andReturn(null);

        $result = $this->provider->retrieveById(99);

        $this->assertNull($result);
    }

    // -------------------------------------------------------------------------
    // retrieveByToken — JWT never uses remember tokens
    // -------------------------------------------------------------------------

    public function testRetrieveByTokenAlwaysReturnsNull(): void
    {
        // Inner provider must NOT be called for this operation.
        $this->inner->shouldNotReceive('retrieveByToken');

        $result = $this->provider->retrieveByToken(1, 'any-token-value');

        $this->assertNull($result);
    }

    public function testRetrieveByTokenReturnsNullRegardlessOfIdentifier(): void
    {
        $this->inner->shouldNotReceive('retrieveByToken');

        $result = $this->provider->retrieveByToken('string-id', 'token');

        $this->assertNull($result);
    }

    // -------------------------------------------------------------------------
    // updateRememberToken — intentional no-op
    // -------------------------------------------------------------------------

    public function testUpdateRememberTokenIsNoOp(): void
    {
        $user = new AuthUserStub();

        // The inner provider's updateRememberToken must never be invoked.
        $this->inner->shouldNotReceive('updateRememberToken');

        // Should complete without error and return nothing.
        $this->provider->updateRememberToken($user, 'new-token');

        // Reaching this line confirms the no-op contract holds.
        // Mockery verifies shouldNotReceive in tearDown.
        $this->addToAssertionCount(1);
    }

    // -------------------------------------------------------------------------
    // retrieveByCredentials
    // -------------------------------------------------------------------------

    public function testRetrieveByCredentialsDelegatesToInnerProvider(): void
    {
        $credentials = ['email' => 'user@example.com', 'password' => 'secret'];
        $user        = new AuthUserStub();

        $this->inner->shouldReceive('retrieveByCredentials')
            ->with($credentials)
            ->once()
            ->andReturn($user);

        $result = $this->provider->retrieveByCredentials($credentials);

        $this->assertSame($user, $result);
    }

    public function testRetrieveByCredentialsReturnsNullWhenInnerReturnsNull(): void
    {
        $credentials = ['email' => 'nobody@example.com', 'password' => 'wrong'];

        $this->inner->shouldReceive('retrieveByCredentials')
            ->with($credentials)
            ->once()
            ->andReturn(null);

        $result = $this->provider->retrieveByCredentials($credentials);

        $this->assertNull($result);
    }

    // -------------------------------------------------------------------------
    // validateCredentials
    // -------------------------------------------------------------------------

    public function testValidateCredentialsDelegatesToInnerProviderAndReturnsTrueOnSuccess(): void
    {
        $user        = new AuthUserStub();
        $credentials = ['password' => 'correct'];

        $this->inner->shouldReceive('validateCredentials')
            ->with($user, $credentials)
            ->once()
            ->andReturn(true);

        $result = $this->provider->validateCredentials($user, $credentials);

        $this->assertTrue($result);
    }

    public function testValidateCredentialsDelegatesToInnerProviderAndReturnsFalseOnFailure(): void
    {
        $user        = new AuthUserStub();
        $credentials = ['password' => 'wrong'];

        $this->inner->shouldReceive('validateCredentials')
            ->with($user, $credentials)
            ->once()
            ->andReturn(false);

        $result = $this->provider->validateCredentials($user, $credentials);

        $this->assertFalse($result);
    }

    // -------------------------------------------------------------------------
    // rehashPasswordIfRequired
    // -------------------------------------------------------------------------

    public function testRehashPasswordIfRequiredDelegatesToInnerProvider(): void
    {
        $user        = new AuthUserStub();
        $credentials = ['password' => 'correct'];

        $this->inner->shouldReceive('rehashPasswordIfRequired')
            ->with($user, $credentials, false)
            ->once();

        $this->provider->rehashPasswordIfRequired($user, $credentials);

        // Mockery verifies the once() expectation in tearDown.
        $this->addToAssertionCount(1);
    }

    public function testRehashPasswordIfRequiredPassesForceFlag(): void
    {
        $user        = new AuthUserStub();
        $credentials = ['password' => 'correct'];

        $this->inner->shouldReceive('rehashPasswordIfRequired')
            ->with($user, $credentials, true)
            ->once();

        $this->provider->rehashPasswordIfRequired($user, $credentials, force: true);

        $this->addToAssertionCount(1);
    }

    // -------------------------------------------------------------------------
    // getModel
    // -------------------------------------------------------------------------

    public function testGetModelReturnsModelClassNameWhenInnerProviderHasGetModel(): void
    {
        // Use an anonymous class to simulate an Eloquent UserProvider with getModel().
        $innerWithModel = new class implements UserProvider {
            public function retrieveById(mixed $identifier): ?Authenticatable { return null; }
            public function retrieveByToken(mixed $identifier, mixed $token): ?Authenticatable { return null; }
            public function updateRememberToken(Authenticatable $user, mixed $token): void {}
            /** @param array<string, mixed> $credentials */
            public function retrieveByCredentials(array $credentials): ?Authenticatable { return null; }
            /** @param array<string, mixed> $credentials */
            public function validateCredentials(Authenticatable $user, array $credentials): bool { return false; }
            /** @param array<string, mixed> $credentials */
            public function rehashPasswordIfRequired(Authenticatable $user, array $credentials, bool $force = false): void {}
            public function getModel(): string { return AuthUserStub::class; }
        };

        $provider = new JWTUserProvider($innerWithModel);

        $this->assertSame(AuthUserStub::class, $provider->getModel());
    }

    public function testGetModelReturnsEmptyStringWhenInnerProviderLacksGetModel(): void
    {
        // $this->inner is a mock of the bare UserProvider contract, which has no getModel().
        $result = $this->provider->getModel();

        $this->assertSame('', $result);
    }

    // -------------------------------------------------------------------------
    // getProvider
    // -------------------------------------------------------------------------

    public function testGetProviderReturnsWrappedInnerProvider(): void
    {
        $result = $this->provider->getProvider();

        $this->assertSame($this->inner, $result);
    }
}
