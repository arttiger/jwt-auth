<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use SensitiveParameter;

/**
 * A thin UserProvider wrapper that delegates all storage operations to an
 * underlying Eloquent (or any other) UserProvider while explicitly making
 * clear that JWT-based guards do not use Laravel's remember-token mechanism.
 *
 * Injected into JWTGuard so that the guard always receives a concrete
 * JWTUserProvider rather than the raw UserProvider contract — this lets us
 * add JWT-specific behaviour (e.g. model-hash validation) without coupling
 * the guard to Eloquent directly.
 */
class JWTUserProvider implements UserProvider
{
    public function __construct(private readonly UserProvider $provider)
    {
    }

    /**
     * Retrieve a user by their unique identifier.
     * Called by JWTGuard::user() after the JWT sub claim is extracted.
     */
    public function retrieveById(mixed $identifier): ?Authenticatable
    {
        return $this->provider->retrieveById($identifier);
    }

    /**
     * JWT does not use Laravel's remember-token mechanism.
     * Always returns null so the framework falls back gracefully.
     */
    public function retrieveByToken(mixed $identifier, #[SensitiveParameter] mixed $token): ?Authenticatable
    {
        return null;
    }

    /**
     * JWT does not use remember tokens — this is intentionally a no-op.
     */
    public function updateRememberToken(Authenticatable $user, #[SensitiveParameter] mixed $token): void
    {
        // no-op: JWT auth is stateless and does not need remember tokens
    }

    /**
     * Retrieve a user by their credentials.
     * Delegates to the underlying provider so that credential-based attempts
     * (login with email + password) continue to work through JWTGuard::attempt().
     *
     * @param array<string, mixed> $credentials
     */
    public function retrieveByCredentials(#[SensitiveParameter] array $credentials): ?Authenticatable
    {
        return $this->provider->retrieveByCredentials($credentials);
    }

    /**
     * Validate the given user against a set of credentials.
     *
     * @param array<string, mixed> $credentials
     */
    public function validateCredentials(Authenticatable $user, #[SensitiveParameter] array $credentials): bool
    {
        return $this->provider->validateCredentials($user, $credentials);
    }

    /**
     * Re-hashes the user's password if the hashing algorithm has changed.
     * Delegates to the underlying provider when supported (Laravel 11+).
     *
     * @param array<string, mixed> $credentials
     */
    public function rehashPasswordIfRequired(
        Authenticatable $user,
        #[SensitiveParameter] array $credentials,
        bool $force = false,
    ): void {
        $this->provider->rehashPasswordIfRequired($user, $credentials, $force);
    }

    /**
     * Return the Eloquent model class name, when available.
     * Used by JWTGuard::validateSubject() to hash and compare the prv claim.
     */
    public function getModel(): string
    {
        if (method_exists($this->provider, 'getModel')) {
            /** @var string $model */
            $model = $this->provider->getModel();

            return $model;
        }

        return '';
    }

    /**
     * Expose the underlying provider for cases where callers need direct access.
     */
    public function getProvider(): UserProvider
    {
        return $this->provider;
    }
}
