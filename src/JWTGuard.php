<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth;

use Illuminate\Auth\Events\Validated;
use BadMethodCallException;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Support\Traits\Macroable;
use ArtTiger\JWTAuth\Contracts\JWTSubject;
use ArtTiger\JWTAuth\Exceptions\JWTException;
use ArtTiger\JWTAuth\Exceptions\UserNotDefinedException;
use ArtTiger\JWTAuth\Payload;

/**
 * @mixin JWT
 */
class JWTGuard implements Guard
{
    use GuardHelpers {
        setUser as guardHelperSetUser;
    }

    use Macroable {
        __call as macroCall;
    }

    /**
     * The user we last attempted to retrieve.
     */
    protected ?Authenticatable $lastAttempted = null;

    /**
     * The name of the Guard.
     */
    protected string $name = 'arttiger.jwt';

    public function __construct(
        protected JWT $jwt,
        UserProvider $provider,
        protected Request $request,
        protected Dispatcher $events,
    ) {
        $this->provider = $provider;
    }

    public function user(): ?Authenticatable
    {
        if (null !== $this->user) {
            return $this->user;
        }

        if (
            # order make sense!
            $this->jwt->setRequest($this->request)->getToken() instanceof Token
            && ($payload = $this->jwt->check(true)) instanceof Payload
            && $this->validateSubject()
        ) {
            return $this->user = $this->provider->retrieveById($payload['sub']);
        }

        return null;
    }

    public function getUserId(): int|string|null
    {
        if (null !== $this->user) {
            $id = $this->user->getAuthIdentifier();

            return is_string($id) || is_int($id) ? $id : null;
        }

        if (
            # order make sense!
            $this->jwt->setRequest($this->request)->getToken() instanceof Token
            && ($payload = $this->jwt->check(true)) instanceof Payload
            && $this->validateSubject()
        ) {
            $sub = $payload->get('sub');

            return is_string($sub) || is_int($sub) ? $sub : null;
        }

        return null;
    }

    public function id(): int|string|null
    {
        return $this->getUserId();
    }

    /**
     * @throws UserNotDefinedException
     */
    public function userOrFail(): Authenticatable
    {
        if (! ($user = $this->user()) instanceof Authenticatable) {
            throw new UserNotDefinedException();
        }

        return $user;
    }

    /**
     * @param array<string, mixed> $credentials
     */
    public function validate(array $credentials = []): bool
    {
        return (bool) $this->attempt(credentials: $credentials, login: false);
    }

    /**
     * @param array<string, mixed> $credentials
     */
    public function attempt(array $credentials = [], bool $login = true): bool|string
    {
        $this->lastAttempted = $this->provider->retrieveByCredentials($credentials);
        $user = $this->lastAttempted;
        $this->fireAttemptEvent($credentials);

        if ($this->hasValidCredentials($user, $credentials)) {
            if ($login && $user instanceof JWTSubject && $user instanceof Authenticatable) {
                return $this->login($user);
            }

            return true;
        }

        $this->fireFailedEvent($user, $credentials);

        return false;
    }

    public function login(JWTSubject&Authenticatable $user): string
    {
        $token = $this->jwt->fromUser($user);
        $this->setToken($token)->setUser($user);

        $this->fireLoginEvent($user);

        return $token;
    }

    public function logout(bool $forceForever = false): void
    {
        try {
            $this->requireToken()->invalidate($forceForever);
        } catch (JWTException) {
            // Proceed with the logout as normal if we can't invalidate the token
        }

        $this->fireLogoutEvent($this->user);

        $this->user = null;
        $this->jwt->unsetToken();
    }

    public function refresh(bool $forceForever = false, bool $resetClaims = false): string
    {
        return $this->requireToken()->refresh($forceForever, $resetClaims);
    }

    public function invalidate(bool $forceForever = false): JWT
    {
        return $this->requireToken()->invalidate($forceForever);
    }

    public function tokenById(int|string $id): ?string
    {
        $user = $this->provider->retrieveById($id);
        if ($user instanceof JWTSubject) {
            return $this->jwt->fromUser($user);
        }

        return null;
    }

    /**
     * @param array<string, mixed> $credentials
     */
    public function once(array $credentials = []): bool
    {
        if ($this->validate($credentials)) {
            $user = $this->lastAttempted ?? $this->provider->retrieveByCredentials($credentials);
            if ($user !== null) {
                $this->setUser($user);
            }

            return true;
        }

        return false;
    }

    public function onceUsingId(int|string $id): bool
    {
        if ($user = $this->provider->retrieveById($id)) {
            $this->setUser($user);

            return true;
        }

        return false;
    }

    public function byId(int|string $id): bool
    {
        return $this->onceUsingId($id);
    }

    /**
     * @param array<string, mixed> $claims
     */
    public function claims(array $claims): self
    {
        $this->jwt->claims($claims);

        return $this;
    }

    public function getPayload(): Payload
    {
        return $this->requireToken()->getPayload();
    }

    public function payload(): Payload
    {
        return $this->getPayload();
    }

    public function setToken(Token|string $token): self
    {
        $this->jwt->setToken($token);

        return $this;
    }

    public function getTTL(): ?int
    {
        return $this->jwt->factory()->getTTL();
    }

    public function setTTL(?int $ttl): self
    {
        $this->jwt->factory()->setTTL($ttl);

        return $this;
    }

    public function getProvider(): UserProvider
    {
        return $this->provider;
    }

    public function setProvider(UserProvider $provider): self
    {
        $this->provider = $provider;

        return $this;
    }

    public function getUser(): ?Authenticatable
    {
        return $this->user;
    }

    public function setUser(Authenticatable $user): self
    {
        $result = $this->guardHelperSetUser($user);

        $this->fireAuthenticatedEvent($user);

        return $result;
    }

    public function getRequest(): Request
    {
        return $this->request;
    }

    public function setRequest(Request $request): self
    {
        $this->request = $request;

        return $this;
    }

    public function getLastAttempted(): ?Authenticatable
    {
        return $this->lastAttempted;
    }

    /**
     * @param array<string, mixed> $credentials
     */
    protected function hasValidCredentials(?Authenticatable $user, array $credentials): bool
    {
        $validated = $user instanceof Authenticatable && $this->provider->validateCredentials($user, $credentials);

        if ($validated) {
            $this->fireValidatedEvent($user);
        }

        return $validated;
    }

    protected function validateSubject(): bool
    {
        if (! method_exists($this->provider, 'getModel')) {
            return true;
        }

        $model = $this->provider->getModel();
        if (! is_string($model) && ! is_object($model)) {
            return true;
        }

        return $this->jwt->checkSubjectModel($model);
    }

    /**
     * @throws JWTException
     */
    protected function requireToken(): JWT
    {
        if (!$this->jwt->setRequest($this->getRequest())->getToken() instanceof Token) {
            throw new JWTException(message: 'Token could not be parsed from the request.');
        }

        return $this->jwt;
    }

    /**
     * @param array<string, mixed> $credentials
     */
    protected function fireAttemptEvent(array $credentials): void
    {
        $this->events->dispatch(new Attempting(
            $this->name,
            $credentials,
            false
        ));
    }

    protected function fireValidatedEvent(Authenticatable $user): void
    {
        if (class_exists(Validated::class)) {
            $this->events->dispatch(
                new Validated(
                    $this->name,
                    $user
                )
            );
        }
    }

    /**
     * @param array<string, mixed> $credentials
     */
    protected function fireFailedEvent(?Authenticatable $user, array $credentials): void
    {
        $this->events->dispatch(new Failed(
            $this->name,
            $user,
            $credentials
        ));
    }

    protected function fireAuthenticatedEvent(Authenticatable $user): void
    {
        $this->events->dispatch(new Authenticated(
            $this->name,
            $user
        ));
    }

    protected function fireLoginEvent(Authenticatable $user, bool $remember = false): void
    {
        $this->events->dispatch(new Login(
            $this->name,
            $user,
            $remember
        ));
    }

    protected function fireLogoutEvent(?Authenticatable $user): void
    {
        if (!$user instanceof Authenticatable) {
            return;
        }

        $this->events->dispatch(new Logout(
            $this->name,
            $user
        ));
    }

    /**
     * @param array<mixed> $parameters
     *
     * @throws BadMethodCallException
     */
    public function __call(string $method, array $parameters): mixed
    {
        if (method_exists($this->jwt, $method)) {
            return $this->jwt->$method(...$parameters);
        }

        if (static::hasMacro($method)) {
            return $this->macroCall($method, $parameters);
        }

        throw new BadMethodCallException(message: "Method [$method] does not exist.");
    }
}
