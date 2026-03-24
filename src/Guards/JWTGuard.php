<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Guards;

use ArtTiger\JWTAuth\Contracts\JWTSubject;
use SensitiveParameter;
use ArtTiger\JWTAuth\Exceptions\JWTException;
use ArtTiger\JWTAuth\Exceptions\UserNotDefinedException;
use ArtTiger\JWTAuth\JWT;
use ArtTiger\JWTAuth\JWTUserProvider;
use ArtTiger\JWTAuth\Payload;
use ArtTiger\JWTAuth\Token;
use BadMethodCallException;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\Events\Validated;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Timebox;
use Illuminate\Support\Traits\Macroable;

class JWTGuard implements Guard
{
    use GuardHelpers {
        setUser as guardHelperSetUser;
    }
    use Macroable {
        __call as macroCall;
    }

    /**
     * The user provider implementation.
     *
     * @var JWTUserProvider
     */
    protected $provider;

    /**
     * The user we last attempted to retrieve.
     */
    protected ?Authenticatable $lastAttempted = null;

    /**
     * The name of the Guard.
     */
    protected string $name = 'arttiger.jwt';

    private Timebox $timebox;

    /**
     * Minimum duration (µs) that attempt() will always consume to prevent
     * timing-based user-enumeration attacks (mirrors SessionGuard).
     */
    protected int $timeboxDuration = 200_000;

    public function __construct(
        protected JWT $jwt,
        JWTUserProvider $provider,
        protected Request $request,
        protected Dispatcher $events,
    ) {
        $this->provider = $provider;
        $this->timebox  = new Timebox();
    }

    // -------------------------------------------------------------------------
    // User retrieval
    // -------------------------------------------------------------------------

    public function user(): ?Authenticatable
    {
        if (! is_null($this->user)) {
            return $this->user;
        }

        if (
            $this->jwt->setRequest($this->request)->getToken() instanceof Token
            && ($payload = $this->jwt->check(true)) instanceof Payload
            && $this->validateSubject()
        ) {
            return $this->user = $this->provider->retrieveById($payload['sub']);
        }

        return null;
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

    public function getUserId(): int|string|null
    {
        if (null !== $this->user) {
            $id = $this->user->getAuthIdentifier();

            return is_string($id) || is_int($id) ? $id : null;
        }

        if (
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

    // -------------------------------------------------------------------------
    // Authentication attempts
    // -------------------------------------------------------------------------

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
        return $this->timebox->call(function (Timebox $timebox) use ($credentials, $login) {
            $this->fireAttemptEvent($credentials);

            $this->lastAttempted = $this->provider->retrieveByCredentials($credentials);
            $user = $this->lastAttempted;

            if ($this->hasValidCredentials($user, $credentials)) {
                $this->rehashPasswordIfRequired($user, $credentials);

                if ($login && $user instanceof JWTSubject && $user instanceof Authenticatable) {
                    $token = $this->login($user);
                    $timebox->returnEarly();

                    return $token;
                }

                $timebox->returnEarly();

                return true;
            }

            $this->fireFailedEvent($user, $credentials);

            return false;
        }, $this->timeboxDuration);
    }

    /**
     * Attempt to authenticate a user with credentials and additional callbacks.
     *
     * Useful for extra checks after credential validation, e.g. email verified,
     * account not banned, 2FA passed, etc. — without modifying the guard itself.
     *
     * Example:
     *   $guard->attemptWhen($credentials, fn ($user) => $user->hasVerifiedEmail());
     *
     * @param array<string, mixed>        $credentials
     * @param callable|callable[]|null    $callbacks
     */
    public function attemptWhen(
        array $credentials = [],
        callable|array|null $callbacks = null,
        bool $login = true,
    ): bool|string {
        return $this->timebox->call(function (Timebox $timebox) use ($credentials, $callbacks, $login) {
            $this->fireAttemptEvent($credentials);

            $this->lastAttempted = $this->provider->retrieveByCredentials($credentials);
            $user = $this->lastAttempted;

            if (
                $user instanceof Authenticatable
                && $this->hasValidCredentials($user, $credentials)
                && $this->shouldLogin($callbacks, $user)
            ) {
                $this->rehashPasswordIfRequired($user, $credentials);

                if ($login && $user instanceof JWTSubject) {
                    $token = $this->login($user);
                    $timebox->returnEarly();

                    return $token;
                }

                $timebox->returnEarly();

                return true;
            }

            $this->fireFailedEvent($user, $credentials);

            return false;
        }, $this->timeboxDuration);
    }

    // -------------------------------------------------------------------------
    // Login / logout
    // -------------------------------------------------------------------------

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
            // Proceed with logout even if the token cannot be invalidated.
        }

        $this->fireLogoutEvent($this->user);

        $this->user = null;
        $this->jwt->unsetToken();
    }

    // -------------------------------------------------------------------------
    // Stateless / one-time login
    // -------------------------------------------------------------------------

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

    /**
     * Log a user in by their ID without issuing a JWT token.
     * Returns the user on success, false otherwise.
     */
    public function onceUsingId(int|string $id): Authenticatable|false
    {
        if ($user = $this->provider->retrieveById($id)) {
            $this->setUser($user);

            return $user;
        }

        return false;
    }

    /**
     * Alias for onceUsingId().
     */
    public function byId(int|string $id): Authenticatable|false
    {
        return $this->onceUsingId($id);
    }

    // -------------------------------------------------------------------------
    // Token helpers
    // -------------------------------------------------------------------------

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

    public function setToken(Token|string $token): self
    {
        $this->jwt->setToken($token);

        return $this;
    }

    // -------------------------------------------------------------------------
    // Payload / claims
    // -------------------------------------------------------------------------

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

    // -------------------------------------------------------------------------
    // TTL
    // -------------------------------------------------------------------------

    public function getTTL(): ?int
    {
        return $this->jwt->factory()->getTTL();
    }

    public function setTTL(?int $ttl): self
    {
        $this->jwt->factory()->setTTL($ttl);

        return $this;
    }

    // -------------------------------------------------------------------------
    // Getters / setters
    // -------------------------------------------------------------------------

    public function getProvider(): JWTUserProvider
    {
        return $this->provider;
    }

    public function setProvider(JWTUserProvider $provider): self
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

    public function getTimebox(): Timebox
    {
        return $this->timebox;
    }

    public function setTimeboxDuration(int $microseconds): self
    {
        $this->timeboxDuration = $microseconds;

        return $this;
    }

    // -------------------------------------------------------------------------
    // Protected helpers
    // -------------------------------------------------------------------------

    /**
     * @param array<string, mixed> $credentials
     */
    protected function hasValidCredentials(?Authenticatable $user, array $credentials): bool
    {
        $validated = $user instanceof Authenticatable
            && $this->provider->validateCredentials($user, $credentials);

        if ($validated) {
            $this->fireValidatedEvent($user);
        }

        return $validated;
    }

    /**
     * Determine if the user should proceed by running all given callbacks.
     *
     * @param callable|callable[]|null $callbacks
     */
    protected function shouldLogin(callable|array|null $callbacks, Authenticatable $user): bool
    {
        foreach (Arr::wrap($callbacks) as $callback) {
            if (! $callback($user, $this)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Rehash the password using the provider if needed.
     *
     * @param array<string, mixed> $credentials
     */
    protected function rehashPasswordIfRequired(
        ?Authenticatable $user,
        #[SensitiveParameter] array $credentials,
    ): void {
        if (!$user instanceof Authenticatable) {
            return;
        }

        if (method_exists($this->provider, 'rehashPasswordIfRequired')) {
            $this->provider->rehashPasswordIfRequired($user, $credentials);
        }
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
        if (! $this->jwt->setRequest($this->getRequest())->getToken() instanceof Token) {
            throw new JWTException(message: 'Token could not be parsed from the request.');
        }

        return $this->jwt;
    }

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    /**
     * @param array<string, mixed> $credentials
     */
    protected function fireAttemptEvent(array $credentials): void
    {
        $this->events->dispatch(new Attempting($this->name, $credentials, false));
    }

    protected function fireValidatedEvent(Authenticatable $user): void
    {
        $this->events->dispatch(new Validated($this->name, $user));
    }

    /**
     * @param array<string, mixed> $credentials
     */
    protected function fireFailedEvent(?Authenticatable $user, array $credentials): void
    {
        $this->events->dispatch(new Failed($this->name, $user, $credentials));
    }

    protected function fireAuthenticatedEvent(Authenticatable $user): void
    {
        $this->events->dispatch(new Authenticated($this->name, $user));
    }

    protected function fireLoginEvent(Authenticatable $user, bool $remember = false): void
    {
        $this->events->dispatch(new Login($this->name, $user, $remember));
    }

    protected function fireLogoutEvent(?Authenticatable $user): void
    {
        if (! $user instanceof Authenticatable) {
            return;
        }

        $this->events->dispatch(new Logout($this->name, $user));
    }

    // -------------------------------------------------------------------------
    // Magic
    // -------------------------------------------------------------------------

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
