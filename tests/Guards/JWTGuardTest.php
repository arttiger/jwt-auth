<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test\Guards;

use ArtTiger\JWTAuth\Exceptions\JWTException;
use ArtTiger\JWTAuth\Exceptions\UserNotDefinedException;
use ArtTiger\JWTAuth\Factory;
use ArtTiger\JWTAuth\Guards\JWTGuard;
use ArtTiger\JWTAuth\JWT;
use ArtTiger\JWTAuth\JWTUserProvider;
use ArtTiger\JWTAuth\Payload;
use ArtTiger\JWTAuth\Test\AbstractTestCase;
use ArtTiger\JWTAuth\Test\Stubs\AuthUserStub;
use ArtTiger\JWTAuth\Token;
use BadMethodCallException;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Support\Timebox;
use Mockery;
use Mockery\MockInterface;

/**
 * Tests for JWTGuard.
 *
 * Strategy:
 * - JWT, JWTUserProvider, Request, and Dispatcher are always mocked.
 * - AuthUserStub implements both Authenticatable and JWTSubject, covering all
 *   code paths that require both interfaces.
 * - `setTimeboxDuration(0)` is called on every guard instance so attempt()
 *   completes without a 200ms delay.
 * - Payload is mocked wherever `get()` / array-access is required, because the
 *   real Payload::toPlainArray() is broken (see project_known_bugs memory).
 */
class JWTGuardTest extends AbstractTestCase
{
    /** @var MockInterface&JWT */
    private MockInterface $jwt;

    /** @var MockInterface&JWTUserProvider */
    private MockInterface $provider;

    /** @var MockInterface&Request */
    private MockInterface $request;

    /** @var MockInterface&Dispatcher */
    private MockInterface $events;

    private JWTGuard $guard;

    private const string VALID_TOKEN = 'header.payload.signature';

    protected function setUp(): void
    {
        parent::setUp();

        $this->jwt      = Mockery::mock(JWT::class);
        $this->provider = Mockery::mock(JWTUserProvider::class);
        $this->request  = Mockery::mock(Request::class);
        $this->events   = Mockery::mock(Dispatcher::class);

        $this->guard = new JWTGuard(
            $this->jwt,
            $this->provider,
            $this->request,
            $this->events,
        );

        // Disable the 200ms timing floor so tests run fast.
        $this->guard->setTimeboxDuration(0);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private function makeToken(string $value = self::VALID_TOKEN): Token
    {
        return new Token($value);
    }

    /**
     * Build a mocked Payload that handles both get('sub') (used in getUserId)
     * and offsetGet('sub') (used in user() via array-access $payload['sub']).
     */
    private function makePayloadMock(int|string $subValue = 1): MockInterface
    {
        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('get')->with('sub')->andReturn($subValue);
        $payload->shouldReceive('offsetGet')->with('sub')->andReturn($subValue);

        return $payload;
    }

    /**
     * Set up the jwt mock so that user() can succeed:
     *   setRequest → getToken → check(true) → validateSubject chain.
     */
    private function setupValidTokenFlow(MockInterface $payload): void
    {
        $token = $this->makeToken();

        $this->jwt->shouldReceive('setRequest')->with($this->request)->andReturnSelf();
        $this->jwt->shouldReceive('getToken')->andReturn($token);
        $this->jwt->shouldReceive('check')->with(true)->andReturn($payload);
        $this->provider->shouldReceive('getModel')->andReturn(AuthUserStub::class);
        $this->jwt->shouldReceive('checkSubjectModel')->with(AuthUserStub::class)->andReturn(true);
    }

    // -------------------------------------------------------------------------
    // user()
    // -------------------------------------------------------------------------

    public function testUserReturnsNullWhenNoTokenInRequest(): void
    {
        $this->jwt->shouldReceive('setRequest')->with($this->request)->andReturnSelf();
        $this->jwt->shouldReceive('getToken')->andReturn(null);

        $result = $this->guard->user();

        $this->assertNull($result);
    }

    public function testUserReturnsUserWhenValidTokenValidPayloadAndValidSubject(): void
    {
        $user    = new AuthUserStub(1);
        $payload = $this->makePayloadMock(1);

        $this->setupValidTokenFlow($payload);
        $this->provider->shouldReceive('retrieveById')->with(1)->andReturn($user);

        $result = $this->guard->user();

        $this->assertSame($user, $result);
    }

    public function testUserCachesResultAndOnlyCallsProviderOnce(): void
    {
        $user    = new AuthUserStub(1);
        $payload = $this->makePayloadMock(1);

        $this->setupValidTokenFlow($payload);
        // retrieveById must only be called once even though user() is called twice.
        $this->provider->shouldReceive('retrieveById')->with(1)->once()->andReturn($user);

        $first  = $this->guard->user();
        $second = $this->guard->user();

        $this->assertSame($user, $first);
        $this->assertSame($user, $second);
    }

    public function testUserReturnsNullWhenCheckFails(): void
    {
        $token = $this->makeToken();

        $this->jwt->shouldReceive('setRequest')->with($this->request)->andReturnSelf();
        $this->jwt->shouldReceive('getToken')->andReturn($token);
        $this->jwt->shouldReceive('check')->with(true)->andReturn(false);

        $result = $this->guard->user();

        $this->assertNull($result);
    }

    public function testUserReturnsNullWhenSubjectValidationFails(): void
    {
        $token   = $this->makeToken();
        $payload = $this->makePayloadMock(1);

        $this->jwt->shouldReceive('setRequest')->with($this->request)->andReturnSelf();
        $this->jwt->shouldReceive('getToken')->andReturn($token);
        $this->jwt->shouldReceive('check')->with(true)->andReturn($payload);
        $this->provider->shouldReceive('getModel')->andReturn(AuthUserStub::class);
        $this->jwt->shouldReceive('checkSubjectModel')->with(AuthUserStub::class)->andReturn(false);

        $result = $this->guard->user();

        $this->assertNull($result);
    }

    // -------------------------------------------------------------------------
    // userOrFail()
    // -------------------------------------------------------------------------

    public function testUserOrFailThrowsUserNotDefinedExceptionWhenNoUser(): void
    {
        $this->jwt->shouldReceive('setRequest')->with($this->request)->andReturnSelf();
        $this->jwt->shouldReceive('getToken')->andReturn(null);

        $this->expectException(UserNotDefinedException::class);

        $this->guard->userOrFail();
    }

    public function testUserOrFailReturnsUserWhenUserResolved(): void
    {
        $user    = new AuthUserStub(1);
        $payload = $this->makePayloadMock(1);

        $this->setupValidTokenFlow($payload);
        $this->provider->shouldReceive('retrieveById')->with(1)->andReturn($user);

        $result = $this->guard->userOrFail();

        $this->assertSame($user, $result);
    }

    // -------------------------------------------------------------------------
    // getUserId() / id()
    // -------------------------------------------------------------------------

    public function testGetUserIdReturnsIdentifierFromCachedUser(): void
    {
        $user = new AuthUserStub(7);

        // Pre-set the user so the cached path is taken.
        // setUser fires Authenticated event.
        $this->events->shouldReceive('dispatch')->with(Mockery::type(Authenticated::class));
        $this->guard->setUser($user);

        $result = $this->guard->getUserId();

        $this->assertSame(7, $result);
    }

    public function testGetUserIdReturnsSubFromPayloadWhenNoCachedUser(): void
    {
        $payload = $this->makePayloadMock(42);

        $this->setupValidTokenFlow($payload);

        $result = $this->guard->getUserId();

        $this->assertSame(42, $result);
    }

    public function testGetUserIdReturnsNullWhenNoToken(): void
    {
        $this->jwt->shouldReceive('setRequest')->with($this->request)->andReturnSelf();
        $this->jwt->shouldReceive('getToken')->andReturn(null);

        $result = $this->guard->getUserId();

        $this->assertNull($result);
    }

    public function testIdIsAliasForGetUserId(): void
    {
        $this->jwt->shouldReceive('setRequest')->with($this->request)->andReturnSelf();
        $this->jwt->shouldReceive('getToken')->andReturn(null);

        $this->assertNull($this->guard->id());
    }

    // -------------------------------------------------------------------------
    // validate()
    // -------------------------------------------------------------------------

    public function testValidateReturnsFalseWhenNoUserFound(): void
    {
        $credentials = ['email' => 'a@b.com', 'password' => 'wrong'];

        $this->events->shouldReceive('dispatch')->with(Mockery::type(Attempting::class));
        $this->provider->shouldReceive('retrieveByCredentials')->with($credentials)->andReturn(null);
        $this->events->shouldReceive('dispatch')->with(Mockery::type(Failed::class));

        $result = $this->guard->validate($credentials);

        $this->assertFalse($result);
    }

    public function testValidateReturnsTrueForValidCredentials(): void
    {
        $user        = new AuthUserStub();
        $credentials = ['email' => 'a@b.com', 'password' => 'correct'];

        $this->events->shouldReceive('dispatch')->with(Mockery::type(Attempting::class));
        $this->provider->shouldReceive('retrieveByCredentials')->with($credentials)->andReturn($user);
        $this->provider->shouldReceive('validateCredentials')->with($user, $credentials)->andReturn(true);
        $this->events->shouldReceive('dispatch'); // Validated + possibly others
        $this->provider->shouldReceive('rehashPasswordIfRequired');

        $result = $this->guard->validate($credentials);

        $this->assertTrue($result);
    }

    // -------------------------------------------------------------------------
    // attempt()
    // -------------------------------------------------------------------------

    public function testAttemptWithLoginTrueReturnsTokenStringForValidJWTSubjectUser(): void
    {
        $user        = new AuthUserStub();
        $credentials = ['email' => 'a@b.com', 'password' => 'correct'];
        $token       = self::VALID_TOKEN;

        $this->events->shouldReceive('dispatch')->with(Mockery::type(Attempting::class));
        $this->provider->shouldReceive('retrieveByCredentials')->with($credentials)->andReturn($user);
        $this->provider->shouldReceive('validateCredentials')->with($user, $credentials)->andReturn(true);
        $this->events->shouldReceive('dispatch'); // Validated, Authenticated, Login
        $this->provider->shouldReceive('rehashPasswordIfRequired');
        $this->jwt->shouldReceive('fromUser')->with($user)->andReturn($token);
        $this->jwt->shouldReceive('setToken')->with($token)->andReturnSelf();

        $result = $this->guard->attempt($credentials, login: true);

        $this->assertSame($token, $result);
    }

    public function testAttemptWithLoginFalseReturnsTrueForValidCredentials(): void
    {
        $user        = new AuthUserStub();
        $credentials = ['email' => 'a@b.com', 'password' => 'correct'];

        $this->events->shouldReceive('dispatch')->with(Mockery::type(Attempting::class));
        $this->provider->shouldReceive('retrieveByCredentials')->with($credentials)->andReturn($user);
        $this->provider->shouldReceive('validateCredentials')->with($user, $credentials)->andReturn(true);
        $this->events->shouldReceive('dispatch'); // Validated
        $this->provider->shouldReceive('rehashPasswordIfRequired');

        $result = $this->guard->attempt($credentials, login: false);

        $this->assertTrue($result);
    }

    public function testAttemptReturnsFalseAndFiresFailedEventForInvalidCredentials(): void
    {
        $credentials = ['email' => 'a@b.com', 'password' => 'wrong'];

        $this->events->shouldReceive('dispatch')->with(Mockery::type(Attempting::class))->once();
        $this->provider->shouldReceive('retrieveByCredentials')->with($credentials)->andReturn(null);
        $this->events->shouldReceive('dispatch')->with(Mockery::type(Failed::class))->once();

        $result = $this->guard->attempt($credentials);

        $this->assertFalse($result);
    }

    // -------------------------------------------------------------------------
    // attemptWhen()
    // -------------------------------------------------------------------------

    public function testAttemptWhenReturnsFalseWhenCallbackReturnsFalse(): void
    {
        $user        = new AuthUserStub();
        $credentials = ['email' => 'a@b.com', 'password' => 'correct'];
        $callback    = fn (Authenticatable $u) => false;

        $this->events->shouldReceive('dispatch')->with(Mockery::type(Attempting::class));
        $this->provider->shouldReceive('retrieveByCredentials')->with($credentials)->andReturn($user);
        $this->provider->shouldReceive('validateCredentials')->with($user, $credentials)->andReturn(true);
        $this->events->shouldReceive('dispatch')->with(Mockery::type(Failed::class));
        $this->events->shouldReceive('dispatch'); // Validated

        $result = $this->guard->attemptWhen($credentials, $callback, login: true);

        $this->assertFalse($result);
    }

    public function testAttemptWhenReturnsTokenWhenCredentialsValidAndCallbackPasses(): void
    {
        $user        = new AuthUserStub();
        $credentials = ['email' => 'a@b.com', 'password' => 'correct'];
        $callback    = fn (Authenticatable $u) => true;
        $token       = self::VALID_TOKEN;

        $this->events->shouldReceive('dispatch')->with(Mockery::type(Attempting::class));
        $this->provider->shouldReceive('retrieveByCredentials')->with($credentials)->andReturn($user);
        $this->provider->shouldReceive('validateCredentials')->with($user, $credentials)->andReturn(true);
        $this->events->shouldReceive('dispatch'); // Validated, Authenticated, Login
        $this->provider->shouldReceive('rehashPasswordIfRequired');
        $this->jwt->shouldReceive('fromUser')->with($user)->andReturn($token);
        $this->jwt->shouldReceive('setToken')->with($token)->andReturnSelf();

        $result = $this->guard->attemptWhen($credentials, $callback, login: true);

        $this->assertSame($token, $result);
    }

    // -------------------------------------------------------------------------
    // login()
    // -------------------------------------------------------------------------

    public function testLoginReturnsTokenStringSetsUserAndFiresLoginEvent(): void
    {
        $user  = new AuthUserStub();
        $token = self::VALID_TOKEN;

        $this->jwt->shouldReceive('fromUser')->with($user)->once()->andReturn($token);
        $this->jwt->shouldReceive('setToken')->with($token)->once()->andReturnSelf();
        $this->events->shouldReceive('dispatch')->with(Mockery::type(Authenticated::class))->once();
        $this->events->shouldReceive('dispatch')->with(Mockery::type(Login::class))->once();

        $result = $this->guard->login($user);

        $this->assertSame($token, $result);
        $this->assertSame($user, $this->guard->getUser());
    }

    // -------------------------------------------------------------------------
    // logout()
    // -------------------------------------------------------------------------

    public function testLogoutCallsInvalidateFiresLogoutEventAndClearsUser(): void
    {
        $user  = new AuthUserStub();
        $token = $this->makeToken();

        // Pre-set the user so logout has something to clear.
        $this->events->shouldReceive('dispatch')->with(Mockery::type(Authenticated::class));
        $this->guard->setUser($user);

        // requireToken() path: setRequest → getToken
        $this->jwt->shouldReceive('setRequest')->with($this->request)->andReturnSelf();
        $this->jwt->shouldReceive('getToken')->andReturn($token);
        $this->jwt->shouldReceive('invalidate')->with(false)->once()->andReturnSelf();
        $this->events->shouldReceive('dispatch')->with(Mockery::type(Logout::class))->once();
        $this->jwt->shouldReceive('unsetToken')->once();

        $this->guard->logout();

        $this->assertNull($this->guard->getUser());
    }

    public function testLogoutSucceedsEvenIfInvalidateThrowsJWTException(): void
    {
        $user  = new AuthUserStub();
        $token = $this->makeToken();

        $this->events->shouldReceive('dispatch')->with(Mockery::type(Authenticated::class));
        $this->guard->setUser($user);

        $this->jwt->shouldReceive('setRequest')->with($this->request)->andReturnSelf();
        $this->jwt->shouldReceive('getToken')->andReturn($token);
        $this->jwt->shouldReceive('invalidate')->andThrow(new JWTException('Blacklist unavailable'));
        $this->events->shouldReceive('dispatch')->with(Mockery::type(Logout::class))->once();
        $this->jwt->shouldReceive('unsetToken')->once();

        // Must not throw even though invalidate threw.
        $this->guard->logout();

        $this->assertNull($this->guard->getUser());
    }

    // -------------------------------------------------------------------------
    // once()
    // -------------------------------------------------------------------------

    public function testOnceReturnsFalseWhenValidateFails(): void
    {
        $credentials = ['email' => 'a@b.com', 'password' => 'wrong'];

        $this->events->shouldReceive('dispatch')->with(Mockery::type(Attempting::class));
        $this->provider->shouldReceive('retrieveByCredentials')->with($credentials)->andReturn(null);
        $this->events->shouldReceive('dispatch')->with(Mockery::type(Failed::class));

        $result = $this->guard->once($credentials);

        $this->assertFalse($result);
    }

    public function testOnceReturnsTrueAndSetsUserWhenValidatePasses(): void
    {
        $user        = new AuthUserStub();
        $credentials = ['email' => 'a@b.com', 'password' => 'correct'];

        // validate() calls attempt(login=false), which calls retrieveByCredentials +
        // validateCredentials internally, then once() uses lastAttempted.
        $this->events->shouldReceive('dispatch')->with(Mockery::type(Attempting::class));
        $this->provider->shouldReceive('retrieveByCredentials')->with($credentials)->andReturn($user);
        $this->provider->shouldReceive('validateCredentials')->with($user, $credentials)->andReturn(true);
        $this->events->shouldReceive('dispatch'); // Validated, Authenticated
        $this->provider->shouldReceive('rehashPasswordIfRequired');

        $result = $this->guard->once($credentials);

        $this->assertTrue($result);
        $this->assertSame($user, $this->guard->getUser());
    }

    // -------------------------------------------------------------------------
    // onceUsingId() / byId()
    // -------------------------------------------------------------------------

    public function testOnceUsingIdReturnsUserWhenProviderFindsIt(): void
    {
        $user = new AuthUserStub(5);

        $this->provider->shouldReceive('retrieveById')->with(5)->once()->andReturn($user);
        $this->events->shouldReceive('dispatch')->with(Mockery::type(Authenticated::class));

        $result = $this->guard->onceUsingId(5);

        $this->assertSame($user, $result);
        $this->assertSame($user, $this->guard->getUser());
    }

    public function testOnceUsingIdReturnsFalseWhenProviderReturnsNull(): void
    {
        $this->provider->shouldReceive('retrieveById')->with(999)->once()->andReturn(null);

        $result = $this->guard->onceUsingId(999);

        $this->assertFalse($result);
    }

    public function testByIdIsAliasForOnceUsingId(): void
    {
        $user = new AuthUserStub(3);

        $this->provider->shouldReceive('retrieveById')->with(3)->once()->andReturn($user);
        $this->events->shouldReceive('dispatch')->with(Mockery::type(Authenticated::class));

        $result = $this->guard->byId(3);

        $this->assertSame($user, $result);
    }

    // -------------------------------------------------------------------------
    // setUser() / getUser()
    // -------------------------------------------------------------------------

    public function testSetUserFiresAuthenticatedEvent(): void
    {
        $user = new AuthUserStub();

        $this->events->shouldReceive('dispatch')
            ->with(Mockery::type(Authenticated::class))
            ->once();

        $this->guard->setUser($user);
    }

    public function testSetUserGetUserRoundTrip(): void
    {
        $user = new AuthUserStub(99);

        $this->events->shouldReceive('dispatch')->with(Mockery::type(Authenticated::class));
        $this->guard->setUser($user);

        $this->assertSame($user, $this->guard->getUser());
    }

    // -------------------------------------------------------------------------
    // getRequest() / setRequest()
    // -------------------------------------------------------------------------

    public function testSetRequestGetRequestRoundTrip(): void
    {
        $newRequest = Request::create('/new', 'GET');

        $this->guard->setRequest($newRequest);

        $this->assertSame($newRequest, $this->guard->getRequest());
    }

    // -------------------------------------------------------------------------
    // getProvider() / setProvider()
    // -------------------------------------------------------------------------

    public function testGetProviderSetProviderRoundTrip(): void
    {
        $newProvider = Mockery::mock(JWTUserProvider::class);

        $result = $this->guard->setProvider($newProvider);

        $this->assertSame($this->guard, $result);
        $this->assertSame($newProvider, $this->guard->getProvider());
    }

    // -------------------------------------------------------------------------
    // getLastAttempted()
    // -------------------------------------------------------------------------

    public function testGetLastAttemptedReturnsTheUserFromLastAttemptCall(): void
    {
        $user        = new AuthUserStub();
        $credentials = ['email' => 'a@b.com', 'password' => 'wrong'];

        $this->events->shouldReceive('dispatch')->with(Mockery::type(Attempting::class));
        $this->provider->shouldReceive('retrieveByCredentials')->with($credentials)->andReturn($user);
        $this->provider->shouldReceive('validateCredentials')->with($user, $credentials)->andReturn(false);
        $this->events->shouldReceive('dispatch')->with(Mockery::type(Failed::class));

        $this->guard->attempt($credentials);

        $this->assertSame($user, $this->guard->getLastAttempted());
    }

    // -------------------------------------------------------------------------
    // tokenById()
    // -------------------------------------------------------------------------

    public function testTokenByIdReturnsTokenStringForJWTSubjectUser(): void
    {
        $user  = new AuthUserStub(10);
        $token = self::VALID_TOKEN;

        $this->provider->shouldReceive('retrieveById')->with(10)->andReturn($user);
        $this->jwt->shouldReceive('fromUser')->with($user)->andReturn($token);

        $result = $this->guard->tokenById(10);

        $this->assertSame($token, $result);
    }

    public function testTokenByIdReturnsNullForUserThatIsNotJWTSubject(): void
    {
        // A plain Authenticatable that does not implement JWTSubject.
        $plainUser = Mockery::mock(Authenticatable::class);

        $this->provider->shouldReceive('retrieveById')->with(20)->andReturn($plainUser);

        $result = $this->guard->tokenById(20);

        $this->assertNull($result);
    }

    public function testTokenByIdReturnsNullWhenProviderCannotFindUser(): void
    {
        $this->provider->shouldReceive('retrieveById')->with(999)->andReturn(null);

        $result = $this->guard->tokenById(999);

        $this->assertNull($result);
    }

    // -------------------------------------------------------------------------
    // claims()
    // -------------------------------------------------------------------------

    public function testClaimsDelegatesToJWTInstanceAndReturnsSelf(): void
    {
        $claims = ['custom' => 'value'];

        $this->jwt->shouldReceive('claims')->with($claims)->once()->andReturnSelf();

        $result = $this->guard->claims($claims);

        $this->assertSame($this->guard, $result);
    }

    // -------------------------------------------------------------------------
    // getTTL() / setTTL()
    // -------------------------------------------------------------------------

    public function testGetTTLDelegatesToJWTFactory(): void
    {
        $factory = Mockery::mock(Factory::class);
        $factory->shouldReceive('getTTL')->once()->andReturn(60);
        $this->jwt->shouldReceive('factory')->andReturn($factory);

        $result = $this->guard->getTTL();

        $this->assertSame(60, $result);
    }

    public function testSetTTLDelegatesToJWTFactoryAndReturnsSelf(): void
    {
        $factory = Mockery::mock(Factory::class);
        $factory->shouldReceive('setTTL')->with(120)->once()->andReturnSelf();
        $this->jwt->shouldReceive('factory')->andReturn($factory);

        $result = $this->guard->setTTL(120);

        $this->assertSame($this->guard, $result);
    }

    // -------------------------------------------------------------------------
    // getPayload() / payload()
    // -------------------------------------------------------------------------

    public function testGetPayloadDelegatesToJWT(): void
    {
        $payload = Mockery::mock(Payload::class);
        $token   = $this->makeToken();

        $this->jwt->shouldReceive('setRequest')->with($this->request)->andReturnSelf();
        $this->jwt->shouldReceive('getToken')->andReturn($token);
        $this->jwt->shouldReceive('getPayload')->once()->andReturn($payload);

        $result = $this->guard->getPayload();

        $this->assertSame($payload, $result);
    }

    public function testPayloadIsAliasForGetPayload(): void
    {
        $payload = Mockery::mock(Payload::class);
        $token   = $this->makeToken();

        $this->jwt->shouldReceive('setRequest')->with($this->request)->andReturnSelf();
        $this->jwt->shouldReceive('getToken')->andReturn($token);
        $this->jwt->shouldReceive('getPayload')->once()->andReturn($payload);

        $result = $this->guard->payload();

        $this->assertSame($payload, $result);
    }

    // -------------------------------------------------------------------------
    // refresh()
    // -------------------------------------------------------------------------

    public function testRefreshDelegatesToJWT(): void
    {
        $token      = $this->makeToken();
        $newToken   = 'new.refreshed.token';

        $this->jwt->shouldReceive('setRequest')->with($this->request)->andReturnSelf();
        $this->jwt->shouldReceive('getToken')->andReturn($token);
        $this->jwt->shouldReceive('refresh')->with(false, false)->once()->andReturn($newToken);

        $result = $this->guard->refresh();

        $this->assertSame($newToken, $result);
    }

    // -------------------------------------------------------------------------
    // invalidate()
    // -------------------------------------------------------------------------

    public function testInvalidateDelegatesToJWTAndReturnsJWTInstance(): void
    {
        $token = $this->makeToken();

        $this->jwt->shouldReceive('setRequest')->with($this->request)->andReturnSelf();
        $this->jwt->shouldReceive('getToken')->andReturn($token);
        $this->jwt->shouldReceive('invalidate')->with(false)->once()->andReturnSelf();

        $result = $this->guard->invalidate();

        $this->assertSame($this->jwt, $result);
    }

    // -------------------------------------------------------------------------
    // __call() — magic delegation
    // -------------------------------------------------------------------------

    public function testMagicCallDelegatesUnknownMethodsToJWTInstance(): void
    {
        // lockSubject() is a real public method on JWT that is not directly
        // exposed on JWTGuard, so the guard's __call will delegate it.
        $this->jwt->shouldReceive('lockSubject')->with(false)->once()->andReturnSelf();

        // Call via __call() to satisfy PHPStan (method is not declared on JWTGuard).
        $result = $this->guard->__call('lockSubject', [false]);

        $this->assertSame($this->jwt, $result);
    }

    public function testMagicCallThrowsBadMethodCallExceptionForTrulyUnknownMethod(): void
    {
        $this->expectException(BadMethodCallException::class);
        $this->expectExceptionMessage('totallyUnknownMethod');

        $this->guard->__call('totallyUnknownMethod', []);
    }

    // -------------------------------------------------------------------------
    // setTimeboxDuration() / getTimebox()
    // -------------------------------------------------------------------------

    public function testSetTimeboxDurationUpdatesTheDuration(): void
    {
        $result = $this->guard->setTimeboxDuration(500_000);

        $this->assertSame($this->guard, $result);
    }

    public function testGetTimeboxReturnsTimeboxInstance(): void
    {
        $timebox = $this->guard->getTimebox();

        $this->assertInstanceOf(Timebox::class, $timebox);
    }
}
