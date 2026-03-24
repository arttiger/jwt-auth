<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth;

use BadMethodCallException;
use Illuminate\Http\Request;
use ArtTiger\JWTAuth\Contracts\JWTSubject;
use ArtTiger\JWTAuth\Exceptions\JWTException;
use ArtTiger\JWTAuth\Http\Parser\Parser;
use ArtTiger\JWTAuth\Support\CustomClaims;

/**
 * @method mixed setBlacklistEnabled(bool $enabled) Delegates to Manager::setBlacklistEnabled().
 */
class JWT
{
    use CustomClaims;

    /**
     * The token.
     */
    protected ?Token $token = null;

    /**
     * Lock the subject.
     */
    protected bool $lockSubject = true;

    /**
     * JWT constructor.
     *
     * @return void
     */
    public function __construct(
        /**
         * The authentication manager.
         */
        protected Manager $manager,
        /**
         * The HTTP parser.
         */
        protected Parser $parser
    )
    {
    }

    /**
     * Generate a token for a given subject.
     */
    public function fromSubject(JWTSubject $subject): string
    {
        $payload = $this->makePayload($subject);

        return $this->manager->encode($payload)->get();
    }

    /**
     * Alias to generate a token for a given user.
     */
    public function fromUser(JWTSubject $user): string
    {
        return $this->fromSubject($user);
    }

    /**
     * Refresh an expired token.
     */
    public function refresh(bool $forceForever = false, bool $resetClaims = false): string
    {
        $token = $this->requireToken();

        return $this->manager->customClaims($this->getCustomClaims())
            ->refresh($token, $forceForever, $resetClaims)
            ->get();
    }

    /**
     * Invalidate a token (add it to the blacklist).
     */
    public function invalidate(bool $forceForever = false): self
    {
        $token = $this->requireToken();

        $this->manager->invalidate($token, $forceForever);

        return $this;
    }

    /**
     * Alias to get the payload, and as a result checks that
     * the token is valid i.e., not expired or blacklisted.
     *
     * @throws JWTException
     */
    public function checkOrFail(): Payload
    {
        return $this->getPayload();
    }

    /**
     * Check that the token is valid.
     */
    public function check(bool $getPayload = false): bool|Payload
    {
        try {
            $payload = $this->checkOrFail();
        } catch (JWTException) {
            return false;
        }

        return $getPayload ? $payload : true;
    }

    /**
     * Get the token.
     */
    public function getToken(): ?Token
    {
        if ($this->token === null) {
            try {
                $this->parseToken();
            } catch (JWTException) {
                $this->token = null;
            }
        }

        return $this->token;
    }

    /**
     * Parse the token from the request.
     *
     * @throws JWTException
     */
    public function parseToken(): static
    {
        if (! $token = $this->parser->parseToken()) {
            throw new JWTException('The token could not be parsed from the request');
        }

        return $this->setToken($token);
    }

    /**
     * Get the raw Payload instance.
     */
    public function getPayload(): Payload
    {
        $token = $this->requireToken();

        return $this->manager->decode($token);
    }

    /**
     * Alias for getPayload().
     */
    public function payload(): Payload
    {
        return $this->getPayload();
    }

    /**
     * Convenience method to get a claim value.
     */
    public function getClaim(string $claim): mixed
    {
        return $this->payload()->get($claim);
    }

    /**
     * Create a Payload instance.
     */
    public function makePayload(JWTSubject $subject): Payload
    {
        return $this->factory()->customClaims($this->getClaimsArray($subject))->make();
    }

    /**
     * Build the claims array and return it.
     *
     * @return array<string, mixed>
     */
    protected function getClaimsArray(JWTSubject $subject): array
    {
        return array_merge(
            $this->getClaimsForSubject($subject),
            $subject->getJWTCustomClaims(),
            $this->customClaims,
        );
    }

    /**
     * Get the claims associated with a given subject.
     *
     * @return array<string, mixed>
     */
    protected function getClaimsForSubject(JWTSubject $subject): array
    {
        // RFC 7519 §4.1.2: sub MUST be a string
        return array_merge(
            ['sub' => (string) $subject->getJWTIdentifier()],
            $this->lockSubject ? ['prv' => $this->hashSubjectModel($subject)] : []
        );
    }

    /**
     * Hash the subject model and return it.
     */
    protected function hashSubjectModel(string|object $model): string
    {
        return sha1(is_object($model) ? $model::class : $model);
    }

    public function checkSubjectModel(string|object $model): bool
    {
        if (($prv = $this->payload()->get('prv')) === null) {
            return true;
        }

        return $this->hashSubjectModel($model) === $prv;
    }

    public function setToken(Token|string $token): static
    {
        $this->token = $token instanceof Token ? $token : new Token($token);

        return $this;
    }

    public function unsetToken(): static
    {
        $this->token = null;

        return $this;
    }

    /**
     * @throws JWTException
     */
    protected function requireToken(): Token
    {
        if ($this->token === null) {
            throw new JWTException('A token is required');
        }

        return $this->token;
    }

    public function setRequest(Request $request): self
    {
        $this->parser->setRequest($request);

        return $this;
    }

    public function lockSubject(bool $lock): static
    {
        $this->lockSubject = $lock;

        return $this;
    }

    public function manager(): Manager
    {
        return $this->manager;
    }

    public function parser(): Parser
    {
        return $this->parser;
    }

    public function factory(): Factory
    {
        return $this->manager->getPayloadFactory();
    }

    public function blacklist(): Blacklist
    {
        return $this->manager->getBlacklist();
    }

    /**
     * @param array<mixed> $parameters
     *
     * @throws BadMethodCallException
     */
    public function __call(string $method, array $parameters): mixed
    {
        if (method_exists($this->manager, $method)) {
            return $this->manager->$method(...$parameters);
        }

        throw new BadMethodCallException("Method [$method] does not exist.");
    }
}
