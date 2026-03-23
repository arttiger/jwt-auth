<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth;

use BadMethodCallException;
use Illuminate\Http\Request;
use ArtTiger\JWTAuth\Contracts\JWTSubject;
use ArtTiger\JWTAuth\Exceptions\JWTException;
use ArtTiger\JWTAuth\Http\Parser\Parser;
use ArtTiger\JWTAuth\Support\CustomClaims;

class JWT
{
    use CustomClaims;

    /**
     * The authentication manager.
     */
    protected Manager $manager;

    /**
     * The HTTP parser.
     */
    protected Parser $parser;

    /**
     * The token.
     */
    protected ?Token $token;

    /**
     * Lock the subject.
     */
    protected bool $lockSubject = true;

    /**
     * JWT constructor.
     *
     * @return void
     */
    public function __construct(Manager $manager, Parser $parser)
    {
        $this->manager = $manager;
        $this->parser = $parser;
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
        $this->requireToken();

        return $this->manager->customClaims($this->getCustomClaims())
            ->refresh($this->token, $forceForever, $resetClaims)
            ->get();
    }

    /**
     * Invalidate a token (add it to the blacklist).
     */
    public function invalidate(bool $forceForever = false): static
    {
        $this->requireToken();

        $this->manager->invalidate($this->token, $forceForever);

        return $this;
    }

    /**
     * Alias to get the payload, and as a result checks that
     * the token is valid i.e. not expired or blacklisted.
     *
     * @return Payload
     *
     * @throws JWTException
     */
    public function checkOrFail()
    {
        return $this->getPayload();
    }

    /**
     * Check that the token is valid.
     *
     * @param bool $getPayload
     *
     * @return Payload|bool
     */
    public function check($getPayload = false)
    {
        try {
            $payload = $this->checkOrFail();
        } catch (JWTException $e) {
            return false;
        }

        return $getPayload ? $payload : true;
    }

    /**
     * Get the token.
     */
    public function getToken(): ?Token
    {
        if (null === $this->token) {
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
            throw new JWTException(message: 'The token could not be parsed from the request');
        }

        return $this->setToken($token);
    }

    /**
     * Get the raw Payload instance.
     */
    public function getPayload(): Payload
    {
        $this->requireToken();

        return $this->manager->decode($this->token);
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
    public function getClaim(string $claim)
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
     * @return array
     */
    protected function getClaimsArray(JWTSubject $subject)
    {
        return array_merge(
            $this->getClaimsForSubject($subject),
            $subject->getJWTCustomClaims(), // custom claims from JWTSubject method
            $this->customClaims // custom claims from inline setter
        );
    }

    /**
     * Get the claims associated with a given subject.
     *
     * @return array
     */
    protected function getClaimsForSubject(JWTSubject $subject)
    {
        return array_merge([
            'sub' => $subject->getJWTIdentifier(),
        ], $this->lockSubject ? ['prv' => $this->hashSubjectModel($subject)] : []);
    }

    /**
     * Hash the subject model and return it.
     *
     * @param string|object $model
     *
     * @return string
     */
    protected function hashSubjectModel($model)
    {
        return sha1(is_object($model) ? get_class($model) : $model);
    }

    /**
     * Check if the subject model matches the one saved in the token.
     *
     * @param string|object $model
     *
     * @return bool
     */
    public function checkSubjectModel($model)
    {
        if (($prv = $this->payload()->get('prv')) === null) {
            return true;
        }

        return $this->hashSubjectModel($model) === $prv;
    }

    /**
     * Set the token.
     *
     * @param Token|string $token
     *
     * @return $this
     */
    public function setToken($token)
    {
        $this->token = $token instanceof Token ? $token : new Token($token);

        return $this;
    }

    /**
     * Unset the current token.
     *
     * @return $this
     */
    public function unsetToken()
    {
        $this->token = null;

        return $this;
    }

    /**
     * Ensure that a token is available.
     *
     * @return void
     *
     * @throws JWTException
     */
    protected function requireToken()
    {
        if (!$this->token) {
            throw new JWTException('A token is required');
        }
    }

    /**
     * Set the request instance.
     *
     * @return $this
     */
    public function setRequest(Request $request)
    {
        $this->parser->setRequest($request);

        return $this;
    }

    /**
     * Set whether the subject should be "locked".
     *
     * @param bool $lock
     *
     * @return $this
     */
    public function lockSubject($lock)
    {
        $this->lockSubject = $lock;

        return $this;
    }

    /**
     * Get the Manager instance.
     *
     * @return Manager
     */
    public function manager()
    {
        return $this->manager;
    }

    /**
     * Get the Parser instance.
     *
     * @return Parser
     */
    public function parser()
    {
        return $this->parser;
    }

    /**
     * Get the Payload Factory.
     *
     * @return Factory
     */
    public function factory()
    {
        return $this->manager->getPayloadFactory();
    }

    /**
     * Get the Blacklist.
     */
    public function blacklist(): Blacklist
    {
        return $this->manager->getBlacklist();
    }

    /**
     * Magically call the JWT Manager.
     *
     * @param array $parameters
     *
     * @throws BadMethodCallException
     */
    public function __call(string $method, array $parameters)
    {
        if (method_exists($this->manager, $method)) {
            return call_user_func_array([$this->manager, $method], $parameters);
        }

        throw new BadMethodCallException("Method [$method] does not exist.");
    }
}
