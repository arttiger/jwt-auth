<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Http\Parser;

use Illuminate\Http\Request;
use ArtTiger\JWTAuth\Contracts\Http\Parser as ParserContract;

class Parser
{
    /**
     * Constructor.
     *
     * @param ParserContract[] $chain
     */
    public function __construct(
        /**
         * The request.
         */
        protected Request $request,
        /**
         * The chain of parsers.
         */
        private array $chain = []
    )
    {
    }

    /**
     * Get the parser chain.
     *
     * @return ParserContract[]
     */
    public function getChain(): array
    {
        return $this->chain;
    }

    /**
     * Add a new parser to the chain.
     *
     * @param ParserContract|ParserContract[] $parsers
     */
    public function addParser(ParserContract|array $parsers): self
    {
        $this->chain = array_merge($this->chain, is_array($parsers) ? $parsers : [$parsers]);

        return $this;
    }

    /**
     * Set the order of the parser chain.
     *
     * @param ParserContract[] $chain
     */
    public function setChain(array $chain): self
    {
        $this->chain = $chain;

        return $this;
    }

    /**
     * Alias for setting the order of the chain.
     *
     * @param ParserContract[] $chain
     */
    public function setChainOrder(array $chain): self
    {
        return $this->setChain($chain);
    }

    /**
     * Iterate through the parsers and attempt to retrieve
     *  a value, otherwise return null.
     */
    public function parseToken(): ?string
    {
        foreach ($this->chain as $parser) {
            if ($response = $parser->parse($this->request)) {
                return $response;
            }
        }

        return null;
    }

    /**
     * Check whether a token exists in the chain.
     */
    public function hasToken(): bool
    {
        return $this->parseToken() !== null;
    }

    /**
     * Set the request instance.
     */
    public function setRequest(Request $request): self
    {
        $this->request = $request;

        return $this;
    }
}
