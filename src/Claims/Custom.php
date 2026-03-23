<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Claims;

use ArtTiger\JWTAuth\Abstracts\Claim;
use ArtTiger\JWTAuth\Exceptions\InvalidClaimException;

class Custom extends Claim
{
    /**
     * @throws InvalidClaimException
     */
    public function __construct(string $name, mixed $value)
    {
        parent::__construct($value);
        $this->setName($name);
    }
}
