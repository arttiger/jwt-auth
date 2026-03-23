<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Exceptions;

use ArtTiger\JWTAuth\Abstracts\Claim;
use Throwable;

class InvalidClaimException extends JWTException
{
    public function __construct(Claim $claim, int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct(
            message: "Invalid value provided for claim [{$claim->getName()}]",
            code: $code,
            previous: $previous,
        );
    }
}
