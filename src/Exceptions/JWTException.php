<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Exceptions;

use RuntimeException;

class JWTException extends RuntimeException
{
    protected $message = 'An error occurred';
}
