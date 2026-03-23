<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test\Fixtures;

use ArtTiger\JWTAuth\Claims\Claim;

class Foo extends Claim
{
    protected string $name = 'foo';
}
