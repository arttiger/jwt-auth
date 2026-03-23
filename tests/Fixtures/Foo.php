<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test\Fixtures;

use ArtTiger\JWTAuth\Abstracts\Claim;

class Foo extends Claim
{
    protected string $name = 'foo';
}
