<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Claims;

class Audience extends Claim
{
    protected string $name = 'aud';
}
