<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) 2014-2021 Sean Tymon <tymon148@gmail.com>
 * (c) 2021 PHP Open Source Saver
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace ArtTiger\JWTAuth\Validators;

use ArtTiger\JWTAuth\Contracts\Validator as ValidatorContract;
use ArtTiger\JWTAuth\Exceptions\JWTException;
use ArtTiger\JWTAuth\Support\RefreshFlow;

abstract class Validator implements ValidatorContract
{
    use RefreshFlow;

    /**
     * Helper function to return a boolean.
     */
    public function isValid(array $value): bool
    {
        try {
            $this->check($value);
        } catch (JWTException) {
            return false;
        }

        return true;
    }

    /**
     * Run the validation.
     */
    abstract public function check(array $value): void;
}
