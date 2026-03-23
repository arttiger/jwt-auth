<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Support;

use Carbon\Carbon;

class Utils
{
    /**
     * Get the Carbon instance for the current time.
     */
    public static function now(): Carbon
    {
        return Carbon::now(timezone: 'UTC');
    }

    /**
     * Get the Carbon instance for the timestamp.
     */
    public static function timestamp(int $timestamp): Carbon
    {
        return Carbon::createFromTimestampUTC($timestamp)->timezone('UTC');
    }

    /**
     * Checks if a timestamp is in the past.
     */
    public static function isPast(int $timestamp, int $leeway = 0): bool
    {
        $ts = static::timestamp($timestamp);

        return $leeway > 0
            ? $ts->addSeconds(value: $leeway)->isPast()
            : $ts->isPast();
    }

    /**
     * Checks if a timestamp is in the future.
     */
    public static function isFuture(int $timestamp, int $leeway = 0): bool
    {
        $ts = static::timestamp($timestamp);

        return $leeway > 0
            ? $ts->subSeconds(value: $leeway)->isFuture()
            : $ts->isFuture();
    }
}
