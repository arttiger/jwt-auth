<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Providers\Storage;

use Illuminate\Contracts\Cache\Repository as CacheContract;
use ArtTiger\JWTAuth\Contracts\Providers\Storage;

class Illuminate implements Storage
{
    protected CacheContract $cache;

    protected string $tag = 'arttiger.jwt';

    protected ?bool $supportsTags = null;

    public function __construct(CacheContract $cache)
    {
        $this->cache = $cache;
    }

    public function add(string $key, mixed $value, int $minutes): void
    {
        // Laravel 5.8+ uses seconds; since we require Laravel 12, always convert.
        $this->cache()->put($key, $value, $minutes * 60);
    }

    public function forever(string $key, mixed $value): void
    {
        $this->cache()->forever($key, $value);
    }

    public function get(string $key): mixed
    {
        return $this->cache()->get($key);
    }

    public function destroy(string $key): bool
    {
        return $this->cache()->forget($key);
    }

    public function flush(): void
    {
        $cache = $this->cache();
        if ($cache instanceof \Illuminate\Cache\Repository) {
            $cache->flush();
        }
    }

    protected function cache(): CacheContract
    {
        if ($this->supportsTags === null) {
            $this->determineTagSupport();
        }

        if ($this->supportsTags === true && $this->cache instanceof \Illuminate\Cache\Repository) {
            return $this->cache->tags($this->tag);
        }

        return $this->cache;
    }

    protected function determineTagSupport(): void
    {
        if (! ($this->cache instanceof \Illuminate\Cache\Repository)) {
            $this->supportsTags = false;

            return;
        }

        try {
            $this->cache->tags($this->tag);
            $this->supportsTags = true;
        } catch (\BadMethodCallException) {
            $this->supportsTags = false;
        }
    }
}
