<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Traits;

use Closure;
use Illuminate\Foundation\Application;
use Illuminate\Support\Str;

trait EnvHelperTrait
{
    protected function envFileExists(): bool
    {
        return file_exists($this->envPath());
    }

    public function updateEnvEntry(string $key, string $value, ?Closure $confirmOnExisting = null): bool
    {
        $filepath = $this->envPath();

        $filecontents = $this->getFileContents($filepath);

        if (! Str::contains($filecontents, $key)) {
            $this->putFileContents(
                $filepath,
                $filecontents.PHP_EOL."{$key}={$value}".PHP_EOL
            );

            return true;
        } else {
            if (is_null($confirmOnExisting) || $confirmOnExisting()) {
                $replaced = preg_replace(
                    "/{$key}=.*/",
                    "{$key}={$value}",
                    $filecontents
                );

                $this->putFileContents($filepath, $replaced ?? $filecontents);

                return true;
            }
        }

        return false;
    }

    protected function getFileContents(string $filepath): string
    {
        $contents = file_get_contents($filepath);

        return $contents !== false ? $contents : '';
    }

    protected function putFileContents(string $filepath, string $data): void
    {
        file_put_contents($filepath, $data);
    }

    protected function envPath(): string
    {
        if ($this->laravel instanceof Application) {
            return $this->laravel->environmentFilePath();
        }

        return $this->laravel->basePath('.env');
    }
}
