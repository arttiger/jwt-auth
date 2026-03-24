<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Console;

use Illuminate\Contracts\Config\Repository;
use ArtTiger\JWTAuth\Traits\EnvHelperTrait;
use Illuminate\Console\Command;
use Illuminate\Support\Str;

class JWTGenerateSecretCommand extends Command
{
    use EnvHelperTrait;

    /**
     * @var string
     */
    protected $signature = 'jwt:secret
        {--s|show : Display the key instead of modifying files.}
        {--always-no : Skip generating key if it already exists.}
        {--f|force : Skip confirmation when overwriting an existing key.}';

    /**
     * @var string
     */
    protected $description = 'Set the JWTAuth secret key used to sign the tokens';

    public function handle(): int
    {
        $key = Str::random(64);

        if ($this->option('show')) {
            $this->comment($key);

            return self::SUCCESS;
        }

        if (! $this->envFileExists()) {
            $this->displayKey($key);

            return self::SUCCESS;
        }

        $updated = $this->updateEnvEntry('JWT_SECRET', $key, function () {
            if ($this->option('always-no')) {
                $this->comment('Secret key already exists. Skipping...');

                return false;
            }

            if (! $this->isConfirmed()) {
                $this->comment('Phew... No changes were made to your secret key.');

                return false;
            }

            return true;
        });

        if ($updated) {
            $this->updateEnvEntry('JWT_ALGO', 'HS256');
            $this->info('jwt-auth secret set successfully.');
        }

        return self::SUCCESS;
    }

    protected function displayKey(string $key): void
    {
        $config = $this->laravel->make(Repository::class);
        $config->set('jwt.secret', $key);

        $this->info("jwt-auth secret [$key] set successfully.");
    }

    protected function isConfirmed(): bool
    {
        return (bool) ($this->option('force') ?: $this->confirm(
            'This will invalidate all existing tokens. Are you sure you want to override the secret key?'
        ));
    }
}
