<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Abstracts\Providers;

use ArtTiger\JWTAuth\Blacklist;
use ArtTiger\JWTAuth\Claims\Factory as ClaimFactory;
use ArtTiger\JWTAuth\Console\JWTGenerateCertCommand;
use ArtTiger\JWTAuth\Console\JWTGenerateSecretCommand;
use ArtTiger\JWTAuth\Contracts\Providers\Auth;
use ArtTiger\JWTAuth\Contracts\Providers\JWT as JWTContract;
use ArtTiger\JWTAuth\Contracts\Providers\Storage;
use ArtTiger\JWTAuth\Factory;
use ArtTiger\JWTAuth\Guards\JWTGuard;
use ArtTiger\JWTAuth\Http\Middleware\Authenticate;
use ArtTiger\JWTAuth\Http\Middleware\AuthenticateAndRenew;
use ArtTiger\JWTAuth\Http\Middleware\Check;
use ArtTiger\JWTAuth\Http\Middleware\RefreshToken;
use ArtTiger\JWTAuth\Http\Parser\AuthHeaders;
use ArtTiger\JWTAuth\Http\Parser\InputSource;
use ArtTiger\JWTAuth\Http\Parser\Parser;
use ArtTiger\JWTAuth\Http\Parser\QueryString;
use ArtTiger\JWTAuth\JWT;
use ArtTiger\JWTAuth\JWTAuth;
use ArtTiger\JWTAuth\JWTUserProvider;
use ArtTiger\JWTAuth\Manager;
use ArtTiger\JWTAuth\Providers\JWT\Lcobucci;
use ArtTiger\JWTAuth\Providers\JWT\Namshi;
use ArtTiger\JWTAuth\Validators\PayloadValidator;
use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Config\Repository as ConfigContract;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\ServiceProvider as BaseServiceProvider;
use Namshi\JOSE\JWS;
use RuntimeException;

abstract class ServiceProvider extends BaseServiceProvider
{
    /**
     * @var array<non-empty-string, class-string>
     */
    protected array $middlewareAliases = [
        'jwt.auth' => Authenticate::class,
        'jwt.check' => Check::class,
        'jwt.refresh' => RefreshToken::class,
        'jwt.renew' => AuthenticateAndRenew::class,
    ];

    abstract public function boot(): void;

    public function register(): void
    {
        $this->registerAliases();

        $this->registerJWTProvider();
        $this->registerAuthProvider();
        $this->registerStorageProvider();
        $this->registerJWTBlacklist();

        $this->registerManager();
        $this->registerTokenParser();

        $this->registerJWT();
        $this->registerJWTAuth();
        $this->registerPayloadValidator();
        $this->registerClaimFactory();
        $this->registerPayloadFactory();
        $this->registerJWTCommands();

        $this->commands([
            'arttiger.jwt.secret',
            'arttiger.jwt.cert',
        ]);
    }

    protected function extendAuthGuard(): void
    {
        $authManager = $this->app->make(AuthManager::class);

        if (! ($authManager instanceof AuthManager)) {
            return;
        }

        $configRepo = $this->resolveConfig($this->app);

        $authManager->extend('jwt', function (Application $app, string $name, array $config) use ($configRepo): JWTGuard {
            $auth = $app->make(AuthManager::class);
            $providerName = $config['provider'] ?? 'users';
            $provider = ($auth instanceof AuthManager)
                ? $auth->createUserProvider(is_string($providerName) ? $providerName : 'users')
                : null;

            if ($provider === null) {
                throw new RuntimeException(message: 'Unable to resolve user provider for JWT guard.');
            }

            $jwt = $app->make(JWT::class);
            if (! ($jwt instanceof JWT)) {
                throw new RuntimeException(message: 'JWT instance not resolved.');
            }

            $request = $app->make(Request::class);
            if (! ($request instanceof Request)) {
                throw new RuntimeException(message: 'Request not resolved.');
            }

            $events = $app->make(Dispatcher::class);
            if (! ($events instanceof Dispatcher)) {
                throw new RuntimeException(message: 'Event dispatcher not resolved.');
            }

            $guard = new JWTGuard($jwt, new JWTUserProvider($provider), $request, $events);

            $ttl = Arr::has($config, 'ttl') ? Arr::get($config, 'ttl') : $configRepo->get('jwt.ttl');

            $guard->setTTL(is_int($ttl) ? $ttl : null);

            if ($app instanceof \Illuminate\Foundation\Application) {
                $app->refresh('request', $guard, 'setRequest');
            }

            return $guard;
        });
    }

    protected function registerAliases(): void
    {
        $this->app->alias('arttiger.jwt', JWT::class);
        $this->app->alias('arttiger.jwt.auth', JWTAuth::class);
        $this->app->alias('arttiger.jwt.provider.jwt', JWTContract::class);
        $this->app->alias('arttiger.jwt.provider.jwt.namshi', Namshi::class);
        $this->app->alias('arttiger.jwt.provider.jwt.lcobucci', Lcobucci::class);
        $this->app->alias('arttiger.jwt.provider.auth', Auth::class);
        $this->app->alias('arttiger.jwt.provider.storage', Storage::class);
        $this->app->alias('arttiger.jwt.manager', Manager::class);
        $this->app->alias('arttiger.jwt.blacklist', Blacklist::class);
        $this->app->alias('arttiger.jwt.payload.factory', Factory::class);
        $this->app->alias('arttiger.jwt.validators.payload', PayloadValidator::class);
    }

    protected function registerJWTProvider(): void
    {
        $this->registerNamshiProvider();
        $this->registerLcobucciProvider();

        $this->app->singleton('arttiger.jwt.provider.jwt', fn (Application $app): mixed => $this->getConfigInstance($app, 'providers.jwt'));
    }

    protected function registerNamshiProvider(): void
    {
        $this->app->singleton('arttiger.jwt.provider.jwt.namshi', function (Application $app): Namshi {
            $config = $this->resolveConfig($app);

            $secret = $config->get('jwt.secret');
            $algo = $config->get('jwt.algo');
            $keys = $config->get('jwt.keys', []);

            return new Namshi(
                new JWS(['typ' => 'JWT', 'alg' => is_string($algo) ? $algo : '']),
                is_string($secret) ? $secret : null,
                is_string($algo) ? $algo : '',
                $this->toStringKeyedArray($keys)
            );
        });
    }

    protected function registerLcobucciProvider(): void
    {
        $this->app->singleton('arttiger.jwt.provider.jwt.lcobucci', function (Application $app): Lcobucci {
            $config = $this->resolveConfig($app);

            $secret = $config->get('jwt.secret');
            $algo = $config->get('jwt.algo');
            $keys = $config->get('jwt.keys', []);

            return new Lcobucci(
                is_string($secret) ? $secret : null,
                is_string($algo) ? $algo : '',
                $this->toStringKeyedArray($keys)
            );
        });
    }

    protected function registerAuthProvider(): void
    {
        $this->app->singleton('arttiger.jwt.provider.auth', fn (Application $app): mixed => $this->getConfigInstance($app, 'providers.auth'));
    }

    protected function registerStorageProvider(): void
    {
        $this->app->singleton('arttiger.jwt.provider.storage', fn (Application $app): mixed => $this->getConfigInstance($app, 'providers.storage'));
    }

    protected function registerManager(): void
    {
        $this->app->singleton('arttiger.jwt.manager', function (Application $app): Manager {
            $provider = $app->make(JWTContract::class);
            if (! ($provider instanceof JWTContract)) {
                throw new RuntimeException(message: 'JWT provider not resolved.');
            }

            $blacklist = $app->make(Blacklist::class);
            if (! ($blacklist instanceof Blacklist)) {
                throw new RuntimeException(message: 'Blacklist not resolved.');
            }

            $factory = $app->make(Factory::class);
            if (! ($factory instanceof Factory)) {
                throw new RuntimeException(message: 'Payload factory not resolved.');
            }

            $config = $this->resolveConfig($app);
            $rawClaims = $config->get('jwt.persistent_claims', []);
            $persistentClaims = is_array($rawClaims)
                ? array_values(array_filter($rawClaims, is_string(...)))
                : [];

            return (new Manager($provider, $blacklist, $factory))
                ->setBlacklistEnabled((bool) $config->get('jwt.blacklist_enabled'))
                ->setRefreshIat((bool) $config->get('jwt.refresh_iat', false))
                ->setPersistentClaims($persistentClaims)
                ->setBlackListExceptionEnabled((bool) $config->get('jwt.show_black_list_exception', 0));
        });
    }

    protected function registerTokenParser(): void
    {
        $this->app->singleton('arttiger.jwt.parser', function (Application $app): Parser {
            $request = $app->make(Request::class);
            if (! ($request instanceof Request)) {
                throw new RuntimeException(message: 'Request not resolved.');
            }

            $parser = new Parser(
                $request,
                [
                    new AuthHeaders(),
                    new QueryString(),
                    new InputSource(),
                ]
            );

            if ($app instanceof \Illuminate\Foundation\Application) {
                $app->refresh('request', $parser, 'setRequest');
            }

            return $parser;
        });
    }

    protected function registerJWT(): void
    {
        $this->app->singleton('arttiger.jwt', function (Application $app): JWT {
            $manager = $app->make(Manager::class);
            if (! ($manager instanceof Manager)) {
                throw new RuntimeException(message: 'Manager not resolved.');
            }

            $parser = $app->make('arttiger.jwt.parser');
            if (! ($parser instanceof Parser)) {
                throw new RuntimeException(message: 'Parser not resolved.');
            }

            return (new JWT($manager, $parser))
                ->lockSubject((bool) $this->resolveConfig($app)->get('jwt.lock_subject'));
        });
    }

    protected function registerJWTAuth(): void
    {
        $this->app->singleton('arttiger.jwt.auth', function (Application $app): JWTAuth {
            $manager = $app->make(Manager::class);
            if (! ($manager instanceof Manager)) {
                throw new RuntimeException(message: 'Manager not resolved.');
            }

            $authProvider = $app->make(Auth::class);
            if (! ($authProvider instanceof Auth)) {
                throw new RuntimeException(message: 'Auth provider not resolved.');
            }

            $parser = $app->make('arttiger.jwt.parser');
            if (! ($parser instanceof Parser)) {
                throw new RuntimeException(message: 'Parser not resolved.');
            }

            return (new JWTAuth($manager, $authProvider, $parser))
                ->lockSubject((bool) $this->resolveConfig($app)->get('jwt.lock_subject'));
        });
    }

    protected function registerJWTBlacklist(): void
    {
        $this->app->singleton('arttiger.jwt.blacklist', function (Application $app): Blacklist {
            $storageProvider = $app->make(Storage::class);
            if (! ($storageProvider instanceof Storage)) {
                throw new RuntimeException(message: 'Storage provider not resolved.');
            }

            $config = $this->resolveConfig($app);

            $gracePeriod = $config->get('jwt.blacklist_grace_period', 0);
            $refreshTTL = $config->get('jwt.refresh_ttl', 20160);

            return (new Blacklist($storageProvider))
                ->setGracePeriod(is_int($gracePeriod) ? $gracePeriod : 0)
                ->setRefreshTTL(is_int($refreshTTL) ? $refreshTTL : 20160);
        });
    }

    protected function registerPayloadValidator(): void
    {
        $this->app->singleton('arttiger.jwt.validators.payload', function (Application $app): PayloadValidator {
            $config = $this->resolveConfig($app);

            $refreshTTL = $config->get('jwt.refresh_ttl', 20160);
            $rawRequired = $config->get('jwt.required_claims', []);
            $requiredClaims = is_array($rawRequired)
                ? array_values(array_filter($rawRequired, is_string(...)))
                : [];

            return (new PayloadValidator())
                ->setRefreshTTL(is_int($refreshTTL) ? $refreshTTL : 20160)
                ->setRequiredClaims($requiredClaims);
        });
    }

    protected function registerClaimFactory(): void
    {
        $this->app->singleton('arttiger.jwt.claim.factory', function (Application $app): ClaimFactory {
            $request = $app->make(Request::class);
            if (! ($request instanceof Request)) {
                throw new RuntimeException(message: 'Request not resolved.');
            }

            $factory = new ClaimFactory($request);
            if ($app instanceof \Illuminate\Foundation\Application) {
                $app->refresh('request', $factory, 'setRequest');
            }

            $config = $this->resolveConfig($app);
            $ttl = $config->get('jwt.ttl');
            $leeway = $config->get('jwt.leeway', 0);

            return $factory
                ->setTTL(is_int($ttl) ? $ttl : null)
                ->setLeeway(is_int($leeway) ? $leeway : 0);
        });
    }

    protected function registerPayloadFactory(): void
    {
        $this->app->singleton('arttiger.jwt.payload.factory', function (Application $app): Factory {
            $claimFactory = $app->make(ClaimFactory::class);
            if (! ($claimFactory instanceof ClaimFactory)) {
                throw new RuntimeException(message: 'ClaimFactory not resolved.');
            }

            $validator = $app->make(PayloadValidator::class);
            if (! ($validator instanceof PayloadValidator)) {
                throw new RuntimeException(message: 'PayloadValidator not resolved.');
            }

            return new Factory($claimFactory, $validator);
        });
    }

    protected function registerJWTCommands(): void
    {
        $this->app->singleton('arttiger.jwt.secret', fn (): JWTGenerateSecretCommand => new JWTGenerateSecretCommand());
        $this->app->singleton('arttiger.jwt.cert', fn (): JWTGenerateCertCommand => new JWTGenerateCertCommand());
    }

    protected function getConfigInstance(Application $app, string $key): mixed
    {
        $instance = $this->resolveConfig($app)->get('jwt.'.$key);

        if (is_string($instance)) {
            return $this->app->make($instance);
        }

        return $instance;
    }

    protected function resolveConfig(Application $app): ConfigContract
    {
        $config = $app->make(ConfigContract::class);

        if (! ($config instanceof ConfigContract)) {
            throw new RuntimeException(message: 'Config repository not resolved.');
        }

        return $config;
    }

    /**
     * Convert a mixed value to array<string, mixed>, dropping non-string keys.
     *
     * @return array<string, mixed>
     */
    private function toStringKeyedArray(mixed $value): array
    {
        if (! is_array($value)) {
            return [];
        }

        $result = [];
        foreach ($value as $k => $v) {
            if (is_string($k)) {
                $result[$k] = $v;
            }
        }

        return $result;
    }
}
