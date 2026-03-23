<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Providers;

use ArtTiger\JWTAuth\Abstracts\Providers\ServiceProvider;
use ArtTiger\JWTAuth\Facades\JWTAuth;
use ArtTiger\JWTAuth\Facades\JWTFactory;
use ArtTiger\JWTAuth\Facades\JWTProvider;
use ArtTiger\JWTAuth\Http\Parser\Cookies;
use ArtTiger\JWTAuth\Http\Parser\Parser;
use ArtTiger\JWTAuth\Http\Parser\RouteParams;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;

class LaravelServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        $path = realpath(__DIR__.'/../../config/config.php');

        if ($path !== false) {
            $this->publishes([$path => $this->app->configPath('jwt.php')], 'config');
            $this->mergeConfigFrom($path, 'jwt');
        }

        $this->aliasMiddleware();

        $this->extendAuthGuard();

        $config = $this->resolveConfig($this->app);

        $parser = $this->app->make('arttiger.jwt.parser');
        if ($parser instanceof Parser) {
            $decryptCookies = (bool) $config->get('jwt.decrypt_cookies', false);
            $cookieKey = $config->get('jwt.cookie_key_name', 'token');
            $cookieKeyStr = is_string($cookieKey) ? $cookieKey : 'token';

            $parser->addParser([
                new RouteParams(),
                (new Cookies($decryptCookies))->setKey($cookieKeyStr),
            ]);
        }

        if (isset($_SERVER['LARAVEL_OCTANE'])) {
            $events = $this->app->make(Dispatcher::class);
            if ($events instanceof Dispatcher) {
                $clear = function (): void {
                    JWTAuth::clearResolvedInstances();
                    JWTFactory::clearResolvedInstances();
                    JWTProvider::clearResolvedInstances();
                };

                if (class_exists('Laravel\Octane\Events\RequestReceived')) {
                    $events->listen('Laravel\Octane\Events\RequestReceived', $clear);
                }

                if (class_exists('Laravel\Octane\Events\TaskReceived')) {
                    $events->listen('Laravel\Octane\Events\TaskReceived', $clear);
                }

                if (class_exists('Laravel\Octane\Events\TickReceived')) {
                    $events->listen('Laravel\Octane\Events\TickReceived', $clear);
                }
            }
        }
    }

    protected function registerStorageProvider(): void
    {
        $this->app->singleton('arttiger.jwt.provider.storage', function (Application $app): mixed {
            return $this->getConfigInstance($app, 'providers.storage');
        });
    }

    protected function aliasMiddleware(): void
    {
        $router = $this->app->make('router');

        if (! ($router instanceof \Illuminate\Routing\Router)) {
            return;
        }

        foreach ($this->middlewareAliases as $alias => $middleware) {
            $router->aliasMiddleware($alias, $middleware);
        }
    }
}
