<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Providers;

use ArtTiger\JWTAuth\Abstracts\Providers\ServiceProvider;
use ArtTiger\JWTAuth\Http\Parser\LumenRouteParams;
use ArtTiger\JWTAuth\Http\Parser\Parser;

class LumenServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        // configure() is Lumen-specific — call dynamically to avoid PHPStan errors on Laravel interface
        if (method_exists($this->app, 'configure')) {
            $this->app->{'configure'}('jwt');
        }

        $path = realpath(__DIR__.'/../../config/config.php');

        if ($path !== false) {
            $this->mergeConfigFrom($path, 'jwt');
        }

        if (method_exists($this->app, 'routeMiddleware')) {
            $this->app->{'routeMiddleware'}($this->middlewareAliases);
        }

        $this->extendAuthGuard();

        $parser = $this->app->make('arttiger.jwt.parser');
        if ($parser instanceof Parser) {
            $parser->addParser(new LumenRouteParams());
        }
    }
}
