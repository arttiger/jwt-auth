# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run all tests
composer test
# or directly:
vendor/bin/phpunit --colors=always

# Run a single test file
vendor/bin/phpunit tests/Claims/CollectionTest.php --no-coverage

# Run a single test method
vendor/bin/phpunit --filter testItShouldHandleCarbonClaims --no-coverage

# Static analysis (level 10, no errors tolerated)
composer phpstan
# or directly:
vendor/bin/phpstan analyse --memory-limit=512M

# Code style
vendor/bin/php-cs-fixer fix --diff
```

## Architecture

This is a JWT authentication library for Laravel 12+/Lumen. Namespace: `ArtTiger\JWTAuth\`.

### Request flow

```
HTTP Request
   └─ Http\Parser\Parser        — extracts raw token string from header/cookie/query
      └─ Token                — value object wrapping validated token string
         └─ Manager         — decodes via JWT Provider, checks blacklist
            └─ Payload    — immutable container of typed Claim objects
               └─ JWTGuard / JWT  — Laravel Guard integration, user resolution
```

### Key layers

**`Providers\JWT\`** — cryptographic layer. Two interchangeable implementations:
- `Lcobucci` (default, lcobucci/jwt v5): uses `AlgorithmRegistry` to resolve typed `Algorithm` objects
- `Namshi` (namshi/jose): legacy alternative

**`Claims\`** — typed claim system. Each RFC 7519 claim is its own class extending `Abstracts\Claim` with a `validateCreate()` method. `Claims\Collection` extends `Illuminate\Support\Collection` keyed by claim name. `Claims\Factory` builds collections from raw arrays.

**`Algorithms\`** — typed algorithm objects. Each algorithm (Hs256, Rs256, Es256, …) holds its RFC 7518 identifier, Lcobucci signer class, and validates key material (HMAC minimum byte length, RSA ≥2048 bits, ECDSA correct curve). `AlgorithmRegistry::find(string $id)` is the entry point.

**`Manager`** — orchestrates encode/decode, refresh, and blacklisting. Uses `CustomClaims` trait shared with `JWT` and `Factory`.

**`JWTGuard`** — implements `Illuminate\Contracts\Auth\Guard`. Delegates unknown method calls to the `JWT` instance via `__call()`.

**`Payload`** — immutable claims container (ArrayAccess, Countable, Jsonable). Created by `Factory`, validated by `Validators\PayloadValidator`.

### Contracts

- `Contracts\JWTSubject` — user models must implement `getJWTIdentifier()` and `getJWTCustomClaims()`
- `Contracts\Providers\JWT` — encode/decode interface implemented by Lcobucci and Namshi
- `Contracts\Providers\Storage` — blacklist storage; default implementation wraps Laravel cache

### Claim lifecycle

`Abstracts\Claim` defines three validation hooks called at different stages:
- `validateCreate(mixed $value)` — called on construction, coerces/validates the raw value
- `validatePayload()` — called when decoding a token (e.g. `exp` checks not expired)
- `validateRefresh()` — called during token refresh (e.g. `iat` checks max refresh TTL)

Date/time claims (`exp`, `nbf`, `iat`) use `Traits\DatetimeTrait` which accepts `int`, `DateTimeInterface`, or `DateInterval` in `setValue()` and normalises to Unix timestamp.

### Service providers

`Providers\AbstractServiceProvider` registers all singletons. `LaravelServiceProvider` extends it and handles middleware aliases, route param parsers, and Octane compatibility. Config key: `jwt` (published to `config/jwt.php`).

## Standards

- `declare(strict_types=1)` in every file
- PHPStan level 10 — zero errors required; `treatPhpDocTypesAsCertain: false` is set in `phpstan.neon.dist`
- PHP `^8.3`; use intersection types, named arguments, and `#[\SensitiveParameter]` on key/secret parameters
- RFC 7519 compliance is the authoritative specification for all claim behaviour
