---
name: Testing framework and conventions
description: PHPUnit + Mockery setup, file locations, namespace, Carbon fake time pattern
type: project
---

- **Framework**: PHPUnit (^10.5|^11|^12|^13) with Mockery (^1.6)
- **Test namespace**: `ArtTiger\JWTAuth\Test\` → `tests/` (PSR-4)
- **Base class**: `tests/AbstractTestCase.php` — sets `Carbon::setTestNow('2024-01-01 00:00:00')` in setUp, closes Mockery in tearDown, provides `makeValidClaims(?array $overrides)` and `makeValidCollection(?array $overrides)` helpers
- **Stubs**: `tests/Stubs/UserStub.php` — implements JWTSubject, identifier=1, custom claims `['foo'=>'bar','role'=>'admin']`
- **Strict types**: Every test file uses `declare(strict_types=1)`
- **Collection construction**: Must pass string-keyed arrays: `new Collection(['sub' => $subClaim, ...])`
- **Carbon timestamps**: Use `$this->testNowTimestamp` (set to 2024-01-01 00:00:00 UTC)
- **isPast(now)**: Returns `false` — exactly "now" is not past. Only `now - 1` is past.
- **Subject URI validation**: `FILTER_VALIDATE_URL` rejects URN-style (`urn:uuid:...`) URIs. Only `https://` and similar HTTP URLs are accepted by Subject::validateCreate.
- **Custom::__construct**: Takes `(string $name, mixed $value)` — 2 args. Cannot be used directly as a mapped class in Claims\Factory::extend() because Factory::get() calls `new $class($value)` with one arg.
