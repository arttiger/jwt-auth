---
name: Known source code bugs
description: Real bugs in the jwt-auth source discovered while writing tests — affects how tests must be written
type: project
---

`Claims\Collection::toPlainArray()` is broken. It calls `$this->map(fn($claim) => $claim->getValue())` which uses `new static(result)` (Illuminate Collection::map). The custom Collection constructor runs `sanitizeClaims()` which drops any non-Claim value, so the returned array is always `[]`.

**Why:** Illuminate's `map()` uses `new static(...)`, and the custom Collection's constructor filters out non-Claim items.

**How to apply:** Any code that relies on `Payload::toArray()`, `Payload::get('key')`, `Payload::offsetGet()`, `Payload::offsetExists()`, `Payload::hasKey()`, `Payload::count()`, `Blacklist::getKey()`, `Blacklist::add()` (hasKey check), `Manager::encode()` (passes empty array to provider) — use **mocked Payloads** in those tests rather than real Payload instances. When testing real Payload behavior, only test methods that do NOT go through `toPlainArray()`: `getInternal()`, `has()`, `matches()`, `getClaims()->get()`, `__call` magic getters.
