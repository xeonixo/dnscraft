# ADR-0005: Injectable Clock / ManualClock instead of sleeping tests

- Status: Accepted
- Date: 2026-10-24; revised 2026-10-27 (one shared `Clock`)
- Deciders: resolver plan ("Injectable time and root hints"); reinforced after flaky
  wall-clock sleeps in clients reviews (C11b)
- Scope: testability across resolver, filtering, clients, tls, api, mcp, policy, listeners

## Context

Limits, TTLs, RRSIG validity, ban windows, poll intervals and TLS handshake deadlines are
time-based. Sleeping in tests for those behaviours is slow and flaky under load (documented in
the clients C11b review in [tasks/archive/progress-2026-10.md](../../tasks/archive/progress-2026-10.md)).

An earlier revision of this ADR said every crate should carry its own small `Clock` copy.
In practice most crates re-exported `dnscraft_common::clock`, and the remaining copies had
already drifted — so the workspace had both duplicate implementations and inconsistent
capabilities.

## Decision

There is **exactly one** `Clock` trait, in `dnscraft_common::clock`, together with
`SystemClock` and `ManualClock`. Crates **re-export** it; they do not define local copies.

The trait exposes:

- `now()` — wall-clock `SystemTime`;
- `instant()` — monotonic `Instant` for TTL/RTT logic, defaulted to `Instant::now()` and
  overridden by `ManualClock` so tests can advance it;
- `tick_notify()` — optional wake signal used by `wait_until` so manual-clock tests can drive
  schedulers without sleeping.

Production wires `SystemClock`; tests advance `ManualClock` (usually with `wait_until`)
instead of sleeping. First recorded as an architecture decision in the resolver plan
([tasks/archive/resolver-plan.md](../../tasks/archive/resolver-plan.md)); listeners repeat it
as a hard rule in [tasks/todo-listeners.md](../../tasks/todo-listeners.md) ("no wall-clock
sleeps to wait for background work").

## Consequences

- Time-sensitive tests are deterministic and fast.
- One trait definition: a new capability (such as `instant()`) is added once and every crate
  sees it; implementations cannot silently diverge.
- A crate that needs time adds `dnscraft-common` and imports `dnscraft_common::clock`; writing
  a local `clock.rs` is a review error.
- Async code that waits for a deadline must go through the clock (`wait_until`), not
  `tokio::time::sleep` alone, when the wait is part of the unit under test.

## Alternatives considered

- **Wall-clock sleeps in tests:** rejected after flaky clients engine tests (C11b); listeners
  plan lists "Flaky socket tests" mitigation as ManualClock.
- **Per-crate `Clock` copies:** rejected. Four crates already re-exported the common clock and
  the copies drifted (for example resolver needed `instant()`, api/mcp did not have it).
- **Single separate `dnscraft-clock` crate:** rejected; `dnscraft-common` is already the shared
  leaf crate for clock, secret and config/network helpers, so another crate adds a dependency
  edge without isolating anything.
- **tokio `Paused` time / time-travel runtime:** not evaluated in writing; **rationale not
  recorded**.

## Links

- [tasks/archive/resolver-plan.md](../../tasks/archive/resolver-plan.md) — Injectable time
- [SPEC-listeners.md](../../SPEC-listeners.md) — ManualClock in testing strategy
- [tasks/todo-listeners.md](../../tasks/todo-listeners.md) — ManualClock rule
- Clients C11b / progress archive (2026-10-25) — flaky sleep lesson
