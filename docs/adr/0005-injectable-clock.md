# ADR-0005: Injectable Clock / ManualClock instead of sleeping tests

- Status: Accepted
- Date: 2026-10-24 (resolver plan); applied in later crates through 2026-10-26
- Deciders: resolver plan ("Injectable time and root hints"); reinforced after flaky
  wall-clock sleeps in clients reviews (C11b)
- Scope: testability across resolver, filtering, clients, tls, policy, listeners

## Context

Limits, TTLs, RRSIG validity, ban windows, poll intervals and TLS handshake deadlines are
time-based. Sleeping in tests for those behaviours is slow and flaky under load (documented in
the clients C11b review in [tasks/archive/progress-2026-10.md](../../tasks/archive/progress-2026-10.md)).

## Decision

Each relevant crate exposes a **`Clock` trait** plus **`ManualClock`** (and usually
`SystemClock`). Production uses the system clock; tests advance `ManualClock` (often with a
`wait_until` helper) instead of wall-clock sleeps. First recorded as an architecture decision in
the resolver plan ([tasks/archive/resolver-plan.md](../../tasks/archive/resolver-plan.md));
listeners repeat it as a hard rule in [tasks/todo-listeners.md](../../tasks/todo-listeners.md)
("no wall-clock sleeps to wait for background work").

## Consequences

- Time-sensitive tests are deterministic and fast.
- Each crate carries its own small `Clock` copy (not a shared workspace trait today).
- Async code that waits for a deadline must go through the clock (`wait_until`), not
  `tokio::time::sleep` alone, when the wait is part of the unit under test.

## Alternatives considered

- **Wall-clock sleeps in tests:** rejected after flaky clients engine tests (C11b); listeners
  plan lists "Flaky socket tests" mitigation as ManualClock.
- **Single workspace `dnscraft-clock` crate:** not chosen; **rationale not recorded** (per-crate
  `Clock` helpers were listed as a cross-module plan note without a written comparison).
- **tokio `Paused` time / time-travel runtime:** not evaluated in writing; **rationale not
  recorded**.

## Links

- [tasks/archive/resolver-plan.md](../../tasks/archive/resolver-plan.md) — Injectable time
- [SPEC-listeners.md](../../SPEC-listeners.md) — ManualClock in testing strategy
- [tasks/todo-listeners.md](../../tasks/todo-listeners.md) — ManualClock rule
- Clients C11b / progress archive (2026-10-25) — flaky sleep lesson
