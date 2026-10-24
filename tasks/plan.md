# Implementation Plan: `resolver` module

> Spec: [SPEC-resolver.md](../SPEC-resolver.md) · Project spec: [SPEC.md](../SPEC.md) ·
> Tasks: [todo.md](todo.md)

## Overview

Build `crates/dnscraft-resolver`: a recursive, DNSSEC-validating resolver with cache,
serve-stale, prefetch, in-flight dedup, forward zones, and locally served private
reverse zones — plus `crates/dnscraft-testkit`, an in-process fake DNS hierarchy that lets
every behaviour be tested without internet access. This is the first code in the repo,
so the plan also bootstraps the Cargo workspace.

## Architecture Decisions

- **Spike before design freeze.** Task 2 evaluates `hickory-recursor` against in-house
  recursion on `hickory-proto` and records ADR-0001. Note: `hickory-recursor` is at 0.25.2
  (last release 2025-06) while `hickory-proto` is at 0.26.3, so the spike must also check
  whether recursion moved elsewhere in hickory 0.26 or the crate is lagging.
  **Tasks 4–16 are written as behaviour, not implementation;** after the ADR the plan is
  revised (some tasks become "wrap/configure", others "implement") and re-approved.
- **Testkit first, real internet last.** All success criteria except #3 are proven against
  the fake hierarchy. Internet checks are manual and happen at checkpoints.
- **Injectable time and root hints.** The resolver takes a clock and root hints via config,
  so expiry, serve-stale, and RRSIG validity are testable without sleeping.
- **Narrow public API** exactly as in the spec (`Resolver::new/resolve/flush/stats`);
  internals stay private to keep the later `policy` integration simple.
- **Trust anchors built in;** RFC 5011 tracking needs persisted state, see Open Questions.

## Dependency graph

```
workspace skeleton (1)
   ├── spike + ADR (2) ──────────────► plan revision
   └── testkit hierarchy (3)
          └── iterative resolution (4)
                 ├── CNAME/NX/NODATA/limits (5)
                 ├── transport robustness (6)
                 └── QNAME minimisation (7)
                        └── testkit DNSSEC zones (8)
                               └── DNSSEC validation (9)
                                      └── denial of existence + NTAs (10)
                                             └── cache (11)
                                                    ├── dedup + prefetch (12)
                                                    └── serve-stale (13)
                        forward zones (14) ◄── 4, 9, 11
                        local reverse zones + ECS (15) ◄── 4
                        stats, codes, bench, acceptance (16) ◄── all
```

## Task List

### Phase 1: Foundation
- [x] Task 1: Workspace skeleton and toolchain
- [ ] Task 2: Spike `hickory-recursor` vs. in-house, write ADR-0001
- [x] Task 3: Testkit fake hierarchy

### Checkpoint A: Foundation + decision
- [ ] Builds clean, testkit answers referrals
- [ ] **Human reviews ADR-0001; plan revised and re-approved**

### Phase 2: Recursion
- [ ] Task 4: Iterative resolution happy path
- [ ] Task 5: CNAME chains, NXDOMAIN, NODATA, limits
- [ ] Task 6: Transport robustness
- [ ] Task 7: QNAME minimisation

### Checkpoint B: Recursion
- [ ] Success criterion 1 met; manual `example.com A` resolves from the internet

### Phase 3: DNSSEC
- [ ] Task 8: Testkit DNSSEC zones
- [ ] Task 9: Chain-of-trust validation
- [ ] Task 10: Authenticated denial (NSEC/NSEC3) and negative trust anchors

### Checkpoint C: DNSSEC
- [ ] Success criteria 2 and 3 met

### Phase 4: Cache and resilience
- [ ] Task 11: Positive/negative cache
- [ ] Task 12: In-flight dedup and prefetch
- [ ] Task 13: Serve-stale

### Checkpoint D: Cache
- [ ] Success criteria 4, 5, 6 met

### Phase 5: Edges and completion
- [ ] Task 14: Forward zones
- [ ] Task 15: Locally served private reverse zones and ECS stripping
- [ ] Task 16: Stats, error codes, benchmark, example binary, acceptance

### Checkpoint E: Complete
- [ ] All 8 success criteria met, coverage ≥ 80 %, ready for review

## Parallelization

Mostly sequential (shared crate, shared internals). Safe in parallel: Task 3 alongside
Task 2; Task 15 alongside Phase 3/4; Task 8 (testkit) alongside Tasks 5–7.

## Dependencies requiring approval (boundary: "ask first")

| Crate | Purpose | Notes |
|---|---|---|
| `tokio` | runtime, sockets, timers | |
| `hickory-proto` (feature `dnssec-ring`) | wire format, DNSSEC primitives | |
| `hickory-recursor` | candidate engine | only if ADR-0001 selects it |
| `hickory-server` | authoritative servers in **testkit only** (dev-dependency) | |
| `thiserror`, `tracing`, `serde`, `toml` | errors, logging, config | |
| `rand` | query ids, source ports | |
| `criterion` | benchmarks (dev) | |
| `cargo-llvm-cov` | coverage (tool, not a dependency) | |

Cache: implemented in-house (size-in-bytes bounded) unless the spike shows the engine's
cache suffices; avoids `moka`'s footprint.

## Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| `hickory-recursor` immature/lagging (DNSSEC gaps, no serve-stale) | High | Spike first (Task 2); fallback is in-house recursion on `hickory-proto`, which roughly doubles Phase 2–3 effort |
| DNSSEC validation is subtle (NSEC3 opt-out, wildcards, algorithm support) | High | Dedicated testkit zones per case (Task 8); cross-check against `unbound`/`delv` manually at Checkpoint C |
| Testkit signing with controllable time is hard | Med | Sign at test time with injectable clock; avoid static fixtures with expiring signatures |
| Fake hierarchy needs multiple loopback IPs/ports per nameserver | Med | Root hints and glue carry `ip:port`; resolver accepts a port override in test config |
| IPv6 unavailable in CI/container | Low | IPv6 tests skip with a clear message when `::1` cannot bind |
| No Rust toolchain on this machine yet | Low | Task 1 installs `rustup` (needs your OK, see Open Questions) |

## Decisions (approved 2026-10-24)

1. Toolchain installed: `rustup` (stable 1.99.1, rustfmt, clippy), `bind-utils`, `knot-utils`.
2. RFC 5011: option (b) — built-in anchors per release + UI warning on mismatch; (a) may follow later.
3. CI: GitHub Actions workflow (fmt, clippy, test, coverage) is part of Task 1.
4. Dependency list above approved.
5. Implementation is delegated to Haiku/Sonnet subagents; the lead reviews every task before ticking it off.
