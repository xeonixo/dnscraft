# Implementation Plan: `resolver` module

> Spec: [SPEC-resolver.md](../SPEC-resolver.md) · Project spec: [SPEC.md](../SPEC.md) ·
> ADR: [0001-recursion-engine.md](../docs/adr/0001-recursion-engine.md) · Tasks: [todo.md](todo.md)

## Overview

Build `crates/dnscraft-proto` (in-house DNS wire format and DNSSEC record types) and
`crates/dnscraft-resolver`: a recursive, DNSSEC-validating resolver with cache, serve-stale,
prefetch, in-flight dedup, forward zones, and locally served private reverse zones —
plus `crates/dnscraft-testkit`, an in-process fake DNS hierarchy so every behaviour is
tested without internet access.

## Architecture Decisions

- **ADR-0001 accepted: Option D — write as much as reasonable in-house.**
  - In-house: wire format (`dnscraft-proto`), DNSSEC validation logic, recursion, transport,
    cache, dedup, serve-stale, prefetch, forward zones, EDE.
  - Third-party by design: crypto primitives via `ring` (never hand-written), `tokio`.
  - hickory only in `dnscraft-testkit` (dev), acting as an **independent oracle**: the testkit
    encodes with hickory, the resolver decodes with `dnscraft-proto`, so mismatches surface.
    hickory pinned exactly (`=0.26.3`).
- **`dnscraft-proto` has no I/O and no async.** Pure encode/decode, reusable by listeners,
  policy, and filtering later. Decoding is hardened for untrusted input: length and pointer
  limits, no recursion on compression pointers, no panics (fuzzed).
- **Testkit first, real internet last.** All success criteria except #3 are proven against
  the fake hierarchy. Internet checks are manual and happen at checkpoints.
- **Injectable time and root hints.** Clock and root hints (`SocketAddr`, so ports work) come
  via config; expiry, serve-stale, and RRSIG validity are testable without sleeping.
- **Narrow public API** exactly as in the spec (`Resolver::new/resolve/flush/stats`).
- **Trust anchors built in** (RFC 5011 tracking deferred, see Decisions).

## Dependency graph

```
workspace (1) ── testkit hierarchy (3)
   │
   └── W1 names ── W2 rdata ── W3 message/EDNS ── W4 DNSSEC records
                                   │                    │
                                   │              W5 fuzzing (after W3, extended after W4)
                                   │
                                   └── 4 iterative resolution
                                          ├── 5 CNAME/NX/NODATA/limits
                                          ├── 6 transport robustness
                                          └── 7 QNAME minimisation
                                                 └── 8 testkit DNSSEC zones (◄ 3)
                                                        └── 9a chain + signature verification (◄ W4)
                                                               └── 9b status mapping
                                                                      └── 10 denial + NTAs
                                                                             └── 11 cache
                                                                                    ├── 12 dedup + prefetch
                                                                                    └── 13 serve-stale
                                          14 forward zones ◄── 4, 9b, 11
                                          15 local reverse zones + ECS ◄── 4
                                          16 stats, codes, bench, acceptance ◄── all
```

## Task List

### Phase 1: Foundation
- [x] Task 1: Workspace skeleton and toolchain
- [x] Task 2: Spike `hickory-recursor` vs. in-house, write ADR-0001
- [x] Task 3: Testkit fake hierarchy

### Checkpoint A: Foundation + decision
- [x] Builds clean, testkit answers referrals
- [x] ADR-0001 accepted (Option D) by the owner
- [ ] Revised plan approved

### Phase 1b: Wire format (`dnscraft-proto`)
- [ ] Task W1: Domain names and compression
- [ ] Task W2: Core RDATA types
- [ ] Task W3: Messages and EDNS
- [ ] Task W4: DNSSEC record types and canonical form
- [ ] Task W5: Fuzzing and oracle round-trips

### Checkpoint W: Wire format
- [ ] Every testkit response decodes with `dnscraft-proto`; round-trips against hickory pass
- [ ] Fuzz targets run 10 min each without findings; coverage ≥ 80 %
- [ ] Review with human

### Phase 2: Recursion
- [ ] Task 4: Iterative resolution happy path
- [ ] Task 5: CNAME chains, NXDOMAIN, NODATA, limits
- [ ] Task 6: Transport robustness
- [ ] Task 7: QNAME minimisation

### Checkpoint B: Recursion
- [ ] Success criterion 1 met; manual `example.com A` resolves from the internet

### Phase 3: DNSSEC
- [ ] Task 8: Testkit DNSSEC zones
- [ ] Task 9a: Chain of trust and signature verification
- [ ] Task 9b: Validation status, AD, SERVFAIL + EDE, CD
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

W1 → W2 → W3 are sequential. W4 and Phase 2 can run in parallel once W3 is done.
Task 8 (testkit) alongside Tasks 5–7; Task 15 alongside Phase 3/4.

## Dependencies

| Crate | Purpose | Status |
|---|---|---|
| `tokio` | runtime, sockets, timers | approved |
| `ring` | DNSSEC signature verification, digests | **new — approval requested** |
| `thiserror`, `tracing`, `serde`, `toml` | errors, logging, config | approved |
| `rand` | query ids, source ports | approved |
| `hickory-proto`, `hickory-server` (`=0.26.3`) | **testkit / dev only**, independent oracle | approved |
| `proptest` | property tests for encode/decode (dev) | **new — approval requested** |
| `libfuzzer-sys` + `cargo-fuzz` (nightly toolchain, fuzz crate only) | fuzzing | **new — approval requested** |
| `criterion` | benchmarks (dev) | approved |
| `cargo-llvm-cov` | coverage (tool) | approved |

Cache: implemented in-house (size-in-bytes bounded); no `moka`.

## Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Own wire parser has bugs on untrusted input | High | Strict limits, no panics (`clippy` + `#![forbid(unsafe_code)]`), fuzzing (W5), hickory oracle round-trips |
| In-house recursion + wire format increase effort | Med | Accepted by the owner; tasks stay S/M; testkit already in place |
| DNSSEC validation is subtle (canonical form, NSEC3 opt-out, wildcards, algorithms) | High | Dedicated testkit zones per case (Task 8, signed by hickory = independent implementation); cross-check with `delv`/`kdig +dnssec` at Checkpoint C |
| Testkit signing with controllable time | Med | Sign at test time with explicit inception/expiration; no static fixtures with expiring signatures |
| Fake hierarchy on one loopback IP with many ports | Med | Root hints and an address map carry `ip:port`; resolver accepts a test-only address override |
| IPv6 unavailable in CI/container | Low | IPv6 tests skip with a clear message when `::1` cannot bind |

## Decisions

Approved 2026-10-24:

1. Toolchain installed: `rustup` (stable 1.99.1, rustfmt, clippy), `bind-utils`, `knot-utils`.
2. RFC 5011: built-in anchors per release + UI warning on mismatch; tracking may follow later.
3. CI: GitHub Actions workflow (fmt, clippy, test, coverage) — done in Task 1.
4. Initial dependency list approved.
5. Implementation is delegated to Haiku/Sonnet subagents; the lead reviews every task before ticking it off.
6. ADR-0001: Option D (in-house wire format and DNSSEC logic; `ring` for crypto; hickory only as test oracle).
