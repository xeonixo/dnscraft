# Implementation Plan: `policy` module

> Spec: [SPEC-policy.md](../SPEC-policy.md) · Project spec: [SPEC.md](../SPEC.md) ·
> Tasks: [todo-policy.md](todo-policy.md) · Resume log: [progress.md](progress.md) ·
> Sibling plans: [plan-clients.md](plan-clients.md), [plan-tls.md](plan-tls.md)

## Overview

Build `crates/dnscraft-policy`: the pipeline between `listeners` and `resolver` / `filtering`.
`PolicyEngine::handle(RequestContext)` does the following:
- selects view + profile (Client ID > longest prefix > default);
- runs the twelve pipeline steps of the spec (local records, ClientDirectory names, canaries,
  filter, SafeSearch + second filter, resolve, CNAME uncloaking, answer-IP rules, rebind, AAAA
  suppression);
- returns the response plus a `DecisionRecord`.

Configuration is an `Arc<PolicySnapshot>` swapped on `apply_config`.

## Architecture Decisions

- **Pipeline as small step functions.** Each step is a function
  `(&Ctx, &mut Draft) -> Flow::{Continue, Answer(Synth)}` that appends a `DecisionStep`. `handle`
  calls them in spec order. This gives one place for the order and each step is testable on its
  own, without generic plugin machinery.
- **Output type.**
  - `PolicyAnswer { message: Message, ede: Option<ExtendedError>, record: DecisionRecord }`.
  - `ExtendedError` is reused from the resolver. The listeners attach the EDE and set the
    message id, the same contract as `resolver::Answer`.
  - The AD bit is set only when the answer is an unmodified resolver answer with `Secure`.
    Every synthesis and modification goes through one `clear_ad` helper.
- **Snapshot.**
  - Client ID → view in a `HashMap`.
  - Subnets in two per-family tables keyed by prefix length (`HashMap<masked addr, ViewIdx>`
    per present length, scanned longest first; ≤ 33 + 129 lookups worst case, typically
    2–3 lengths).
  - View records in a `HashMap<Name, RrSets>`.
  - Everything is built and validated in `PolicySnapshot::build(config, known_sets, known_zones)`.
- **Names.** Policy works on `dnscraft_proto::Name`. It converts to filtering's `DomainName`
  once per checked name. A name filtering cannot represent (e.g. a label with characters outside
  its rules) is treated as `Pass` and recorded in the decision steps.
- **Forward-zone knowledge.** Policy needs to know whether a forward zone covers a name (for the
  special-use NXDOMAIN rule) and which zone ids exist (config validation). P5 adds two small
  read-only resolver accessors:
  - `Resolver::forward_zone_ids() -> Vec<ForwardZoneId>`
  - `Resolver::forward_zone_for(&Name, Option<&[ForwardZoneId]>) -> Option<ForwardZoneId>`

  Pure lookups, no behaviour change.
- **Clock.** Pause timing uses `dnscraft_filtering::Clock` (policy already depends on
  filtering). Callers pass the same clock to `FilterEngine` and `PolicyEngine`.
- **Locks.** No lock is held across an `await`. `handle` clones the snapshot `Arc` once at
  entry.
- **Counters.** Per-view and per-profile `AtomicU64` counters (queries, blocks, local hits)
  live next to the snapshot. On reload they are carried over by id.
- **Test queries.** `test_query: true` sets `PolicyAnswer.loggable = false`. Policy never writes
  logs itself; `control-api` does, so the "never log" rule is a flag that a spy test checks.

## Cross-module decisions

These apply to all three plans.

1. **`ClientDirectory` returns policy-owned types.**
   - The spec sketch returns `Arc<ClientInfo>`, but `ClientInfo` lives in `dnscraft-clients`,
     and policy must not depend on it.
   - The trait (defined in `dnscraft-policy`) is:
     - `addresses(&self, fqdn: &Name) -> Option<Arc<[IpAddr]>>`. `None` means unknown;
       `Some(empty)` means known but without addresses, which gives NODATA.
     - `reverse(&self, ip) -> Option<Arc<str>>`
     - `local_domains(&self) -> Arc<[String]>`
   - `by_ip` is dropped from the trait. Policy never needs it; log enrichment in `control-api`
     uses `ClientLookup::by_ip` directly.
   - `clients` stores `ClientInfo.addresses` as `Arc<[IpAddr]>`, so the `control-api` adapter is
     an `Arc` clone.
   - This changes the wording of the spec sketch, not its behaviour. Both specs get a one-line
     note when P5 lands.
2. **Each crate has its own small `Clock` trait** (resolver, filtering, clients, tls), except
   that policy reuses filtering's. No shared "common" crate yet; revisit when `control-api`
   wires them.
3. **Secrets** (`*_FILE` or env) use a small per-crate helper with the same behaviour (clients,
   tls). Duplicated about 20 lines on purpose rather than a new shared crate.
4. **Client-ID charset:** `[a-z0-9-]{1,63}`, so it is a valid DNS label for the DoT/DoQ
   hostname. Policy validates ids with that rule. The reserved-label check stays in
   `control-api` registration, using `tls::ReservedLabels`.
5. **Suggested build order:**
   - `policy` and `tls` can be built in parallel. Both are on the critical path to `listeners`.
   - `clients` is only needed by `control-api`, so it can come last.
   - Policy needs R2 committed (done on 2026-10-25 per progress.md).

## Dependencies (need approval — all three plans)

| Crate | Version / features | Used by | Kind | Already in lockfile? | Alternative |
|---|---|---|---|---|---|
| `rustls` | 0.23, `default-features = false`, `ring`, `std`, `tls12` | clients (pin verifier), tls (cert resolver) | normal | yes (via reqwest) | none (reqwest exposes no pinning hook) |
| `ipnet` | 2 | clients, policy (CIDRs) | normal | yes | hand-written prefix type (~60 lines per crate) |
| `time` | 0.3, `parsing` | clients (`connectedAt` RFC 3339) | normal | yes | hand-written RFC 3339 parser |
| `instant-acme` | 0.8.5, `default-features = false`, `ring`, `rcgen`, `time`, `x509-parser` (+ `hyper-rustls` only as fallback) | tls | normal | no | none comparable without aws-lc |
| `rcgen` | 0.14, `default-features = false`, `ring`, `pem` | tls (key + CSR); clients, tls tests (self-signed) | normal / dev | no (pulled by instant-acme) | — |
| `x509-parser` | 0.18 | tls (`not_after`) | normal | no (pulled by instant-acme) | trust `meta.json` only (weaker) |
| `rustls-pki-types` | 1, `std` | tls (PEM) | normal | yes (testkit) | `rustls-pemfile` |
| `tokio-rustls` | 0.26 | clients, tls tests (TLS mock servers) | dev | yes | — |

Policy itself needs only `ipnet`, plus the workspace crates (`dnscraft-proto`,
`dnscraft-resolver`, `dnscraft-filtering`, tokio, thiserror, tracing). Its dev-dependency is
`dnscraft-testkit`.
Versions were checked with `cargo info` / `cargo search` on 2026-10-25. instant-acme 0.9.0
exists on GitHub main but is not released; pin 0.8.5.

## Dependency graph

```
R2 (resolver, done) ─┐
                     ▼
P1 skeleton, config model, validation, errors
   └── P2 selection
          └── P3 engine skeleton: handle → resolve passthrough → emit (AD, ANY, ECS, test_query)
                 ├── P4 view local records (step 1)
                 ├── P5 ClientDirectory + special-use NXDOMAIN (step 2) + resolver accessors
                 ├── P6 canaries (step 3)
                 └── P7 filter qname + block/rewrite synthesis (steps 4, 4a–c)
                        └── P8 CNAME uncloaking + answer-IP (steps 8, 9)
                               └── P9 rebind + AAAA suppression (steps 10, 11)
P10 pause + hot reload + counters ── P11 SafeSearch/schedules config surface (steps 5, 6 stubbed)
P12 golden integration tests, AD/EDE matrix, bench, coverage, README
(P13 SafeSearch evaluation, P14 schedule evaluation — later, owner go required)
```

## Task List

### Phase 1: Skeleton
- [x] P1: Crate skeleton, config model, validation, errors
- [x] P2: View selection
- [x] P3: Engine skeleton with resolver passthrough and decision record
- [x] P4: View local records

### Checkpoint A: Skeleton
- [x] Query → selection → local record or resolver answer, end to end with the testkit; lead review done

### Phase 2: Pipeline
- [x] P5: ClientDirectory names/PTR + special-use NXDOMAIN
- [ ] P6: Bypass canaries
- [ ] P7: Filter the original qname, block/rewrite synthesis
- [ ] P8: CNAME uncloaking + answer-IP rules
- [ ] P9: Rebind protection + AAAA suppression

### Checkpoint B: Pipeline
- [ ] All twelve steps in order (SafeSearch stubbed); AD/EDE matrix rows covered; lead review

### Phase 3: Operations
- [ ] P10: Pause (global + per profile), hot reload, counters
- [ ] P11: SafeSearch + schedules config surface (stub, status "not applied")
- [ ] P12: Golden integration tests, bench, coverage, README

### Checkpoint C: Complete
- [ ] Spec success criteria 1–6; coverage ≥ 80 %; **owner approval**

### Later (owner go required, spec "ask first")
- [ ] P13: SafeSearch evaluation (steps 5, 6)
- [ ] P14: Schedule evaluation

## Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Hot path exceeds the 1 ms p50 cached budget through conversions and allocations | Med | P12 criterion bench (cache hit, filter miss); one `Name → DomainName` conversion per checked name; no `String` allocations in selection. |
| AD bit left set on a modified answer | High (DNSSEC honesty) | A single `clear_ad` path; matrix tests per answer kind; review item at Checkpoint B. |
| Spec text vs trait change (`ClientDirectory`) causes confusion | Low | Cross-module decision 1; spec note added in P5. |
| Block synthesis details (SOA in NXDOMAIN authority, TTLs) differ from AdGuard behaviour | Med | Follow SPEC-filtering block modes; NXDOMAIN/NODATA synthetic answers carry a synthetic SOA with TTL = the set's blocked-response TTL (or 10 s default); documented in P7. |
| Canary RDATA (Apple Private Relay) not verifiable | Low | Constant table marked `unverified` with the doc URL in a comment (spec decision 9). |

## Open Questions for the owner (answered 2026-10-25: deps approved, Pebble local only, order policy + tls → clients)

1. **Dependencies:** approve the table above once for all three modules?
2. **Pebble in CI (tls):** the recommendation is to keep the Pebble test `#[ignore]` and run it
   at checkpoints locally. A CI job with a Pebble container is a CI change and needs your go.
3. **UniFi check (clients O1):** about 2 minutes with three `curl` commands on your gateway
   before task C7. Report field names only.
4. **Order:** the recommendation is policy and tls first (critical path to `listeners`),
   clients after. Or keep the original order clients → tls → policy?
