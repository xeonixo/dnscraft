# Implementation Plan: `filtering` module

> Spec: [SPEC-filtering.md](../SPEC-filtering.md) · Project spec: [SPEC.md](../SPEC.md) ·
> Tasks: [todo.md](todo.md) · Resume log: [progress.md](progress.md) ·
> Previous module: [archive/resolver-plan.md](archive/resolver-plan.md)

## Overview

Build `crates/dnscraft-filtering`: an AdGuard-DNS-compatible rule parser and rule
builder, a compact in-memory match index with AdGuard priority semantics, filter sets,
temporary allows, list download/caching/scheduling with atomic hot reload, and the
blocked-services catalog. Pure library, no DNS transport; `policy` consumes it later.

## Architecture Decisions

- **Parser is pure and hardened** (lists are untrusted): line-based, no panics, per-line
  length cap (4 KiB), fuzzed. Unsupported rules are skipped with a reason, never fatal.
- **Match index (in-house, no extra dependency):**
  - Domain rules (`||x^`, plain domains, hosts lines — the vast majority) live in one
    byte arena of reversed, lower-cased names plus a sorted `Vec<u32>` of offsets.
    Lookup walks the queried name's suffixes (≤ 127) and binary-searches each.
    Expected ≈ 35–45 MB for the reference set, no per-entry heap allocation.
  - Per-entry flags (block/allow, important, subdomains, dnstype set, source id) in a
    parallel compact `Vec`; sources referenced by `u32` id → list id + line number.
  - Patterns (wildcards) and regexes (few thousand at most) are evaluated only after the
    domain index, with a cheap literal prefilter (required substring) to skip most.
  - If the benchmark misses the budgets, fall back to a hash table keyed by suffix hash
    (`hashbrown` is already in the lockfile) — decided at Checkpoint B, not up front.
- **Filter sets share list data:** each list is parsed once into an immutable `ListIndex`.
  A set's effective index is built by merging its lists' indexes plus custom rules and
  service rules (dedup + `$badfilter` applied at build time). Sets with the same list
  combination share one merged index (`Arc`), so typical setups hold one copy.
- **Hot reload:** `RwLock<Arc<Snapshot>>`; readers clone the `Arc` (lock held for
  nanoseconds), rebuilds run on a blocking thread and swap atomically. No `arc-swap` dep.
- **Clock injectable** (reuse the resolver's `Clock` trait shape; filtering gets its own
  small trait to keep the dependency graph clean) for temporary allows, pause, schedules
  of updates.
- **I/O isolated:** `ListStore` (data directory, atomic writes, metadata JSON) and
  `Fetcher` (HTTP) behind small traits, so tests use a temp dir and a local test server.

## Dependencies (need approval)

| Crate | Purpose | Notes |
|---|---|---|
| `reqwest` 0.12, `default-features = false`, features `rustls-tls` (ring provider, webpki roots), `gzip` | list + catalog downloads | Also the natural HTTP client for `tls` (ACME, Cloudflare, DynDNS echo) and `clients` (UniFi API) later, so it is paid for once. Redirect policy hook refuses HTTPS→HTTP. webpki roots because the container has no system CA store. |
| `regex` 1.x (already in the lockfile) | regex rules | Linear-time engine; compiled size limit per rule (`RegexBuilder::size_limit`). |
| `idna` 1.x (already in the lockfile) | non-ASCII rules → punycode | Alternative if you prefer smaller: skip non-ASCII rules with a warning (lists are > 99.9 % ASCII). |
| `serde` + `serde_json` (serde already approved) | `services.json` catalog, list metadata | — |

Dev only: none new (local HTTP test server is hand-written on tokio, as the testkit does
for DNS).

## Dependency graph

```
F1 skeleton + types ── F2 core rule parser ── F3 modifiers + IDNA ── F4 wildcard/regex
                               │                                          │
                               └── F5 builder + fuzz + proptest ◄─────────┘
                                          │
                                M1 domain index + verdicts
                                          │
                                M2 filter sets (merge, dedup, $badfilter, sharing)
                                          │
                     M3 chain, temporary allow, pause, counters
                                          │
                                M4 benchmark + memory (Checkpoint B)
                                          │
         L1 list store ── L2 fetcher ── L3 scheduler + hot reload + status
                                          │
                                L4 blocked services catalog
                                          │
                     C1 engine API polish, docs, coverage, fuzz, real-list run
```

## Task List

### Phase 1: Rules
- [x] Task F1: Crate skeleton, core types, error codes
- [x] Task F2: Core rule parser (adblock domain rules, exceptions, anchors, plain, hosts, comments, skipped categories)
- [x] Task F3: Modifiers and IDNA
- [x] Task F4: Wildcard and regex rules
- [x] Task F5: Rule builder, round trip, fuzz target, proptest
- [ ] Task F6: IP rules (answer filtering) — added after Checkpoint A

### Checkpoint A: Rules
- [x] All syntax/modifier unit tests green; fuzz target 10 min clean
- [x] All 19 reference lists parse (manual run), skip report reviewed with owner

### Phase 2: Matching
- [x] Task M1: Domain index and verdicts with reasons
- [x] Task M2: Filter sets (merge, dedup, `$badfilter`, shared indexes, block mode, custom rules)
- [ ] Task M3: CNAME chain matching, temporary allows, pause, counters
- [ ] Task M4: Benchmark and memory measurement on a generated reference-sized set

### Checkpoint B: Matching
- [ ] Priority table (success criterion 2) green
- [ ] Budgets met (criterion 4) or fallback index decided with owner

### Phase 3: Lists and services
- [x] Task L1: List store (data directory, atomic writes, metadata, local file lists)
- [x] Task L2: Fetcher (conditional GET, size cap, timeout, redirect policy, last-good fallback)
- [ ] Task L3: Scheduler, hot reload, `apply_config`, list status and unique contribution
- [ ] Task L4: Blocked services catalog

### Checkpoint C: Lists and services
- [ ] Criteria 5 and 6 met; reload never blocks matching (concurrency test)

### Phase 4: Completion
- [ ] Task C1: Engine API polish, stats, README, error-code table, coverage ≥ 80 %, real-list acceptance run

### Checkpoint D: Complete
- [ ] All 8 success criteria met; review (`/agent-skills:code-review-and-quality`) passed

## Parallelization

F2 → F3 → F4 sequential (same parser files). F5 can start after F2 (builder) and get the
fuzz target extended after F4. L1 and L2 can run in parallel with M2–M4 (separate files).
L4 after L1/L2.

## Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Memory budget missed with 2.25 M rules | High | Arena + offsets design; measured in M4 before list I/O exists; hash fallback ready |
| AdGuard priority/modifier semantics subtly differ | Med | Table-driven tests from AdGuard's documented examples; manual comparison on a few real lists |
| Regex rules from lists are slow or huge | Med | Size limit per regex, literal prefilter, count of regex rules reported; budget test with many regexes |
| Malicious/garbled list content | Med | Line cap, fuzzing, skip-with-reason, 64 MiB cap, last-good fallback |
| HTTP client weight (binary size budget 30 MB image) | Low | `default-features = false`, rustls+ring only; size checked when the binary exists |
| Tests hitting the internet | Low | Local test server only; real lists only in manual runs |

## Decisions

Approved by owner 2026-10-25: this plan, the dependency list above (idna included, not the skip alternative), and the CI fuzz job for the rule parser.
