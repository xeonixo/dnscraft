# ADR-0001: Recursion engine for the resolver module

- Status: Accepted — Option D (amended 2026-10-24, see "Final decision")
- Date: 2026-10-24
- Deciders: project owner, at Checkpoint A
- Scope: `crates/dnscraft-resolver` ([SPEC-resolver.md](../../SPEC-resolver.md))

## Context

The resolver must walk the delegation chain from the root, validate DNSSEC, cache, and meet the
requirements in SPEC-resolver.md. Plan risk R1 was that `hickory-recursor` (crates.io latest
stable 0.25.2, 2025-05; last prerelease 0.26.0-alpha.1, 2025-06-03) might be lagging while
`hickory-proto` is at 0.26.3 (2026-09-10). This spike checks (a) whether recursion moved in
hickory 0.26 and (b) whether the current implementation fits our requirements.

Findings on (a), verified against crates.io, the hickory-dns repository (`main` at 2026-10-22,
workspace version 0.27.0-alpha.1) and by compiling:

- The `hickory-recursor` crate is **abandoned**. It has had no release since 2025-06-03, and
  the repository no longer has a `crates/recursor` directory (commit 4d2fdd1 "Remove references
  to hickory-recursor").
- Recursion now lives in **`hickory-resolver` behind the cargo feature `recursor`**
  (`crates/resolver/src/recursor/`, about 2.3k lines of code plus 1.9k lines of tests). It
  is released as part of hickory-resolver 0.26.x (0.26.3 on 2026-09-10); the spike compiled and
  ran it from crates.io. The hickory-dns server exposes it as `recursor` feature, documented in
  the repo as "Recursive Resolution is Experimental!" (`crates/server/Cargo.toml`,
  `bin/Cargo.toml`).
- The crate split in 0.26: `hickory-proto` (wire types, DNSSEC primitives), new `hickory-net`
  (transports, `DnsHandle`, `DnssecDnsHandle` validator), `hickory-resolver`, `hickory-server`.
- API churn is real: `main` (0.27-alpha) already differs from 0.26.3 (for example `Query::new`
  signature). Any dependency must be pinned exactly.

So "the current recursor" is `hickory_resolver::recursor::Recursor` (0.26.3). That is what was
evaluated.

## Options considered

### A. Use hickory's recursor as-is (`hickory-resolver` 0.26.x, feature `recursor`)

Wrap `Recursor::resolve(Query, Instant, dnssec_ok)`. Gets iteration, glue handling, bailiwick
checks, loop/query-budget limits, QNAME minimisation (Strict/Relaxed), a DNSSEC validating mode
(`DnssecPolicy::ValidateWithStaticKey`), caches and a TTL policy for free.

Gaps (details in the table): no serve-stale, no prefetch, no per-domain flush, no forward zones,
no negative trust anchors, no RFC 5011, no EDE, no in-flight dedup, no way to set non-53 ports
for root hints or glue, `Instant::now()` and `SystemTime` used internally, AD bit is not set
and Bogus is returned as `Ok(..)` with Bogus-tagged records instead of SERVFAIL, default server
deny-list blocks 127.0.0.0/8. Roughly half of the functional requirements would still be ours to
build, and several of them (cache, serve-stale, flush, dedup, prefetch) need to sit *inside* the
cache, which we do not control. 45 open issues mention the recursor and 81 mention DNSSEC at the
time of writing (GitHub text search, not label counts), including correctness bugs in exactly the
areas we depend on (#4073, #4063, #4047, #4027, #3964, #3563, #2595).

### B. In-house recursion on `hickory-proto` (everything else ours)

Own iterator, transport, cache, and DNSSEC validator; `hickory-proto` only for message
types, name handling, (de)serialisation, and crypto-backed RRSIG/DS/NSEC3 primitives.
Full control over clock, ports, cache, dedup, serve-stale, EDE, NTAs. Highest effort and the
highest risk in DNSSEC (subtle: wildcards, opt-out, algorithm downgrade, KeyTrap-style
CPU attacks), which the plan already rates High risk.

### C. Hybrid: own iteration, transport, cache, and orchestration; reuse hickory's DNSSEC building blocks

Own everything except cryptographic and wire-format primitives (`hickory-proto`:
`dnssec` module, `TrustAnchors`, NSEC3 hashing, RRSIG verification) and, if it proves clean
in Task 9, the validator `hickory_net::dnssec::DnssecDnsHandle`, which is generic over any
`DnsHandle` and so can sit on top of our own iterator. The choice "use `DnssecDnsHandle` or write
a thin validator over proto primitives" is made in Task 9 under a time box, with the Task 8
testkit zones as the acceptance gate. Caveats seen in the spike: `DnssecDnsHandle` takes its
clock from the static `Time::current_time()` of the runtime provider (global, not injectable per
test) and it has open correctness issues (#4047, #4063, #3964, #3966).

## Evaluation

Legend: Yes = supported and evidenced; Partial = exists with limits; No = absent;
Unverified = not checked end-to-end. "Spike" means output in the Evidence appendix.
Source paths are relative to hickory-dns `main` (0.27-alpha) and were cross-checked against
the 0.26.3 crates compiled in the spike unless noted.

| Requirement | hickory recursor (0.26.3, A) | Evidence | Effort in-house (B/C) |
|---|---|---|---|
| DNSSEC: chain of trust, NSEC, NSEC3 | Yes (validating mode, NSEC3 iteration limits configurable) | `recursor/mod.rs` `ValidatingRecursor`, `DnssecConfig`; `net/src/dnssec/mod.rs`. Spike: example.com Secure, NSEC proof for NODATA at example.com Secure, NXDOMAIN under iana.org and nlnetlabs.nl with Secure SOA (denial type, NSEC vs NSEC3, not printed by the spike). NSEC3 opt-out and wildcard cases not exercised (Unverified) | C reuses it; B must write it (large) |
| DNSSEC: AD bit | No. Recursor returns per-record `proof` (Secure/Insecure/Bogus/Indeterminate); AD is left to the caller | Spike: `ad=false` while records are `Secure`. hickory-server's `catalog.rs` ~L1273 sets AD from the proofs, so mapping is easy but ours | Small, ours either way |
| DNSSEC: Bogus to SERVFAIL | No. Bogus returns `Ok` with Bogus-tagged records; caller must turn it into SERVFAIL | Spike: `dnssec-failed.org` gave `rcode=NoError`, proof `Bogus`. Server side converts at `catalog.rs` ~L1278 | Small, ours either way |
| DNSSEC: Extended DNS Errors (RFC 8914) | No (only the EDNS option code constant exists; open issue #2301) | `grep` of `crates/` finds no EDE generation; `proto/src/rr/rdata/opt.rs` has the code only | Ours (we must classify failure reasons ourselves) |
| DNSSEC: honouring CD | Partial. Validation mode is chosen at construction (`ValidationDisabled` vs validating); no per-query CD switch. Caller can run a second non-validating path. Outbound queries from validator clear CD (#3966 open) | `recursor/mod.rs` `RecursorMode`; `net/src/dnssec/mod.rs` L1159 | Ours (cache must key on CD) |
| DNSSEC: negative trust anchors | No | no occurrences of NTA in recursor/dnssec code | Ours (small) |
| DNSSEC: root anchors, RFC 5011 | Built-in anchors yes (2018 key 20326 and 2024 key 38696); RFC 5011 No (`// TODO RFC5011`) | `proto/src/dnssec/trust_anchor.rs` L31-32; `recursor/mod.rs` L709. Matches the plan's choice (b): built-in anchors only | Same for all options |
| QNAME minimisation (RFC 9156) | Yes (`QNameMinimization::Strict` default, `Relaxed`) | `recursor/mod.rs` `RecursorOptions.qname_minimization`; `handle.rs` L637; e2e tests in `conformance/e2e-tests/src/recursor/qmin_relaxed`. Wire behaviour not checked in the spike (Unverified) | Ours (moderate) |
| Serve-stale (RFC 8767) | No. `ResponseCache` drops entries at TTL. Open issue #2106; #3680 was closed in 2026-05 but no implementation exists on `main` (reason not investigated) | `resolver/src/cache.rs`; `grep -i stale` finds only unrelated tests | Ours (needs own cache) |
| Hooks for prefetch | No. No hit counters, no expiry callbacks, caches are private to the handle | `cache.rs`, `recursor/handle.rs` (`ns_cache` is an `lru-cache`) | Ours (needs own cache) |
| Cache size control | Partial. `response_cache_size` (entries, not MB; `u64`) and `ns_cache_size` (entries); TTL clamps via `TtlConfig` (positive/negative min/max) | `RecursorOptions` in `recursor/mod.rs` | Ours (byte-bounded cache per spec) |
| Flush all / by domain | No. `clear()` and `clear_query()` exist but are `pub(crate)`; the recursor exposes no flush API. Dropping and rebuilding the whole `Recursor` is the only flush | `resolver/src/cache.rs` L194-198 | Ours (needs own cache) |
| Forward zones / conditional forwarding | No in recursor (hickory-server has a separate forwarder authority, not integrated with the recursor) | no "forward" in `recursor/handle.rs`; `RecursorError`/`AuthorityData` naming is a remnant only | Ours (moderate, plus loop detection) |
| Injectable root hints, custom ports | Hints injectable as `&[IpAddr]` (no ports). Port 53 is hard-wired (`ConnectionConfig::new`), glue is IP-only. Workaround: the generic `ConnectionProvider`/`RuntimeProvider` can rewrite destination addresses; hickory's own tests use a `MockProvider` (`tests/test-support`). Also default `deny_server` blocks 127.0.0.0/8, must be cleared in tests. Not tried in the spike (Unverified) | `recursor/mod.rs` `Recursor::new(roots: &[IpAddr], ..)`, `handle.rs` `name_server_config`; `net/src/runtime.rs` L252 `RuntimeProvider` | B/C: own transport takes `SocketAddr` natively |
| ECS behaviour | Recursor never adds an ECS option (no code path in `recursor/`); ECS is only used as cache-key input in the stub `NameServerPool`. Incoming ECS is irrelevant because the API takes a `Query`. Wire behaviour not captured (Unverified) | `grep -i subnet resolver/src/recursor` is empty; `name_server_pool.rs` L1024-1048 | Trivial in B/C (never emit) |
| Injectable clock (RRSIG expiry) | Partial. Cache and `resolve` take an `Instant` parameter; the validator reads `Time::current_time()` (static fn of the `RuntimeProvider::Timer` type) so a custom `RuntimeProvider` with a test `Timer` can move it, but only through a process-global. Internals also call `Instant::now()` (e.g. `handle.rs` L1081) | `net/src/dnssec/mod.rs` L246; `net/src/runtime.rs` L375 | B/C: clock passed explicitly |
| In-flight dedup | No. Only per-request loop guards (`in_flight_zones`, `in_flight_cnames`) that reject cycles; identical concurrent questions are not coalesced | `recursor/handle.rs` L947-1040; open issue #2984 on structure | Ours (small) |
| Async / tokio | Yes (feature `tokio`, `TokioRuntimeProvider`; also runtime-agnostic via `RuntimeProvider`) | Spike runs on tokio 1.x; `resolver/Cargo.toml` features | Ours on tokio directly |
| Loop and amplification guards | Yes: `recursion_limit` 24, `ns_recursion_limit` 24, per-request budget 200 queries, glueless width 5, cyclic referral short-circuit, CNAME loop to SERVFAIL (#3942/#3969 closed) | `handle.rs` constants; commits e4badc7, d18a76a, 284f13e | Ours (specified limits: CNAME at most 16) |
| Hardening: bailiwick, ghost domain, 0x20, source-port avoidance | Yes (bailiwick checks, ghost-domain test, `case_randomization` option, `avoid_local_udp_ports`) | `recursor/tests/ghost_domain.rs`, `RecursorOptions` | Ours |
| Negative caching | Partial: open issues #2595 (no negative cache for recursor), #3563 (failures not cached) | issue tracker | Ours |
| Maintenance status | Crate `hickory-recursor`: dead since 2025-06. Recursor code in hickory-resolver: active (about 300 commits on `main` since 2026-08-01, 79 of them touching recursor or DNSSEC code; two main authors: David Cook 151, Dirkjan Ochtman 76) but labelled experimental, with open correctness bugs (see Option A) and API churn between 0.26 and 0.27-alpha | `git log` of a depth-300 clone; GitHub search API | n/a |
| License | MIT OR Apache-2.0 (same as this project) | repo `Cargo.toml` `[workspace.package]` | n/a |

## Final decision (supersedes the recommendation below)

At Checkpoint A the owner chose to write as much as reasonable in-house. **Option D** is accepted:

- **In-house:** DNS wire format (names, compression, all needed RDATA types, EDNS, messages) in a
  new shared crate `dnscraft-proto`, DNSSEC validation logic (canonical form, RRSIG verification
  orchestration, DS/DNSKEY chain, NSEC/NSEC3 proofs, key tags, NSEC3 hashing), and everything
  listed under Option C (iteration, transport, cache, dedup, serve-stale, prefetch, forward zones, EDE).
- **Third-party, by design:** cryptographic primitives via `ring` (RSA/SHA-x, ECDSA P-256/P-384,
  Ed25519, SHA-1/256/384 digests) — never hand-written crypto; `tokio` runtime; later `rustls`/`quinn`.
- **hickory** stays only as a dev-dependency of `dnscraft-testkit`, where it serves as an independent
  oracle: every testkit response is encoded by hickory and decoded by `dnscraft-proto`, so parser
  bugs on either side surface in tests.
- The wire parser handles untrusted internet input: strict limits, no panics, and `cargo-fuzz`
  targets are mandatory.

Consequences: a new "wire format" phase (tasks W1–W5) precedes recursion; Task 9's time box for
`DnssecDnsHandle` is dropped (own validator over `ring`, split into 9a/9b); Task 10 is implemented
in-house. No dependency on hickory's API churn (0.27 already changes it) or its open DNSSEC bugs.

## Recommendation of the spike (Option C, not adopted)

Recommend **Option C**: implement iteration, transport, cache, in-flight dedup, serve-stale,
prefetch, forward zones, local reverse zones, EDE, and result mapping in `dnscraft-resolver`,
on top of `hickory-proto` (and `hickory-net` if its transport or `DnsHandle` abstraction helps),
and reuse hickory's DNSSEC primitives rather than writing cryptography. Pin `hickory-proto` and
friends with exact versions (`=0.26.3`).

Reasons:

1. **The recursor does not cover the spec's differentiating requirements.** Serve-stale,
   prefetch, per-domain flush, MB-bounded cache, forward zones, NTAs, EDE, dedup, per-query CD
   and custom ports are all missing, and most of them must live inside the cache and the
   iteration loop, which are private. Wrapping would mean writing a second cache and resolution
   front end around a first one, and bypassing its cache for correctness anyway.
2. **Testability requirements point the same way.** Success criteria 1-7 rely on an in-process
   fake hierarchy on `127.0.0.1:random` with an injectable clock. The recursor has no port
   concept in root hints or glue and only a process-global time source for validation. These
   are workable only through provider-level hacks.
3. **Quality of the recursor is still moving.** It is explicitly experimental, was moved between
   crates in 0.26, and has open bugs in zone-cut discovery, CNAME-for-DS, and Bogus
   classification (#4073, #4063, #4047, #4027). Adopting it means inheriting its bug stream
   with no control over fixes, while our own testkit would still need to catch them.
4. **Option B's main cost is DNSSEC, and C removes most of it.** The crypto, DS digest,
   NSEC3 hashing, trust-anchor handling, and (probably) the validator logic exist in
   `hickory-proto` / `hickory-net` and are exercised by hickory's own tests. Iteration, caching,
   dedup and forwarding are comparatively routine to write and test with Task 3's testkit.
5. **Cost of being wrong is bounded.** If a later review prefers A, the public API in the spec
   (`Resolver::new/resolve/flush/stats`) hides the engine, so a swap remains possible; the
   reverse (starting from A, then discovering missing features) would be more disruptive.

What is **not** established by this spike (honest caveats):

- Whether `DnssecDnsHandle` can be used cleanly on top of our own iterator with an injectable
  clock and without its open bugs. Decide in Task 9 with a fixed time box (suggest 1 day); the
  fallback is a thin validator in `dnscraft-resolver` over `hickory-proto` verification
  primitives, which raises Task 9-10 effort from M to L.
- NSEC3 opt-out/wildcard correctness of hickory's validator, hickory's QNAME-minimisation wire
  behaviour and non-53 port workarounds were not exercised.
- Effort estimate for C is qualitative: Tasks 4-7 and 11-15 are "implement" and the plan's
  fallback note ("roughly doubles Phase 2-3 effort") applies to those phases.

## Consequences

For tasks 4-16 in `tasks/todo.md`. "Implement" means written in `dnscraft-resolver`;
"wrap/configure" means mostly hickory code.

| Task | Verdict | Note |
|---|---|---|
| 4 Iterative resolution happy path | Implement | Own iterator; transport takes `SocketAddr` so root hints with ports work. `hickory-proto` for messages |
| 5 CNAME chains, NXDOMAIN, NODATA, limits | Implement | Limits as in spec (CNAME at most 16, delegation depth, query budget). Learn from hickory's guard list (cyclic referral, glueless width) |
| 6 Transport robustness | Implement | EDNS 1232, TC to TCP, RTT-based server selection, retries. May reuse `hickory-net` transports if they accept explicit `SocketAddr` (check at start of task) |
| 7 QNAME minimisation | Implement | RFC 9156 with relaxed fallback; hickory's `Relaxed` mode behaviour is a useful reference |
| 8 Testkit DNSSEC zones | Implement | Sign with `hickory-proto` DNSSEC signing primitives and an explicit clock |
| 9 Chain-of-trust validation | Wrap/configure for primitives; implement orchestration | Time-boxed choice between `DnssecDnsHandle` over our iterator and a thin own validator; built-in anchors via `TrustAnchors` (2018 and 2024 keys present) |
| 10 Denial of existence and NTAs | Wrap/configure for NSEC/NSEC3 checks if `DnssecDnsHandle` is kept, otherwise implement; NTAs always implement | Needs dedicated tests for opt-out and wildcard proofs (not verified in spike) |
| 11 Positive/negative cache | Implement | Byte-bounded, RFC 2308, flush all or by domain, TTL clamps; hickory's `ResponseCache` is entry-based and has no flush API |
| 12 In-flight dedup and prefetch | Implement | Neither exists in hickory |
| 13 Serve-stale | Implement | Absent upstream |
| 14 Forward zones | Implement | Absent in recursor; loop protection ours |
| 15 Local reverse zones and ECS stripping | Implement | ECS: never emit (hickory also never emits it) |
| 16 Stats, codes, benchmark, example, acceptance | Implement | EDE mapping and AD/SERVFAIL mapping from `Secure`/`Bogus` are ours in every option |

Further consequences:

- Dependencies to add to the approved list: `hickory-proto = "=0.26.3"` (with a DNSSEC crypto
  feature, `dnssec-ring` worked in the spike) and possibly `hickory-net = "=0.26.3"`. Not
  `hickory-recursor`, and not `hickory-resolver` with `recursor`.
- Cost: the plan's stated fallback applies; Phases 2-3 grow. The plan must be revised and
  re-approved (the lead's step).
- Upgrade path: hickory 0.27 changes APIs; budget a deliberate upgrade task rather than
  floating versions.
- Revisit trigger: if hickory ships serve-stale, a flush API, and port-aware roots, and its
  DNSSEC bug backlog shrinks, reconsider Option A behind the unchanged public API.

## Evidence appendix

### Registry and repository facts (retrieved 2026-10-24)

- crates.io `hickory-recursor`: versions 0.25.2 (2025-05-03), 0.26.0-alpha.1 (2025-06-03); nothing later.
- crates.io `hickory-proto`, `hickory-net`, `hickory-resolver`, `hickory-server`, `hickory-dns`: 0.26.3 (2026-09-10); 0.26.0 on 2026-04-16.
- hickory-dns `main` (HEAD 2026-10-22): workspace members `crates/net`, `crates/proto`, `crates/resolver`, `crates/server`; no recursor crate; `crates/resolver/Cargo.toml` has `recursor = ["dep:async-recursion", "dep:lru-cache"]`; `crates/server/Cargo.toml` and `bin/Cargo.toml` mark it "Experimental".
- Commit "Remove references to hickory-recursor" (4d2fdd1); recent recursor commits include "recursor: return SERVFAIL on CNAME loops", "recursor: implement per-request query limit", "Order CNAME chain records in recursor answers".
- Selected open issues: #4073 (CNAME chased for DS queries), #4063 (SERVFAIL on ancestor NS query makes insecure names Bogus), #4047 (valid positive answer marked Bogus), #4027 (Bogus for unsigned zone with no NS at apex), #3964 (data fetch failure reported as Bogus), #3966 (validating outbound queries set AD and clear CD), #3563 and #2595 (negative/failure caching), #3562 (no DNAME), #2106 (serve-stale), #2301 (EDE).
- Spike dependency: `hickory-resolver =0.26.3` with features `recursor`, `tokio`, `dnssec-ring`; compiled on Rust 1.99.1.

### Spike code

`spikes/hickory-recursor/` (own empty `[workspace]`, not part of the root workspace).
Calls `Recursor::new(roots, DnssecPolicy::ValidateWithStaticKey(DnssecConfig::default()), None,
RecursorOptions::default(), TokioRuntimeProvider::default())` with four IANA root addresses and
then `recursor.resolve(Query, Instant::now(), true)`.

### Spike output (real internet, 2026-10-24)

`rcode`/`ad` in the output are from the returned `Message`; for negative answers the recursor
returns an `Err(RecursorError)` carrying SOA and proof, so no rcode exists and nxdomain/nodata
flags are printed instead. Record `proof` is hickory's per-record DNSSEC status.

```
=== example.com. A
  ok rcode=NoError ad=false cd=false elapsed=259.245713ms
  A example.com. ttl=300 proof=Secure
  A example.com. ttl=300 proof=Secure
  RRSIG example.com. ttl=300 proof=Secure
=== dnssec-failed.org. A
  ok rcode=NoError ad=false cd=false elapsed=2.603013761s
  A dnssec-failed.org. ttl=300 proof=Bogus
  RRSIG dnssec-failed.org. ttl=300 proof=Indeterminate
=== nonexistent-dnscraft-spike.example.com. A
  err elapsed=51.722932ms: negative response nxdomain=false nodata=true soa_proof=Some("Secure")
=== nxd-dnscraft-spike.iana.org. A
  err elapsed=403.824919ms: net error: DNS error: no records found for Query { name: Name("nxd-dnscraft-spike.iana.org."), query_type: NS, query_class: IN } nxdomain=true nodata=true soa_proof=Some("S
=== nxd-dnscraft-spike.nlnetlabs.nl. A
  err elapsed=181.855242ms: net error: DNS error: no records found for Query { name: Name("nxd-dnscraft-spike.nlnetlabs.nl."), query_type: NS, query_class: IN } nxdomain=true nodata=true soa_proof=Som
=== www.github.com. A
  ok rcode=NoError ad=false cd=false elapsed=217.780846ms
  CNAME www.github.com. ttl=3600 proof=Insecure
  A github.com. ttl=60 proof=Insecure
  NS github.com. ttl=900 proof=Insecure
  NS github.com. ttl=900 proof=Insecure
  NS github.com. ttl=900 proof=Insecure
  NS github.com. ttl=900 proof=Insecure
  NS github.com. ttl=900 proof=Insecure
  NS github.com. ttl=900 proof=Insecure
  NS github.com. ttl=900 proof=Insecure
  NS github.com. ttl=900 proof=Insecure
=== example.com. A
  ok rcode=NoError ad=false cd=false elapsed=359.065µs
  A example.com. ttl=300 proof=Secure
  A example.com. ttl=300 proof=Secure
  RRSIG example.com. ttl=300 proof=Secure
```

Observations from the output:

- `example.com A`: records `Secure`, second query served from cache in 0.36 ms (cache hit
  path works). `ad=false` although every record is `Secure`: AD must be derived by the caller.
- `dnssec-failed.org A`: **not SERVFAIL**. Returns `NoError` with the A record tagged `Bogus`.
  The caller must convert that to SERVFAIL (plus EDE, which hickory does not produce).
- `nonexistent-dnscraft-spike.example.com A`: Cloudflare "black lies" produced a NODATA with
  a Secure NSEC proof (example.com is a Cloudflare-signed zone), not NXDOMAIN. Two further
  checks under `iana.org` and `nlnetlabs.nl` returned NXDOMAIN with a Secure SOA.
  The error text mentions an `NS` query because of minimisation-driven zone-cut lookups; the
  mapping from this error to a final rcode and authority section is ours to build.
- `www.github.com A`: CNAME chain resolved (CNAME then A) and tagged `Insecure` (github.com is
  unsigned). The answer also includes the `NS github.com.` records in the same list, which is
  odd for a client-facing answer and would need filtering (observed; not investigated further).
- Not exercised: a confirmed NSEC3 negative proof (the denial type of the NXDOMAIN cases was not printed), CD handling,
  non-53 ports, forward zones, stale, flush.
