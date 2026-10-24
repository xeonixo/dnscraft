# Tasks: `resolver` module

> Plan: [plan.md](plan.md) · Spec: [SPEC-resolver.md](../SPEC-resolver.md)
> Every task also clears the project Definition of Done: `cargo fmt --all --check`,
> `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test --workspace --locked`.

## Phase 1: Foundation

## Task 1: Workspace skeleton and toolchain

**Description:** Create the Cargo workspace with `crates/dnscraft-resolver` and
`crates/dnscraft-testkit` (empty libraries), pinned toolchain, lint settings, and
workspace-level dependency versions.

**Acceptance criteria:**
- [x] `Cargo.toml` workspace with edition 2024, `resolver = "3"`, shared `[workspace.dependencies]` and `[workspace.lints]`
- [x] `rust-toolchain.toml` pins a stable toolchain with `rustfmt` and `clippy`
- [x] Both crates compile and contain one trivial passing test
- [x] `.github/workflows/ci.yml` runs fmt, clippy, test, and coverage (`cargo llvm-cov`) on push/PR for `ubuntu-latest`

**Verification:**
- [x] `cargo build --workspace --locked` and `cargo test --workspace --locked` succeed
- [x] `cargo clippy --workspace --all-targets --locked -- -D warnings` is clean

**Dependencies:** None

**Files likely touched:** `Cargo.toml`, `rust-toolchain.toml`, `crates/dnscraft-resolver/{Cargo.toml,src/lib.rs}`, `crates/dnscraft-testkit/{Cargo.toml,src/lib.rs}`, `.github/workflows/ci.yml`

**Estimated scope:** S

## Task 2: Spike `hickory-recursor` vs. in-house, write ADR-0001

**Description:** Time-boxed evaluation (throwaway code in `spikes/`, not merged into crates).
Resolve real domains with `hickory-recursor` and check every spec requirement against it;
check whether hickory 0.26 relocated recursion. Record the decision.

**Acceptance criteria:**
- [ ] Checklist answered with evidence: DNSSEC (NSEC, NSEC3, AD, EDE, CD), QNAME minimisation, serve-stale, prefetch hooks, cache size control/flush, forward zones, injectable root hints/ports, ECS behaviour, maintenance status
- [ ] `docs/adr/0001-recursion-engine.md` states decision, alternatives, consequences
- [ ] Plan tasks 4–16 annotated with "wrap" vs. "implement" based on the decision

**Verification:**
- [ ] Manual: spike resolves `example.com A` (Secure) and `dnssec-failed.org A` (SERVFAIL) from the internet
- [ ] Human reviews ADR at Checkpoint A

**Dependencies:** Task 1

**Files likely touched:** `spikes/hickory-recursor/` (throwaway), `docs/adr/0001-recursion-engine.md`, `tasks/plan.md`

**Estimated scope:** M

## Task 3: Testkit fake hierarchy

**Description:** `dnscraft-testkit` starts in-process authoritative servers on loopback with
random ports for `.`, `test.`, and `example.test.` from inline zone definitions, and exposes
matching root hints. Servers can be stopped/started individually and record received queries.

**Acceptance criteria:**
- [x] `Hierarchy::start()` returns root hints (`ip:port`) and handles to each server
- [x] A query for `www.example.test. A` sent to the fake root returns a referral to `test.`
- [x] Per-server query log and `stop()`/`start()` available for tests

**Verification:**
- [x] `cargo test -p dnscraft-testkit`

**Dependencies:** Task 1

**Files likely touched:** `crates/dnscraft-testkit/src/{lib.rs,hierarchy.rs,zone.rs}`, `crates/dnscraft-testkit/Cargo.toml`

**Estimated scope:** M

## Checkpoint A: Foundation + decision
- [ ] All tests pass, clippy clean
- [ ] ADR-0001 reviewed by the human; `tasks/plan.md` and this file revised and re-approved

## Phase 2: Recursion

## Task 4: Iterative resolution happy path

**Description:** Public API (`Resolver::new`, `resolve`, `ResolverConfig`, `Answer`, errors with
`code()`) and iterative resolution from root hints with priming, following referrals and glue.

**Acceptance criteria:**
- [ ] `A` and `AAAA` for `www.example.test.` resolve through the fake hierarchy
- [ ] Priming query refreshes root NS set at startup
- [ ] Missing glue is resolved (out-of-bailiwick nameserver)

**Verification:**
- [ ] `cargo test -p dnscraft-resolver --test recursion`

**Dependencies:** Checkpoint A

**Files likely touched:** `crates/dnscraft-resolver/src/{lib.rs,config.rs,error.rs,iterate.rs}`, `crates/dnscraft-resolver/tests/recursion.rs`

**Estimated scope:** M

## Task 5: CNAME chains, NXDOMAIN, NODATA, limits

**Description:** Follow CNAME chains across zones; correct NXDOMAIN/NODATA answers; enforce
CNAME length (≤ 16), delegation depth, and per-question outgoing query budget.

**Acceptance criteria:**
- [ ] Cross-zone CNAME chain resolves; NXDOMAIN and NODATA carry the right rcode/SOA
- [ ] CNAME loop and over-long chain return `SERVFAIL` with code `resolver.cname_limit`
- [ ] Exceeding the outgoing budget returns `SERVFAIL` instead of hanging

**Verification:**
- [ ] `cargo test -p dnscraft-resolver --test recursion`

**Dependencies:** Task 4

**Files likely touched:** `src/iterate.rs`, `src/limits.rs`, `tests/recursion.rs`, testkit zones

**Estimated scope:** S

## Task 6: Transport robustness

**Description:** EDNS(0) 1232, TC → TCP fallback, timeouts with retry on other servers,
smoothed-RTT server selection, randomized ids/ports, response matching, IPv4/IPv6 preference.

**Acceptance criteria:**
- [ ] Truncated UDP answer is retried over TCP and succeeds
- [ ] A stopped or lame nameserver is skipped; resolution succeeds via the other one
- [ ] Mismatched id/question responses are ignored (spoofing test)

**Verification:**
- [ ] `cargo test -p dnscraft-resolver --test transport`

**Dependencies:** Task 4

**Files likely touched:** `src/transport.rs`, `src/server_selection.rs`, `tests/transport.rs`, testkit (TC and lame modes)

**Estimated scope:** M

## Task 7: QNAME minimisation

**Description:** RFC 9156 minimisation with fallback for broken servers.

**Acceptance criteria:**
- [ ] Testkit query logs show the root only sees `test.` and `test.` only sees `example.test.`
- [ ] A server answering NXDOMAIN wrongly for empty non-terminals triggers fallback to full QNAME

**Verification:**
- [ ] `cargo test -p dnscraft-resolver --test recursion -- qname`

**Dependencies:** Task 4

**Files likely touched:** `src/iterate.rs`, `tests/recursion.rs`

**Estimated scope:** S

## Checkpoint B: Recursion
- [ ] Success criterion 1 met
- [ ] Manual: example binary resolves `example.com A` from the internet
- [ ] Review with human

## Phase 3: DNSSEC

## Task 8: Testkit DNSSEC zones

**Description:** Sign testkit zones at test time with an injectable clock: `secure`,
`insecure` (no DS), `bogus` variants (bad signature, expired RRSIG, missing DNSKEY),
NSEC and NSEC3 (incl. opt-out) denial zones; expose the fake root's trust anchor.

**Acceptance criteria:**
- [ ] Each zone variant is selectable by name from tests
- [ ] Fake root DS/DNSKEY exported as a trust anchor for the resolver config
- [ ] Responder answers `DS` queries at a zone cut authoritatively from the parent (today it returns a referral, see review note on Task 3)
- [ ] Wildcard records supported (needed for wildcard denial proofs)

**Verification:**
- [ ] `cargo test -p dnscraft-testkit -- dnssec`

**Dependencies:** Task 3

**Files likely touched:** `crates/dnscraft-testkit/src/{signer.rs,dnssec_zones.rs}`

**Estimated scope:** M

## Task 9: Chain-of-trust validation

**Description:** Validate DS → DNSKEY → RRSIG from the trust anchor down; set `DnssecStatus`,
AD bit, `SERVFAIL` + EDE for bogus; honour CD bit; built-in IANA root anchors (KSK-2017, KSK-2024).

**Acceptance criteria:**
- [ ] `secure` → `Secure` + AD; `insecure` → `Insecure`, no AD
- [ ] Every bogus variant → `SERVFAIL` with the matching EDE code
- [ ] With CD bit set, the bogus answer is returned unvalidated

**Verification:**
- [ ] `cargo test -p dnscraft-resolver --test dnssec`

**Dependencies:** Tasks 4, 8

**Files likely touched:** `src/dnssec/{mod.rs,chain.rs,anchors.rs}`, `tests/dnssec.rs`

**Estimated scope:** M

## Task 10: Authenticated denial and negative trust anchors

**Description:** Validate NXDOMAIN/NODATA via NSEC and NSEC3 (incl. opt-out, wildcard proofs);
configurable negative trust anchors.

**Acceptance criteria:**
- [ ] Signed NXDOMAIN/NODATA validate as `Secure` for NSEC and NSEC3 zones
- [ ] Forged denial (missing/incorrect NSEC) → `Bogus`
- [ ] A domain listed as negative trust anchor resolves `Insecure` despite bogus signatures

**Verification:**
- [ ] `cargo test -p dnscraft-resolver --test dnssec -- denial nta`

**Dependencies:** Task 9

**Files likely touched:** `src/dnssec/{denial.rs,nta.rs}`, `tests/dnssec.rs`

**Estimated scope:** M

## Checkpoint C: DNSSEC
- [ ] Success criterion 2 met against testkit
- [ ] Success criterion 3 met manually (`example.com` Secure, `dnssec-failed.org` SERVFAIL); cross-check with `delv`
- [ ] Review with human

## Phase 4: Cache and resilience

## Task 11: Positive/negative cache

**Description:** Byte-bounded cache with LRU-like eviction, RFC 2308 negative caching,
TTL clamping, `flush(FlushScope::All | Domain)`; DNSSEC status cached with the entry.

**Acceptance criteria:**
- [ ] Second identical query causes zero testkit traffic
- [ ] TTL clamp and negative TTL (SOA minimum) honoured using the injected clock
- [ ] Memory bound respected under a fill test; flush by domain removes subdomains too

**Verification:**
- [ ] `cargo test -p dnscraft-resolver --test cache`

**Dependencies:** Tasks 5, 9

**Files likely touched:** `src/cache.rs`, `src/lib.rs`, `tests/cache.rs`

**Estimated scope:** M

## Task 12: In-flight dedup and prefetch

**Description:** Coalesce identical concurrent questions; refresh popular entries before expiry.

**Acceptance criteria:**
- [ ] 50 concurrent identical queries → one outgoing resolution chain (testkit query log)
- [ ] A frequently queried entry is refreshed before TTL expiry without a client-visible miss

**Verification:**
- [ ] `cargo test -p dnscraft-resolver --test cache -- dedup prefetch`

**Dependencies:** Task 11

**Files likely touched:** `src/inflight.rs`, `src/prefetch.rs`, `tests/cache.rs`

**Estimated scope:** S

## Task 13: Serve-stale

**Description:** RFC 8767: when authoritative servers fail, serve expired entries up to the
configured window (default 1 day) with EDE "Stale Answer" and `AnswerSource::Stale`.

**Acceptance criteria:**
- [ ] Testkit servers stopped + expired entry → stale answer within window
- [ ] Beyond the window → `SERVFAIL`
- [ ] Stale answers never replace a fresh successful resolution

**Verification:**
- [ ] `cargo test -p dnscraft-resolver --test cache -- stale`

**Dependencies:** Task 11

**Files likely touched:** `src/cache.rs`, `src/lib.rs`, `tests/cache.rs`

**Estimated scope:** S

## Checkpoint D: Cache
- [ ] Success criteria 4, 5, 6 met
- [ ] Review with human

## Phase 5: Edges and completion

## Task 14: Forward zones

**Description:** Configured zones go to target servers (RTT order, failover), `validate`
flag per zone (default false), loop protection, cached like recursive answers.

**Acceptance criteria:**
- [ ] Forward zone resolves via targets only; fake root sees no query for it
- [ ] First target stopped → second target answers
- [ ] Target forwarding back to the resolver ends in `SERVFAIL` (`resolver.forward_loop`), no hang

**Verification:**
- [ ] `cargo test -p dnscraft-resolver --test forward`

**Dependencies:** Tasks 4, 9, 11

**Files likely touched:** `src/forward.rs`, `src/config.rs`, `tests/forward.rs`

**Estimated scope:** M

## Task 15: Locally served private reverse zones and ECS stripping

**Description:** RFC 6303 zones (RFC 1918, ULA, link-local, …) answered locally unless a
forward zone covers them; ECS never sent and stripped from incoming queries.

**Acceptance criteria:**
- [ ] PTR for `10.in-addr.arpa` space → local NXDOMAIN, zero testkit traffic
- [ ] Forward zone for a private reverse zone overrides the local answer
- [ ] Outgoing queries never carry ECS (testkit inspects received EDNS options)

**Verification:**
- [ ] `cargo test -p dnscraft-resolver --test local_zones`

**Dependencies:** Task 4 (Task 14 for the override case)

**Files likely touched:** `src/local_zones.rs`, `src/transport.rs`, `tests/local_zones.rs`

**Estimated scope:** S

## Task 16: Stats, error codes, benchmark, example binary, acceptance

**Description:** `stats()` (cache hits, latencies, DNSSEC outcomes), stable `code()` on every
error, `criterion` benchmark for cache lookup, `examples/query.rs`, coverage run.

**Acceptance criteria:**
- [ ] Cache-hit p50 < 1 ms in benchmark; all error variants have unique, documented codes
- [ ] `cargo run -p dnscraft-resolver --example query -- example.com A` prints answer + DNSSEC status
- [ ] Line coverage ≥ 80 % (`cargo llvm-cov -p dnscraft-resolver`)

**Verification:**
- [ ] `cargo bench -p dnscraft-resolver`, `cargo llvm-cov -p dnscraft-resolver`
- [ ] Manual: all 8 success criteria in SPEC-resolver.md ticked

**Dependencies:** Tasks 4–15

**Files likely touched:** `src/stats.rs`, `src/error.rs`, `benches/cache.rs`, `examples/query.rs`

**Estimated scope:** M

## Checkpoint E: Complete
- [ ] All success criteria met, coverage ≥ 80 %
- [ ] Ready for review (`/review`)
