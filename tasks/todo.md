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
- [x] Checklist answered with evidence: DNSSEC (NSEC, NSEC3, AD, EDE, CD), QNAME minimisation, serve-stale, prefetch hooks, cache size control/flush, forward zones, injectable root hints/ports, ECS behaviour, maintenance status
- [x] `docs/adr/0001-recursion-engine.md` states decision, alternatives, consequences
- [x] Plan tasks 4–16 annotated with "wrap" vs. "implement" based on the decision

**Verification:**
- [x] Manual: spike resolves `example.com A` (Secure) and `dnssec-failed.org A` (SERVFAIL) from the internet
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
- [x] All tests pass, clippy clean
- [x] ADR-0001 accepted by the owner (Option D)
- [x] Revised `tasks/plan.md` and this file approved

## Phase 1b: Wire format (`dnscraft-proto`)

Common rules for W1–W5: new crate `crates/dnscraft-proto`, no I/O, no async, no `unsafe`,
no panics on any input (no indexing that can panic, no `unwrap`/`expect`), every decode error is
a typed `ProtoError` variant with a stable `code()`. Dependencies: `thiserror` only (plus `ring` in W4).
Oracle tests live in `crates/dnscraft-proto/tests/` and use `hickory-proto` as a dev-dependency.

## Task W1: Domain names and compression

**Description:** `Name` type: labels as bytes, case-insensitive equality/hash, canonical
(lowercase) form, presentation parsing/formatting (`"www.example.com."`, escapes `\.` and `\DDD`),
wire decode with compression pointers and wire encode with an optional compression table.

**Acceptance criteria:**
- [x] Limits enforced: label ≤ 63, name ≤ 255 octets on the wire, pointers only backwards, max 128 pointer jumps, no recursion
- [x] `zone_of`, `parent`, label iteration, and RFC 4034 §6.1 canonical ordering implemented
- [x] Round-trip against hickory `Name` for a corpus incl. escapes, root, max-length names

**Verification:**
- [x] `cargo test -p dnscraft-proto -- name`

**Dependencies:** Task 1

**Files likely touched:** `crates/dnscraft-proto/{Cargo.toml,src/lib.rs,src/error.rs,src/name.rs}`, `crates/dnscraft-proto/tests/name_oracle.rs`, root `Cargo.toml`

**Estimated scope:** M

## Task W2: Core RDATA types

**Description:** `RecordType`, `Class`, `Record`, and `RData` for A, AAAA, NS, CNAME, DNAME, SOA,
PTR, MX, TXT, SRV, CAA, SVCB/HTTPS (needed later for DDR), OPT placeholder, and unknown types
as opaque bytes (RFC 3597). Names inside RDATA follow compression rules per RFC 3597 §4.

**Acceptance criteria:**
- [x] Decode/encode for every listed type; RDLENGTH mismatch is an error, not a panic
- [x] Compression only used for names in NS/CNAME/SOA/PTR/MX (and decoded wherever legal)
- [x] Oracle round-trips against hickory for every type

**Verification:**
- [x] `cargo test -p dnscraft-proto -- rdata`

**Dependencies:** W1

**Files likely touched:** `src/rtype.rs`, `src/record.rs`, `src/rdata/{mod.rs,basic.rs,svcb.rs}`, `tests/rdata_oracle.rs`

**Estimated scope:** M

## Task W3: Messages and EDNS

**Description:** `Header` (all flags incl. AD/CD), `Message` with four sections, EDNS(0) OPT
(payload size, DO bit, extended rcode, options: ECS, EDE (RFC 8914), padding, cookie, unknown),
encoder with name compression and a size limit that truncates cleanly (TC bit, whole RRsets
dropped), and a decoder with section count sanity checks.

**Acceptance criteria:**
- [x] Every response the testkit sends (hickory-encoded) decodes and re-encodes to an equivalent message
- [x] Encoding with a 512/1232-byte limit sets TC and never splits an RRset
- [x] Malformed inputs (counts larger than data, trailing garbage, duplicate OPT) yield typed errors

**Verification:**
- [x] `cargo test -p dnscraft-proto -- message edns`
- [x] `cargo test -p dnscraft-testkit` still green with the oracle check enabled

**Dependencies:** W2, Task 3

**Files likely touched:** `src/header.rs`, `src/message.rs`, `src/edns.rs`, `tests/message_oracle.rs`

**Estimated scope:** M

## Task W4: DNSSEC record types and canonical form

**Description:** DNSKEY, DS, RRSIG, NSEC, NSEC3, NSEC3PARAM (type bitmaps), key tag (RFC 4034
App. B), DS digest computation (SHA-1/256/384 via `ring`), NSEC3 hash (RFC 5155), and the
canonical RRset form used as signature input (RFC 4034 §6.2/§6.3, RFC 4035 §5.3.2 incl.
wildcard label count handling). No signature verification yet (Task 9a).

**Acceptance criteria:**
- [x] Oracle round-trips against hickory for all six types
- [x] Key tags and DS digests match published values for the IANA root KSKs (20326, 38696)
- [x] NSEC3 hashes match RFC 5155 Appendix A test vectors; canonical form matches hickory's signature input for a test RRset

**Verification:**
- [x] `cargo test -p dnscraft-proto -- dnssec` and `cargo test -p dnscraft-proto --test dnssec_oracle --test dnssec_vectors`

**Dependencies:** W3

**Files likely touched:** `src/rdata/dnssec.rs`, `src/dnssec/{mod.rs,keytag.rs,digest.rs,nsec3hash.rs,canonical.rs}`, `tests/dnssec_oracle.rs`

**Estimated scope:** M

## Task W5: Fuzzing and oracle round-trips

**Description:** `fuzz/` crate (outside the workspace, nightly) with targets: name decode,
message decode, decode→encode→decode stability; `proptest` round-trip tests for names,
records, and messages; a CI job that runs each fuzz target for 60 s.

**Acceptance criteria:**
- [x] Three fuzz targets exist and run 10 min each locally without crashes or timeouts
- [x] Property tests: `decode(encode(x)) == x` for generated names/records/messages
- [x] CI runs the short fuzz job; `dnscraft-proto` line coverage ≥ 80 %

**Verification:**
- [x] `cargo +nightly fuzz run <target> -- -max_total_time=600` per target
- [x] `cargo llvm-cov -p dnscraft-proto --summary-only`

**Dependencies:** W3 (extended after W4)

**Files likely touched:** `fuzz/{Cargo.toml,fuzz_targets/*.rs}`, `crates/dnscraft-proto/tests/props.rs`, `.github/workflows/ci.yml`

**Estimated scope:** M

## Checkpoint W: Wire format
- [x] All testkit responses decode with `dnscraft-proto`; oracle round-trips green
- [x] Fuzzing clean; coverage ≥ 80 %
- [x] Review with human

## Phase 2: Recursion

## Task 4: Iterative resolution happy path

**Description:** Public API (`Resolver::new`, `resolve`, `ResolverConfig`, `Answer`, errors with
`code()`) built on `dnscraft-proto`, and iterative resolution from root hints with priming, following referrals and glue.

**Acceptance criteria:**
- [x] `A` and `AAAA` for `www.example.test.` resolve through the fake hierarchy
- [x] Priming query refreshes root NS set at startup
- [x] Missing glue is resolved (out-of-bailiwick nameserver)

**Verification:**
- [x] `cargo test -p dnscraft-resolver --test recursion`

**Dependencies:** Checkpoint W

**Files likely touched:** `crates/dnscraft-resolver/src/{lib.rs,config.rs,error.rs,iterate.rs}`, `crates/dnscraft-resolver/tests/recursion.rs`

**Estimated scope:** M

## Task 5: CNAME chains, NXDOMAIN, NODATA, limits

**Description:** Follow CNAME chains across zones; correct NXDOMAIN/NODATA answers; enforce
CNAME length (≤ 16), delegation depth, and per-question outgoing query budget.

**Acceptance criteria:**
- [x] Cross-zone CNAME chain resolves; NXDOMAIN and NODATA carry the right rcode/SOA
- [x] CNAME loop and over-long chain return `SERVFAIL` with code `resolver.cname_limit`
- [x] Exceeding the outgoing budget returns `SERVFAIL` instead of hanging

**Verification:**
- [x] `cargo test -p dnscraft-resolver --test recursion`

**Dependencies:** Task 4

**Files likely touched:** `src/iterate.rs`, `src/limits.rs`, `tests/recursion.rs`, testkit zones

**Estimated scope:** S

## Task 6: Transport robustness

**Description:** EDNS(0) 1232, TC → TCP fallback, timeouts with retry on other servers,
smoothed-RTT server selection, randomized ids/ports, response matching, IPv4/IPv6 preference.

**Acceptance criteria:**
- [x] Truncated UDP answer is retried over TCP and succeeds
- [x] A stopped or lame nameserver is skipped; resolution succeeds via the other one
- [x] Mismatched id/question responses are ignored (spoofing test)

**Verification:**
- [x] `cargo test -p dnscraft-resolver --test transport`

**Dependencies:** Task 4

**Files likely touched:** `src/transport.rs`, `src/server_selection.rs`, `tests/transport.rs`, testkit (TC and lame modes)

**Estimated scope:** M

## Task 7: QNAME minimisation

**Description:** RFC 9156 minimisation with fallback for broken servers.

**Acceptance criteria:**
- [x] Testkit query logs show the root only sees `test.` and `test.` only sees `example.test.`
- [x] A server answering NXDOMAIN wrongly for empty non-terminals triggers fallback to full QNAME

**Verification:**
- [x] `cargo test -p dnscraft-resolver --test recursion -- qname`

**Dependencies:** Task 4

**Files likely touched:** `src/iterate.rs`, `tests/recursion.rs`

**Estimated scope:** S

## Checkpoint B: Recursion
- [x] Success criterion 1 met
- [x] Manual: example binary resolves `example.com A` from the internet
- [x] Review with human (owner approved 2026-10-24)

## Phase 3: DNSSEC

## Task 8: Testkit DNSSEC zones

**Description:** Sign testkit zones at test time with hickory's signer (independent implementation) and explicit inception/expiration: `secure`,
`insecure` (no DS), `bogus` variants (bad signature, expired RRSIG, missing DNSKEY),
NSEC and NSEC3 (incl. opt-out) denial zones; expose the fake root's trust anchor.

**Acceptance criteria:**
- [x] Each zone variant is selectable by name from tests
- [x] Fake root DS/DNSKEY exported as a trust anchor for the resolver config
- [x] Responder answers `DS` queries at a zone cut authoritatively from the parent (today it returns a referral, see review note on Task 3)
- [x] Wildcard records supported (needed for wildcard denial proofs)

**Verification:**
- [x] `cargo test -p dnscraft-testkit -- dnssec`

**Dependencies:** Task 3

**Files likely touched:** `crates/dnscraft-testkit/src/{signer.rs,dnssec_zones.rs}`

**Estimated scope:** M

## Task 9a: Chain of trust and signature verification

**Description:** Own validator in `dnscraft-resolver` over `dnscraft-proto` (W4) and `ring`:
trust anchors (built-in IANA root KSK-2017/KSK-2024, overridable for the testkit), DS → DNSKEY
matching, RRSIG verification (algorithms 8, 10, 13, 14, 15; 5/7 as insecure-by-policy per RFC 8624),
validity window against the injected clock, label-count/wildcard expansion check.

**Acceptance criteria:**
- [x] `secure` zone validates via the testkit trust anchor; wrong signature, expired RRSIG, missing DNSKEY each fail with a distinct reason
- [x] Unsupported algorithm → treated as insecure, not bogus (RFC 4035 §5.2)
- [x] Root anchors verify the real root DNSKEY set (captured fixture)

**Verification:**
- [x] `cargo test -p dnscraft-resolver --test dnssec -- chain`

**Dependencies:** Tasks W4, 4, 8

**Files likely touched:** `src/dnssec/{mod.rs,anchors.rs,chain.rs,verify.rs}`, `tests/dnssec.rs`

**Estimated scope:** M

## Task 9b: Validation status, AD, SERVFAIL + EDE, CD

**Description:** Map validation results to `DnssecStatus` (`Secure`, `Insecure`, `Bogus`,
`Indeterminate`), set the AD bit, turn `Bogus` into `SERVFAIL` with the matching EDE code,
honour the CD bit per query, find insecure delegations (no DS) correctly.

**Acceptance criteria:**
- [x] `secure` → `Secure` + AD; `insecure` → `Insecure`, no AD
- [x] Every bogus variant → `SERVFAIL` with the matching EDE code
- [x] With CD bit set, the bogus answer is returned unvalidated

**Verification:**
- [x] `cargo test -p dnscraft-resolver --test dnssec -- status`

**Dependencies:** Task 9a

**Files likely touched:** `src/dnssec/status.rs`, `src/lib.rs`, `tests/dnssec.rs`

**Estimated scope:** S

## Task 10: Authenticated denial and negative trust anchors

**Description:** Own implementation: validate NXDOMAIN/NODATA via NSEC and NSEC3 (incl. opt-out, wildcard proofs, closest-encloser);
configurable negative trust anchors.

**Acceptance criteria:**
- [x] Signed NXDOMAIN/NODATA validate as `Secure` for NSEC and NSEC3 zones
- [x] Forged denial (missing/incorrect NSEC) → `Bogus`
- [x] A domain listed as negative trust anchor resolves `Insecure` despite bogus signatures

**Verification:**
- [x] `cargo test -p dnscraft-resolver --test dnssec -- denial nta`

**Dependencies:** Task 9b

**Files likely touched:** `src/dnssec/{denial.rs,nta.rs}`, `tests/dnssec.rs`

**Estimated scope:** M

## Checkpoint C: DNSSEC
- [x] Success criterion 2 met against testkit
- [x] Success criterion 3 met manually (`example.com` Secure, `dnssec-failed.org` SERVFAIL); cross-check with `delv`
- [x] Review with human (owner approved 2026-10-24)

## Phase 4: Cache and resilience

## Task 11: Positive/negative cache

**Description:** Byte-bounded cache with LRU-like eviction, RFC 2308 negative caching,
TTL clamping, `flush(FlushScope::All | Domain)`; DNSSEC status cached with the entry.

**Acceptance criteria:**
- [x] Second identical query causes zero testkit traffic
- [x] TTL clamp and negative TTL (SOA minimum) honoured using the injected clock
- [x] Memory bound respected under a fill test; flush by domain removes subdomains too

**Verification:**
- [x] `cargo test -p dnscraft-resolver --test cache`

**Dependencies:** Tasks 5, 9b

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

**Dependencies:** Tasks 4, 9b, 11

**Files likely touched:** `src/forward.rs`, `src/config.rs`, `tests/forward.rs`

**Estimated scope:** M

## Task 15: Locally served private reverse zones and ECS stripping

**Description:** RFC 6303 zones (RFC 1918, ULA, link-local, …) answered locally unless a
forward zone covers them; ECS never sent and stripped from incoming queries.

**Acceptance criteria:**
- [x] PTR for `10.in-addr.arpa` space → local NXDOMAIN, zero testkit traffic
- [x] Forward zone for a private reverse zone overrides the local answer
- [x] Outgoing queries never carry ECS (testkit inspects received EDNS options)

**Verification:**
- [x] `cargo test -p dnscraft-resolver --test local_zones`

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
