# Progress log

Resume point for interrupted sessions. Newest entry first.
Task details: [todo.md](todo.md) · Plan: [plan.md](plan.md)

**Workflow:** each task is implemented by a Haiku/Sonnet subagent, reviewed by the lead
(diff, `fmt`, `clippy`, tests), ticked off in `todo.md`, logged here, and committed.

## Current state

- Phase: 4 (cache) — Task 13 in progress (serve-stale); Checkpoint D after that.
- Phase 1 done. ADR-0001 accepted as **Option D** (in-house wire format + DNSSEC logic, `ring` for crypto).
- Checkpoint A passed (plan + new deps approved).
- Checkpoint W complete (coverage 96 %, fuzzing clean)
- Real-internet resolution works (example.com 4 queries / ~90 ms incl. priming; www.microsoft.com 13 with minimisation).
- Checkpoint B passed (owner approved 2026-10-24).
- Checkpoint C passed (owner approved 2026-10-24): testkit DNSSEC green; live example.com Secure + dnssec-failed.org SERVFAIL match delv/kdig.
- Phase 3 DNSSEC tasks 8–10 done. Dev Do53 server deferred by owner.
- Blockers: none

## Log

- 2026-10-24 — Task 13 started.

- 2026-10-24 — Task 12 done (Grok + lead review): in-flight dedup (key = name/type/class + CD; DO stripped per waiter); prefetch for popular (≥3 hits) near-expiry entries (window max(10% TTL, 2s)); config `prefetch` default true; 2 integration + unit tests. Workspace DoD green.

- 2026-10-24 — Checkpoint B checkboxes synced in todo.md; Checkpoint C passed (49 dnssec tests; live Secure/SERVFAIL cross-checked with delv/kdig).

- 2026-10-24 — Task 12 started.

- 2026-10-24 — Task 11 done (Grok + lead review fix): byte-budget LRU message cache, RFC 2308 negative TTL (incl. CNAME→NODATA), TTL clamp, flush All/Domain, CD/Bogus not stored. 13 integration + 9 unit tests. Follow-ups: O(n) LRU scan, NXDOMAIN still per-qtype.

- 2026-10-24 — Task 11 started (Grok agent; Sonnet unavailable).

- 2026-10-24 — Task 10 done (Sonnet + lead review fix): NSEC/NSEC3 denial (NXDOMAIN, NODATA, wildcards, opt-out, closest encloser), NTAs via config. Review found NSEC wildcard answers omitted closest-encloser consistency → fixed + unit/forge regression. 17 denial/nta integration tests; workspace green.

- 2026-10-24 — Task 9b done (Sonnet, 2 review rounds): trust state per zone cut, AD only for Secure, Bogus → SERVFAIL + EDE (text = code), CD → unvalidated/Indeterminate, DO=false strips DNSSEC records, signed no-DS proof required for Insecure. Review round 1 found false Bogus on hidden zone cuts (bbc.co.uk, www.nic.uk, www.cloudflare.com) → DS walk (signer below zone, label probe max 8, intermediate zones). Live results match delv. 253 tests green. TODO(Task 10): negative/wildcard stay Indeterminate; NSEC3 closest-encloser check.

- 2026-10-24 — Follow-up fix (Haiku, reviewed): no full-QNAME retry at a server that did not answer a minimised query; move to next candidate (one timeout per dead server). Regression test with a silent server. 232 tests green.

- 2026-10-24 — Task 7 done (Sonnet, reviewed): RFC 9156 minimisation with A qtype, relaxed fallback on NXDOMAIN/errors/alias nodes, MAX_MINIMISE_COUNT 10 / ONE_LAB 4, config switch. Live: example.com 4 queries, microsoft 13 (+2), _dmarc.google.com TXT 4. Follow-up: plain timeout currently retries full name at the same dead server (double timeout).

- 2026-10-24 — Bug fix (Sonnet, reviewed): glue was discarded unless inside the delegated child → gtld-servers.net glue dropped → circular glueless chase via nstld.com. Fixed with lazy glueless resolution, per-resolve NS host map, cycle skip, cap 4 glueless per cut. Review found the fix accepted ANY glue (poisoning risk) → restricted to responder bailiwick (RFC 2181 §5.4.1) by Haiku agent with unit tests. 225 tests green.

- 2026-10-24 — Task 15 done + wired (Haiku, reviewed): RFC 6303 local zones answered before recursion, forward zones exempt; `examples/query.rs` added (pulled forward from Task 16). First real-internet run: all lookups fail with query budget exhaustion → bug ticket.

- 2026-10-24 — Follow-up of Task 6 (Haiku, reviewed): Resolver owns shared ServerStats; iterate.rs orders candidates by SRTT and uses query_servers (TC→TCP); transport/server_selection exposed as doc(hidden) pub, test #[path] hack removed. Priming still uses plain exchange (acceptable).

- 2026-10-24 — W5 fuzz runs (libFuzzer, 600 s each, aarch64): name_decode 139.2 M execs, message_decode 105.3 M, message_roundtrip 7.1 M — 0 crashes, 0 timeouts. Task 15 code done (Haiku; local_zones.rs, awaiting wiring into lib.rs).

- 2026-10-24 — Tasks 5, 6, 9a done in parallel (Sonnet, reviewed; 203 workspace tests, stable 3x). 5: CNAME/DNAME chains (bailiwick rule, RFC 6604), shared query budget. 6: TC→TCP, strict response matching, SRTT server selection, IPv6 cool-down — not yet wired into iterate.rs (follow-up). 9a: own validator over ring (alg 8/10/13/14/15, RSA ≥1024 legacy), DS matching with SHA-1 suppression, RFC 1982 validity, EDE mapping, wildcard hook; root fixture verifies.

- 2026-10-24 — Task 4 done (Sonnet, reviewed): Resolver API, iterative resolution with priming, glueless NS lookups, injectable clock, test hook for per-name nameserver addresses; root hints verified against IANA named.root. 9 tests.
- 2026-10-24 — Task 8 done (Sonnet, reviewed): signed testkit hierarchy via hickory (independent signer): secure/NSEC3/opt-out/insecure/bogus-sig/bogus-expired/bogus-nokey, wildcards, DS at cut from parent, DO-bit responses. Embedded RSA keys are test-only fixtures (not secrets). `rustls-pki-types` added as direct testkit dep (already transitive via hickory). 15 tests. Workspace: 164 tests, stable 3x.

- 2026-10-24 — Task W4 done (Sonnet agent, reviewed): DNSKEY/DS/RRSIG/NSEC/NSEC3/NSEC3PARAM, type bitmaps, key tag, DS digest, NSEC3 hash (RFC 5155 vectors), canonical signing input — verifies the live root DNSKEY RRSIG with ring. Review found RRSIG signer must be lowercased per RFC 6840 §5.1 (checked against RFC text) → fixed by Haiku agent. Note: hickory sorts RRsets by raw (not lowercased) RDATA; we follow RFC 4034 §6.3.
- 2026-10-24 — Task W5 code (Sonnet agent): fuzz/ crate with 3 targets + seeds, proptest suite (5 properties, also 10k cases), CI fuzz job. libFuzzer needed gcc-c++ → installed by lead.

- 2026-10-24 — Task W3 done (Sonnet agent, reviewed): Header/Rcode, EDNS (ECS, EDE, padding, cookie), Message decode with count sanity check, OPT interception, trailing-data check; encode_with_limit drops whole RRsets (TC only for answer/authority). Testkit now decodes every response with dnscraft-proto (oracle). 71 unit + 7 oracle + 4 testkit-oracle tests.

- 2026-10-24 — Task W2 done (Sonnet agent, reviewed): RecordType/Class, Record, RData for 12 types + Unknown; RDATA parsed against an RDLENGTH-bounded slice; encode returns Result and rolls back on error; 38 new unit + 6 oracle tests. Follow-up: `Record` does not enforce rtype == rdata variant.

- 2026-10-24 — Task W1 done (Sonnet agent, reviewed): `Name` with iterative hardened decoder (backward-only pointers, 128 jumps, 255-octet limit), compression map, RFC 4034 ordering; 17 unit + 4 hickory-oracle tests. Follow-up for later perf work: compression map allocates a lowercase key per suffix.

- 2026-10-24 — Owner chose Option D at Checkpoint A. ADR amended, SPEC/map updated, plan revised: new phase 1b (W1–W5), Task 9 split into 9a/9b.

- 2026-10-24 — Task 2 done (Sonnet agent, reviewed; key claims re-verified on crates.io/GitHub): `hickory-recursor` abandoned, successor experimental and missing serve-stale/forward zones/EDE/NTA/dedup/ports; ADR-0001 proposes Option C. Plan revised accordingly.

- 2026-10-24 — Task 3 done (Sonnet agent, reviewed): hand-written authoritative responder on tokio + hickory-proto 0.26.3; 5 integration tests, stable over 3 runs. Review findings carried into Task 8: DS at zone cut must be answered by the parent; wildcard support missing.

- 2026-10-24 — Task 1 done (Haiku agent, reviewed): workspace, toolchain pin, lints, CI workflow. fmt/clippy/test green locally.

- 2026-10-24 — Specs approved and pushed. Plan approved. Toolchain installed (Rust 1.99.1, dig, kdig).
