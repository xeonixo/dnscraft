# Tasks: `policy` module

> Plan: [plan-policy.md](plan-policy.md) · Spec: [SPEC-policy.md](../SPEC-policy.md) · Resume log: [progress.md](progress.md)
> Definition of done per task: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
> `cargo test --workspace --locked` green; lead review; committed. Tests use `dnscraft-testkit`, `FilterEngine::from_snapshot`
> and a mock `ClientDirectory`; never the internet. Documentation ranges and `example.com` only.

## Phase 1: Skeleton

## Task P1: Crate skeleton, config model, validation, errors

**Description:** Create `crates/dnscraft-policy` (workspace member, workspace lints). Dependencies:
`dnscraft-proto`, `dnscraft-resolver`, `dnscraft-filtering`, tokio, thiserror, tracing, `ipnet`.
Contents:
- Ids: `ViewId`, `ProfileId`, `ListenerId`, and `ClientId` (DoH/DoT, `[a-z0-9-]{1,63}`).
- `DnsProtocol`, `RequestContext`, `ClientFlags`.
- `PolicyConfig`:
  - top level: `default_rebind`, `ptr_prefixes`, `local_nxdomain_suffixes` (default `local`,
    `lan`, `internal`), `rebind_check_forward_zones`;
  - views: subnets, `client_ids`, records, profile;
  - profiles: `filter_set`, `suppress_aaaa`, `firefox_canary`, `icloud_private_relay`, `rebind`,
    `rebind_exceptions`, `forward_zones`, plus the `safesearch` / `schedules` surface.

`PolicySnapshot::build(config, known_sets: &[SetId], known_zones: &[ForwardZoneId])` rejects:
- not exactly one default view;
- a Client ID on two views;
- an unknown set → `policy.config.unknown_filter_set`;
- an unknown zone → `policy.config.unknown_forward_zone` (also for `rebind_check_forward_zones`);
- a CNAME next to other types → `policy.record.cname_conflict`;
- record types outside A/AAAA/CNAME/TXT/SRV/MX/PTR;
- wildcard owner names.

`PolicyError` with every code from the spec.

**Acceptance criteria:**
- [x] Every error variant has a unique `code()` (enumerating test); public items documented
- [x] Validation table tests, one per rejection rule, plus the spec's TOML excerpt expressed as Rust values accepted
- [x] `ClientId` rejects upper case, `_`, empty, 64 chars

**Verification:** `cargo test -p dnscraft-policy config`

**Dependencies:** R2 committed; plan + `ipnet` approved

**Files:** `Cargo.toml`, `crates/dnscraft-policy/{Cargo.toml,src/lib.rs,src/ids.rs,src/config.rs,src/snapshot.rs,src/error.rs}`

**Scope:** M

## Task P2: View selection

**Description:** `PolicySnapshot::select(&RequestContext) -> Selection` in this order:
1. Client ID exact match.
2. Longest prefix per family, using per-length hash tables built in P1's snapshot. IPv4-mapped
   IPv6 (`::ffff:a.b.c.d`) is matched as IPv4.
3. The default view.

`SelectionCause` records which rule matched (including the prefix). A Client ID that is not on
any view falls through to subnet matching.

**Acceptance criteria:**
- [x] Table: Client ID beats a /32; /28 beats /24; IPv6 /64 vs /48; unlisted Client ID → subnet; nothing → default
- [x] IPv4-mapped IPv6 source selects the IPv4 view
- [x] Selection allocates nothing (no `String`/`Vec` in the path; reviewed) and takes < 1 µs p50 with 100 views (simple timing test or criterion)

**Verification:** `cargo test -p dnscraft-policy select`

**Dependencies:** P1 · **Files:** `src/select.rs`, `src/snapshot.rs`, `tests/select.rs` · **Scope:** S

## Task P3: Engine skeleton with resolver passthrough

**Description:**
- `PolicyEngine::new(config, filter: Arc<FilterEngine>, resolver: Arc<Resolver>, clients: Arc<dyn ClientDirectory>, clock)`.
  Define the `ClientDirectory` trait per plan cross-module decision 1, plus `NoClients` (always
  `None`).
- `handle(ctx) -> Result<PolicyAnswer, PolicyError>` with the step framework (`Flow`, `Draft`,
  `DecisionStep`), selection, step 7 and emit:
  - `Resolver::resolve` with `RequestFlags { checking_disabled, dnssec_ok, client, forward_zones: profile allow-list }`;
  - AD passthrough only for unmodified `Secure`;
  - the resolver's EDE kept;
  - `DecisionRecord` with `forward_zone`, `dnssec`, `answer_source`, `timings`, `rcode`.
- ANY → minimal RFC 8482 answer (synthesised HINFO "RFC8482", no recursion).
- An ECS option from the client is never forwarded.
- Resolver error → SERVFAIL with `policy.resolve` in the record.
- `test_query` → `loggable = false`.

**Acceptance criteria:**
- [ ] Testkit hierarchy: A query resolves through the policy; decision record lists selection + resolve step; message id left to the listener
- [ ] Profile `forward_zones = Some([..])` passed through: name under a disallowed zone recurses (testkit forward target sees no query)
- [ ] ANY never reaches the resolver; `test_query` → `loggable == false`; Secure answer keeps AD, Insecure has none

**Verification:** `cargo test -p dnscraft-policy engine`

**Dependencies:** P2 · **Files:** `src/engine.rs`, `src/pipeline.rs`, `src/decision.rs`, `src/directory.rs`, `src/synth.rs`, `tests/engine.rs` · **Scope:** M

## Task P4: View local records

**Description:** Step 1:
- Exact owner name in the selected view: answer the RR set of the queried type (TTL from the
  record, default 60 s). PTR is supported.
- A name with records but none of the queried type → NODATA.
- A CNAME at the name with qtype ≠ CNAME → return the CNAME, and follow it only while the target
  is also a local name in the same view (loop guard of 8 hops). An external target stops after
  the CNAME.
- AA set, AD cleared.
- Synthetic answers are flagged so rebind (P9) skips them.

**Acceptance criteria:**
- [ ] A / AAAA / TXT / SRV / MX / PTR answered without resolver traffic (testkit server sees 0 queries)
- [ ] CNAME → local A followed; CNAME → external name returned alone; CNAME loop stops at 8
- [ ] Same name in two views answers per selected view (split-horizon)

**Verification:** `cargo test -p dnscraft-policy local_records`

**Dependencies:** P3 · **Files:** `src/steps/local_records.rs`, `src/synth.rs`, `tests/local_records.rs` · **Scope:** M

## Checkpoint A: Skeleton
- [ ] DoD green; selection + local records + passthrough end to end
- [ ] Lead review (step framework shape, AD handling)
- [ ] progress.md updated

## Phase 2: Pipeline

## Task P5: ClientDirectory names/PTR + special-use NXDOMAIN

**Description:** Step 2 (skipped if step 1 answered):
- Forward: `addresses(qname)`:
  - `Some(addrs)` → A/AAAA of the queried type, else NODATA;
  - other qtypes on a known name → NODATA;
  - `None` → continue.
- PTR: when the qname is in the reverse zone of RFC 1918, ULA `fc00::/7`, loopback or
  `ptr_prefixes`, answer `reverse(ip)`; `None` → continue.
- Special-use: name under a `local_nxdomain_suffixes` entry, unknown to the directory, and
  `resolver.forward_zone_for(name, profile allow-list)` is `None` → NXDOMAIN (synthetic SOA, no
  EDE).
- `home.arpa` is not handled here (the resolver's local zone answers).

Also:
- Add the two read-only resolver accessors `forward_zone_ids()` and `forward_zone_for(..)`
  (plan § Architecture), with tests in the resolver crate.
- Add a one-line note to SPEC-policy.md and SPEC-clients.md about the trait signature
  (cross-module decision 1).

**Acceptance criteria:**
- [ ] Known name with A only: A answered, AAAA → NODATA, unknown name under the same local domain reaches the resolver
- [ ] PTR for 192.0.2.x listed in `ptr_prefixes` and for `10.x` answered from the mock; public-range PTR goes to the resolver
- [ ] `printer.lan` unknown → NXDOMAIN without resolver traffic; with a forward zone `lan` allowed → forwarded; with that zone not in the profile allow-list → NXDOMAIN

**Verification:** `cargo test -p dnscraft-policy directory && cargo test -p dnscraft-resolver forward`

**Dependencies:** P4 · **Files:** `src/steps/directory.rs`, `src/reverse.rs`, `crates/dnscraft-resolver/src/{lib.rs,forward.rs}`, `tests/directory.rs`, `SPEC-policy.md`, `SPEC-clients.md` · **Scope:** M

## Task P6: Bypass canaries

**Description:** Step 3, per profile:
- `firefox_canary` → `use-application-dns.net` (exact name) → NXDOMAIN.
- `icloud_private_relay` → `mask.icloud.com` / `mask-h2.icloud.com` → the documented blocking
  answer.
- Constants live in one table with the Mozilla/Apple doc URLs in comments. Mark them
  `unverified` if the implementer cannot confirm from the official page (spec decision 9).
- Synthetic: AD clear, no EDE (not a list block). The decision record says `Bypass`.

**Acceptance criteria:**
- [ ] Canary answered without resolver/filter involvement when enabled; resolved normally when disabled
- [ ] Doc URLs present in the constant table; commit message states verified/unverified

**Verification:** `cargo test -p dnscraft-policy canary`

**Dependencies:** P3 · **Files:** `src/steps/canary.rs`, `tests/canary.rs` · **Scope:** S

## Task P7: Filter the original qname, block/rewrite synthesis

**Description:** Steps 4 / 4a–c: `filter.match_name(set, name, qtype, now)`.
- `Blocked` → synthesis per the set's `BlockMode`:
  - REFUSED / NXDOMAIN → EDE 15 with the reason code in EXTRA-TEXT;
  - NullIp (`0.0.0.0` / `::`, other qtypes NODATA) → EDE 4;
  - CustomIp (a missing family → NODATA) → EDE 4.
  - TTL is the set's blocked-response TTL.
- `Rewrite` → records or rcode from the rewrite. A CNAME rewrite resolves the target through
  step 7 and returns CNAME + target answer. The target is filtered once more; a block there →
  block synthesis.
- `Allowed` / `Pass` → continue.
- `FilterHit` goes into the decision record.
- An unknown set at runtime (race during reload) → `policy.internal` + SERVFAIL, logged once.

**Acceptance criteria:**
- [ ] Each `BlockMode` produces the right rcode / records / EDE / AD clear; blocked names cause zero resolver queries
- [ ] Rewrite to A record, to NXDOMAIN, to CNAME (target resolved via testkit; blocked target → block)
- [ ] Temporary allow and set pause from filtering are honoured (verdict passes through)

**Verification:** `cargo test -p dnscraft-policy filter`

**Dependencies:** P4 · **Files:** `src/steps/filter.rs`, `src/synth.rs`, `tests/filter.rs` · **Scope:** M

## Task P8: CNAME uncloaking + answer-IP rules

**Description:**
- Step 8: collect the CNAME chain names from the resolver answer (owner names in order) and run
  `match_chain`. `Blocked` → replace the answer with block synthesis.
- Step 9: run `match_answer_ip` for each A/AAAA in the final answer. Any `Blocked` → block
  synthesis (block wins).
- Both steps are skipped for synthetic answers.
- Any modification clears AD.

**Acceptance criteria:**
- [ ] Testkit CNAME chain `a.example.com → tracker.example.net → …` with `tracker.example.net` blocked → blocked answer
- [ ] Answer IP on an IP rule → blocked; allowed chain name overrides per filtering priority
- [ ] Unblocked chain keeps AD when the resolver said Secure

**Verification:** `cargo test -p dnscraft-policy answer_side`

**Dependencies:** P7 · **Files:** `src/steps/answer_side.rs`, `tests/answer_side.rs` · **Scope:** S

## Task P9: Rebind protection + AAAA suppression

**Description:** Step 10, for resolver answers only (synthetic answers skip it).
- Private means RFC 1918, loopback, link-local (v4 + v6), ULA `fc00::/7`, `0.0.0.0/8`, CGNAT
  `100.64.0.0/10`, IPv4-mapped forms of these.
- Skipped when:
  - the profile has rebind off;
  - the qname or a suffix matches `rebind_exceptions` (`*.suffix` and exact);
  - `answer.forward_zone` is `Some(z)` and `z` is not in `rebind_check_forward_zones`.
- Private A/AAAA are stripped. All stripped → NOERROR/NODATA, no EDE; some left → the rest.
  AD cleared on any change.
- The decision record notes the skip reason and the stripped count.

Step 11: profile `suppress_aaaa` and qtype AAAA → NODATA; other qtypes unchanged.

**Acceptance criteria:**
- [ ] Public name resolving to 10.0.0.1 stripped → NODATA; mixed answer keeps the public address; exception suffix passes
- [ ] Forward-zone answer with a private address passes by default and is stripped when the zone is listed in `rebind_check_forward_zones`
- [ ] View record / filter rewrite to a private IP passes; AAAA suppression only on qtype AAAA (HTTPS/SVCB untouched)

**Verification:** `cargo test -p dnscraft-policy rebind`

**Dependencies:** P8 · **Files:** `src/steps/rebind.rs`, `src/steps/aaaa.rs`, `src/private.rs`, `tests/rebind.rs` · **Scope:** M

## Checkpoint B: Pipeline
- [ ] Steps 1–12 in spec order (5/6 stubbed); every row of the AD/EDE matrix has a test
- [ ] Lead review; progress.md updated

## Phase 3: Operations

## Task P10: Pause, hot reload, counters

**Description:**
- `pause(scope: PauseScope::{Global, Profile(id)}, until: PauseUntil::{For(5 min | 1 h), UntilResumed})` and
  `resume(scope)`. While paused, steps 4 / 6 / 8 / 9 return `Pass`; local records, directory,
  canaries, rebind and AAAA still run. Expiry uses the clock.
- `apply_config`: build and validate the new snapshot (known sets from `FilterEngine`, zones from
  the resolver accessor), then swap the `Arc`. Pause state and counters survive by id; pauses
  for removed profiles are dropped.
- Per-view and per-profile counters (queries, blocked, local hits) with a `stats()` getter.

**Acceptance criteria:**
- [ ] `ManualClock`: global 5 min pause passes a blocked name, blocks again after expiry; per-profile pause affects only that profile; until-resumed stays until `resume`
- [ ] `apply_config` with an invalid config keeps the old snapshot and returns the error code; a valid one takes effect on the next query
- [ ] Counters increment per outcome and survive reload

**Verification:** `cargo test -p dnscraft-policy pause`

**Dependencies:** P9 · **Files:** `src/pause.rs`, `src/engine.rs`, `src/stats.rs`, `tests/pause.rs`, `tests/reload.rs` · **Scope:** M

## Task P11: SafeSearch + schedules config surface

**Description:** Accept and validate the `safesearch` (enabled + providers) and `schedules` (time
windows → set id) profile fields. Steps 5 and 6 exist as no-ops that add a
`DecisionStep::NotApplied`. `PolicyStatus` exposes `safesearch_applied = false` and
`schedules_applied = false` so the UI can say "not applied yet" (spec: low priority).

**Acceptance criteria:**
- [ ] Config with SafeSearch/schedules validates (unknown set in a schedule rejected)
- [ ] Decision record shows the not-applied step when enabled; status flags false

**Verification:** `cargo test -p dnscraft-policy safesearch`

**Dependencies:** P10 · **Files:** `src/config.rs`, `src/steps/safesearch.rs`, `src/status.rs`, `tests/safesearch.rs` · **Scope:** S

## Task P12: Golden integration tests, bench, coverage, README

**Description:**
- Golden tests over the full pipeline (testkit hierarchy + resolver + `FilterEngine::from_snapshot`
  + mock directory) for spec success criteria 1–5:
  - view/directory answers never reach the resolver;
  - blocked names never reach it;
  - chain block;
  - rebind matrix;
  - unknown local-domain names reach the resolver while special-use names never do.
- Criterion bench: cache hit + filter miss end to end, p50 < 1 ms.
- Coverage ≥ 80 % lines (`cargo llvm-cov` locally, or report the gap).
- README: pipeline table, config fields, the ClientDirectory contract for control-api, the AD/EDE
  matrix.
- Success criteria table in progress.md.

**Acceptance criteria:**
- [ ] Golden tests for criteria 1–5 pass
- [ ] Bench p50 < 1 ms recorded in progress.md
- [ ] Coverage ≥ 80 % (or gap listed with a reason); README complete

**Verification:** `cargo test -p dnscraft-policy && cargo bench -p dnscraft-policy --no-run` + DoD

**Dependencies:** P11 · **Files:** `tests/golden.rs`, `benches/pipeline.rs`, `crates/dnscraft-policy/README.md` · **Scope:** M

## Checkpoint C: Complete
- [ ] Spec success criteria 1–6
- [ ] Independent review (DNSSEC/AD honesty, rebind, synthesis correctness)
- [ ] **Owner approval**

## Later (owner go required)

- **P13 SafeSearch evaluation:** provider host table verified against Google/Bing/YouTube/DuckDuckGo docs (URLs cited); steps 5 + 6 live.
- **P14 Schedule evaluation:** time windows on the policy clock switch the active set.
