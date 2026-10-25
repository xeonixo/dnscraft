# Tasks: `filtering` module

> Plan: [plan.md](plan.md) · Spec: [SPEC-filtering.md](../SPEC-filtering.md) · Resume log: [progress.md](progress.md)
> Definition of done per task: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
> `cargo test --workspace --locked` green; lead review; committed.

## Phase 1: Rules

## Task F1: Crate skeleton, core types, error codes

**Description:** Create `crates/dnscraft-filtering` (workspace member, lints inherited), approved
dependencies, and the core types: canonical domain name for matching (lower-case ASCII, no
trailing dot, validated length/labels), `SetId`, `ListId`, `RuleSource`, `Verdict`
(`Pass`/`Allowed`/`Blocked`/`Rewrite`), `Reason`, `BlockMode`, `Clock` trait with system and
manual clocks, and the error types with stable `code()`.

**Acceptance criteria:**
- [x] Crate builds in the workspace; public types documented (no `missing_docs` warnings)
- [x] Domain name canonicalisation rejects empty labels, labels > 63, names > 253, invalid characters
- [x] Every error variant has a unique documented `code()` (test enumerates them)

**Verification:** `cargo test -p dnscraft-filtering`

**Dependencies:** plan approved (dependencies)

**Files:** `Cargo.toml`, `crates/dnscraft-filtering/{Cargo.toml,src/lib.rs,src/name.rs,src/types.rs,src/error.rs,src/clock.rs}`

**Scope:** S

## Task F2: Core rule parser

**Description:** `parse_rule(&str) -> Result<Rule, RuleError>` and `parse_list(&str) -> ParsedList`
for: `||domain^`, `@@||domain^`, `|domain^`, `domain|`, plain domains, hosts lines (any IP →
block, multiple names per line), comments (`!`, `#`), blank lines. Browser-only rules
(`##`, `#@#`, `$script`, paths, `$domain=`, …) are skipped with a reason. Per-line cap 4 KiB.
`RuleError` has a stable code, parameters, and a byte span.

**Acceptance criteria:**
- [ ] Table tests for each form, including edge cases (trailing dots, uppercase, `^` variants, `*` only, IPv6 hosts lines, inline comments)
- [ ] `ParsedList` reports counts per skip reason; garbage lines never abort a list
- [ ] No panics on arbitrary input (proptest smoke)

**Verification:** `cargo test -p dnscraft-filtering parser`

**Dependencies:** F1 · **Files:** `src/rule.rs`, `src/parser.rs`, `tests/parser.rs` · **Scope:** M

## Task F3: Modifiers and IDNA

**Description:** `$important`, `$badfilter`, `$dnstype=` (list, negation), `$denyallow=`,
`$dnsrewrite=` (rcode forms; record forms parsed but flagged "custom rules only"),
`$client`/`$ctag` ignored with warning, unknown modifiers → error for custom rules / skip for
lists. Non-ASCII domains → punycode via `idna`.

**Acceptance criteria:**
- [ ] Table tests per modifier incl. invalid values with precise error codes/spans
- [ ] `$dnsrewrite` record rewrites from a list source are marked ignored (with warning count); from custom rules accepted
- [ ] IDNA conversion tested (umlaut domain, invalid IDNA skipped with reason)

**Verification:** `cargo test -p dnscraft-filtering modifiers`

**Dependencies:** F2 · **Files:** `src/modifiers.rs`, `src/parser.rs`, `tests/parser.rs` · **Scope:** M

## Task F4: Wildcard and regex rules

**Description:** Glob patterns as AdGuard defines them for DNS (`*` within labels,
`||ad*.example^`) and `/regex/` rules via `regex` with a compiled size limit; extract a
literal prefilter per pattern.

**Acceptance criteria:**
- [ ] Matching semantics tests for globs and regexes (anchors, case-insensitivity)
- [ ] Oversized/invalid regex → skip (list) or error (custom) with code
- [ ] Prefilter never causes a false negative (proptest: prefilter ⊇ match)

**Verification:** `cargo test -p dnscraft-filtering patterns`

**Dependencies:** F3 · **Files:** `src/pattern.rs`, `tests/patterns.rs` · **Scope:** M

## Task F5: Rule builder, round trip, fuzz target

**Description:** `build_rule(&RuleSpec) -> String` for the guided editor (action, domain,
include subdomains, record types, important); proptest round trip with the parser; fuzz
target `rule_parse` (list parser) in `fuzz/` with seeds from real list styles.

**Acceptance criteria:**
- [ ] `parse_rule(build_rule(spec))` reproduces `spec` for all generated specs
- [ ] Builder output never contains characters the spec does not need
- [ ] Fuzz target runs 10 min without findings (CI 60 s job added — CI change approved with this plan)

**Verification:** `cargo test -p dnscraft-filtering builder`; `cargo +nightly fuzz run rule_parse -- -max_total_time=600`

**Dependencies:** F2 (builder), F4 (fuzz seeds) · **Files:** `src/builder.rs`, `tests/builder.rs`, `fuzz/fuzz_targets/rule_parse.rs`, `fuzz/Cargo.toml`, `.github/workflows/ci.yml` · **Scope:** S

## Checkpoint A: Rules
- [ ] All Phase 1 tests green; fuzz clean
- [ ] Manual: all 19 reference lists downloaded once (manual, not in tests) and parsed; skip report per list reviewed with owner

## Phase 2: Matching

## Task M1: Domain index and verdicts

**Description:** Arena of reversed lower-case names + sorted offsets + parallel flags;
suffix walk lookup; pattern/regex stage; AdGuard priority evaluation (`$important` allow >
`$important` block > allow > block), `$dnstype`, `$denyallow`; `Verdict` with `Reason`
(rule text, source, important).

**Acceptance criteria:**
- [ ] Table-driven priority tests (success criterion 2 cases without sets)
- [ ] Subdomain vs exact (`|x^`) semantics correct; dnstype filtering correct
- [ ] Index build is deterministic; memory per domain entry measured in a unit test

**Verification:** `cargo test -p dnscraft-filtering index`

**Dependencies:** F4 · **Files:** `src/index.rs`, `src/verdict.rs`, `tests/matching.rs` · **Scope:** M

## Task M2: Filter sets

**Description:** `FilterSet` config (lists, custom rules, services placeholder, block mode,
pause), merged per-set index with dedup and `$badfilter`, sharing of identical list
combinations, custom-rule line sources.

**Acceptance criteria:**
- [ ] `$badfilter` in one list disables the identical rule from another list in the same set only
- [ ] Two sets with identical lists share one index (`Arc::ptr_eq` in test)
- [ ] Custom rules override lists per priority rules; reasons point to custom line numbers

**Verification:** `cargo test -p dnscraft-filtering sets`

**Dependencies:** M1 · **Files:** `src/set.rs`, `src/snapshot.rs`, `tests/sets.rs` · **Scope:** M

## Task M3: Chain matching, temporary allows, pause, counters

**Description:** `match_chain` (CNAME uncloaking semantics from the spec), temporary allows
with expiry (manual clock), pause-until, per-list and per-set atomic counters.

**Acceptance criteria:**
- [ ] Blocked CNAME target blocks the chain; non-important allow on the qname does not unblock it; important allow does
- [ ] Temporary allow ranks like `$important` allow and expires exactly at `until`
- [ ] Counters increment once per match call and are readable via `stats()`

**Verification:** `cargo test -p dnscraft-filtering chain temp pause`

**Dependencies:** M2 · **Files:** `src/engine.rs`, `src/temp_allow.rs`, `src/stats.rs`, `tests/engine.rs` · **Scope:** M

## Task M4: Benchmark and memory

**Description:** Generator for a reference-shaped rule set (≈ 2.25 M rules with realistic
overlap, some globs/regexes); `criterion` benches for match (hit/miss, deep names) and
build; memory measured with a counting global allocator in a bench/test binary.

**Acceptance criteria:**
- [ ] Match p99 < 10 µs warm; build < 10 s; filtering memory ≤ 80 MB — numbers recorded in progress.md
- [ ] If missed: fallback design proposal for the owner (Checkpoint B)

**Verification:** `cargo bench -p dnscraft-filtering`

**Dependencies:** M3 · **Files:** `benches/matching.rs`, `src/testgen.rs` (feature-gated or dev) · **Scope:** S

## Checkpoint B: Matching
- [ ] Criteria 2 and 4 met (or fallback approved)

## Phase 3: Lists and services

## Task L1: List store

**Description:** Data-directory store: list bodies + metadata (ETag, Last-Modified, last
attempt/success, error code, counts) as JSON, atomic write (temp + rename), local file
lists (`file://` or path), startup load without network.

**Acceptance criteria:**
- [ ] Crash-safe write (interrupted write leaves the old file intact — simulated)
- [ ] Startup with cached lists builds the index without any fetch
- [ ] Corrupt metadata is recovered (re-fetch scheduled), never a crash

**Verification:** `cargo test -p dnscraft-filtering store`

**Dependencies:** F1 · **Files:** `src/store.rs`, `tests/store.rs` · **Scope:** S

## Task L2: Fetcher

**Description:** `reqwest` fetcher with conditional GET, streaming size cap (64 MiB default),
30 s timeout, ≤ 5 redirects with HTTPS→HTTP refused, gzip; error codes; hand-written local
HTTP/1.1 test server in tests.

**Acceptance criteria:**
- [ ] 200, 304, 404, oversize (aborted mid-stream), slow (timeout), redirect to http, garbage body, gzip — each tested with the expected status/code
- [ ] Last-good list stays active after any failure

**Verification:** `cargo test -p dnscraft-filtering fetch`

**Dependencies:** L1 · **Files:** `src/fetch.rs`, `tests/fetch.rs`, `tests/support/http.rs` · **Scope:** M

## Task L3: Scheduler, hot reload, status

**Description:** Update loop (interval default 24 h, jitter, manual "update now"),
`apply_config` with background rebuild and atomic swap, `ReloadReport`, `list_status()`
incl. unique contribution after dedup.

**Acceptance criteria:**
- [ ] Concurrent matching during a rebuild never blocks > 1 ms and never sees a half-built index
- [ ] Unique contribution numbers correct on a small fixture
- [ ] Manual clock drives the schedule in tests (no sleeping)

**Verification:** `cargo test -p dnscraft-filtering reload schedule`

**Dependencies:** M2, L2 · **Files:** `src/scheduler.rs`, `src/engine.rs`, `tests/reload.rs` · **Scope:** M

## Task L4: Blocked services catalog

**Description:** Download/cache `services.json` + `services_i18n.json` like lists, parse
(serde), expose id/name/group/icon/translations, inject service rules into sets with source
"service: <id>"; unavailable state when no catalog.

**Acceptance criteria:**
- [ ] Fixture catalog (small, hand-written, not GPL data) loads; toggling a service per set changes verdicts
- [ ] Translated names by locale with fallback to English
- [ ] Malformed catalog keeps the previous one and reports a code

**Verification:** `cargo test -p dnscraft-filtering services`

**Dependencies:** L1, L2, M2 · **Files:** `src/services.rs`, `tests/services.rs` · **Scope:** M

## Checkpoint C: Lists and services
- [ ] Criteria 5 and 6 met; reload concurrency test green

## Phase 4: Completion

## Task C1: Engine polish and acceptance

**Description:** Finalise `FilterEngine` API per spec, `stats()`, README (usage, syntax
table, error codes, limits), coverage run, 10 min fuzz, manual acceptance against the 19
real lists (load time, memory, skip report).

**Acceptance criteria:**
- [ ] Coverage ≥ 80 % lines (`cargo llvm-cov -p dnscraft-filtering`)
- [ ] All 8 success criteria in SPEC-filtering.md ticked with evidence in progress.md

**Verification:** `cargo llvm-cov -p dnscraft-filtering`; manual run

**Dependencies:** all · **Files:** `src/lib.rs`, `README.md` (crate), `tasks/progress.md` · **Scope:** M

## Checkpoint D: Complete
- [ ] All success criteria met; review passed; owner approval
