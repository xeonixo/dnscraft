# Next tasks for Cursor — `filtering` module

> Ready-to-paste briefs, one per task, in dependency order. Each brief is self-contained.
> Background: [SPEC-filtering.md](../../SPEC-filtering.md) · [plan.md](filtering-plan.md) ·
> [todo.md](filtering-todo.md) (acceptance criteria) · [progress.md](../progress.md) (what is done, lessons).

## Rules for every task (paste once per session)

```text
Project: DNScraft, Rust workspace in this repo. Work only in crates/dnscraft-filtering unless the brief says otherwise.
Read first: SPEC-filtering.md, tasks/plan.md, the task's entry in tasks/todo.md, and the "Log" in tasks/progress.md.
Conventions:
- English code, comments and docs. No unwrap()/expect() outside tests. No unsafe. No new dependencies
  without asking (approved for this module: reqwest 0.12 rustls/ring, regex, idna, serde, serde_json, tokio).
- Every public item documented. Every error variant has a stable code() ("area.reason"), covered by the
  code-uniqueness test.
- Tests never touch the internet. Real lists live cached in target/reference-lists/ (fill them with
  `cargo run --release -p dnscraft-filtering --example parse_lists`) and are used only by #[ignore] tests.
- Bug fixes need a regression test that fails before the fix.
Definition of done (run all, all green):
  cargo fmt --all --check
  cargo clippy --workspace --all-targets --locked -- -D warnings
  cargo test --workspace --locked
Then: tick the task's checkboxes in tasks/todo.md and tasks/plan.md, add a dated entry at the top of the
"Log" in tasks/progress.md (what was done, numbers measured, decisions), update "Current state", and make one
commit per task ending with the Co-Authored-By line used in earlier commits. Push.
```

## Status when this file was written (2026-10-25)

- Done and committed: F1–F4, F5 builder, F6, R1, L1–L4, M1–M4a/M4b, **C1**.
- Checkpoint A complete; Checkpoint B owner: RAM may grow; Checkpoint C (lists/services) met with L4.
  **Checkpoint D ready for Claude/owner review** (not marked by Cursor).

## Order

1. **M4a — build-peak and memory slimming** (most important: decides whether the budget holds)
2. **R1 — two small parser fixes** (anytime)
3. **F6 — IP rules** (independent of M4a; separate files except `index.rs` → do after M4a or coordinate)
4. **M3 — chain matching, temporary allows, counters**
5. **M4b — criterion benchmarks** (Checkpoint B: show numbers to the owner)
6. **L3 — scheduler, hot reload, status**
7. **L4 — blocked services catalog**
8. **C1 — engine polish, README, coverage, acceptance** → Checkpoint D, then review with Claude

---

## M4a: Cut the index build peak and slim entries

```text
Task: make reloading the reference filter set fit the memory budget (SPEC.md: ≤150 MB RSS for the whole
process; filtering target ≤80 MB steady state).

Measured (progress.md, M2): one set with all 19 real lists → index 67.7 MB steady state (names 31.7 MB +
19 B/entry overhead × 1.897 M entries = 36 MB), but the build peak is ≈ +147 MB above baseline (IndexBuilder
`pending` and `arena` vectors before sort/compaction + the largest list's Vec<Rule>). During a hot reload
the old index stays alive, so peak = old index + build peak → far over budget.

Do:
1. Slim per-entry data in src/index.rs (currently offsets 4, flags 1, src 4, line 4, text_off 4, text_len 2):
   - drop `lines`: derive the line number lazily from the text offset when a Reason is built (the text source
     can count newlines up to the offset, or return it);
   - source id as u16 (reject > 65535 sources with an error code);
   - drop `text_lens`: the text source reads up to the next newline from the offset.
   Target ≈ 11 B/entry. Keep the RuleTextSource trait shape sensible for an on-disk implementation (L3).
2. Reduce the build peak:
   - feed rules into the builder per list without keeping a Vec<Rule> per list (streaming callback or iterator
     from the parser — coordinate the parser API: add a `parse_list_each(body, source, |rule| …)` that does
     not allocate a Vec; keep parse_list for tests/UI);
   - avoid holding a DomainName heap box per pending rule: write reversed name bytes straight into the arena
     when the rule arrives;
   - sort an index array of u32 instead of 24-byte pending records if that lowers the peak; shrink_to_fit at the end.
   Target: build peak ≤ +60 MB above baseline for the reference set.
3. Extend the #[ignore] test `real_lists_snapshot` in tests/sets.rs (or add one) to print: build time,
   VmRSS before/after, VmHWM delta during build, Index::memory() figures. It must not keep the list bodies in
   memory during the measurement (read them from target/reference-lists/ per list).
4. Keep all existing tests green; behaviour (verdicts, reasons, priority, dedup, badfilter) must not change.

Report the before/after numbers in progress.md. If the targets are missed, write down why and the next
option (e.g. hash-of-suffix table) — the owner decides at Checkpoint B.
```

## F6: IP rules (answer filtering)

```text
Task F6 in tasks/todo.md. Owner decision (Checkpoint A): support AdGuard IP rules such as `||194.63.143.96^`,
`194.63.143.96`, `@@||1.2.3.4^`, IPv6 forms, with $important / $badfilter. They match ADDRESSES IN DNS ANSWERS
(policy will call the new API for every A/AAAA record of a resolved answer).

Do:
- Parser: these lines currently skip as `invalid_syntax` (reason `ip_address`). Turn them into a new rule kind
  (e.g. MatchKind::Ip) holding an IpAddr; hosts lines whose *name* is an IP stay invalid (that is a different
  case — see the parser fix in git log). Builder/describe_rule: return None / reject for IP rules.
- Index: a separate IP index (sorted Vec<u32> for IPv4, Vec<u128> for IPv6, parallel flags + source + text
  offset like domain entries), badfilter and dedup like domain rules.
- API: `Index::match_answer_ip(&self, ip: IpAddr) -> Verdict` and `Snapshot::match_answer_ip(&SetId, IpAddr, now)`
  with the same priority rules (important allow > important block > allow > block), pause respected,
  Reason pointing at the rule.
- Tests in tests/ip_rules.rs: parse forms, IPv6 canonicalisation, allow/important/badfilter, reason text,
  unknown set, paused set.
- Rerun `cargo run --release -p dnscraft-filtering --example parse_lists` and note in progress.md how many IP
  rules the AdGuard DNS filter now yields (was 72 invalid_syntax).
```

## R1: Two small parser fixes from the real-list run (do anytime, ~30 min)

```text
1. Regex rules are compiled with Unicode classes, so a real AdGuard DNS filter rule like
   /^(mon|tue|wed|thu|fri|sat|sun)\d{1,2}\.\w{2}\d{1,6}\w{4}\.com$/ fails with regex_too_large.
   Hostnames are ASCII: build regexes with RegexBuilder::unicode(false) (keep case_insensitive and the size
   limits). If unicode(false) rejects a pattern that only works with Unicode, skip it with invalid_regex.
   Regression test with that exact rule.
2. AdGuard DNS filter contains rules like `://jhf.ru^` and `://*.a-akamaihd.com^` (17 skipped as
   browser_only). In URL syntax `://` marks the start of the hostname: treat `://x^` as an exact-start
   anchor (same as `|x^` → Exact) and `://*.x^` as the glob `||*.x^`. A `://` followed by a path (`/`)
   stays browser_only. Tests + rerun examples/parse_lists.rs, note the new numbers in progress.md.
```

## M3: Chain matching, temporary allows, pause, counters

```text
Task M3 in tasks/todo.md. Build on src/snapshot.rs (Snapshot::match_name) and src/index.rs.

Do:
- `Snapshot::match_chain(&SetId, &[DomainName], qtype, now) -> Result<Verdict, FilterError>` for CNAME
  uncloaking: the first blocking verdict along the chain wins; a non-important allow on the queried name does
  NOT unblock a blocked CNAME target; an important allow on the target does. Document the exact rules with
  examples in the doc comment.
- Temporary allows: `TempAllow { domain, include_subdomains, until: SystemTime }` per set; they rank like an
  `$important` allow; expire exactly at `until` (use the injected clock / `now` parameter, never sleep);
  stored outside the immutable index (a small RwLock'ed map per set) so adding one does not rebuild the
  snapshot; list/remove API; RuleSource::TemporaryAllow in the Reason.
- Pause already exists (paused_until) — add resume/pause API on the engine side only if needed by M3 tests.
- Counters: per list and per set atomics (matches, blocks, allows) incremented once per match call; `stats()`
  returns a plain struct. Use Relaxed atomics; no locks in the hot path.
- Tests in tests/engine.rs covering every acceptance criterion of M3.
```

## M4b: Criterion benchmarks (Checkpoint B)

```text
Task M4 in tasks/todo.md (benchmark part). criterion is already a workspace dev-dependency.

Do:
- A deterministic generator for a reference-shaped rule set (~2.25 M rules: mostly subdomain rules, ~85 k
  exact hosts rules, ~500 globs, ~30 regexes, 15 % duplicates across "lists") in a test-support module
  (dev-only, not in the public API).
- benches/matching.rs: match hit, miss, deep name (10 labels), chain of 3, IP rule; build time of the full set.
  Report p50/p99 where criterion allows (or compute from samples in an #[ignore] test).
- Record in progress.md: match p99 (< 10 µs target), build time (< 10 s), memory (from M4a measurement).
- Then stop: Checkpoint B needs the owner's review of these numbers.
```

## L3: Scheduler, hot reload, status

```text
Task L3 in tasks/todo.md. Pieces that exist: ListStore (src/store.rs), Fetcher (src/fetch.rs),
SnapshotBuilder/Snapshot (src/snapshot.rs), RuleTextSource trait (src/index.rs).

Do:
- `FilterEngine` (src/engine.rs): holds `RwLock<Arc<Snapshot>>`; readers clone the Arc (lock held only for the
  clone); `apply_config(FilterConfig)` and `update_lists(ListSelection)` rebuild on a blocking thread
  (tokio::task::spawn_blocking) and swap atomically; at most one rebuild at a time (coalesce requests).
- On-disk RuleTextSource backed by ListStore: read the rule line at the stored offset from the cached list file
  (pread/seek), small LRU of recently used lines; custom rule text stays in memory.
- ListBodies from ListStore (bodies read per list during build, never all at once).
- Startup: build from cached lists without any network access; then schedule updates.
- Scheduler: interval from FilterConfig (default 24 h) + random jitter (±10 %), driven by the injectable Clock
  so tests do not sleep (tick-based or a clock-aware sleep helper); manual "update now".
- ReloadReport and list_status(): per list last attempt/success, error code, rules parsed/skipped, unique
  contribution.
- Tests in tests/reload.rs: concurrent matching during rebuild never blocks > 1 ms and never sees a half-built
  index; startup without network; failed update keeps last good; schedule with manual clock.
```

## L4: Blocked services catalog

```text
Task L4 in tasks/todo.md.

Do:
- Download/cache AdGuard HostlistsRegistry `services.json` + `services_i18n.json` via the existing Fetcher and
  ListStore::services_dir() (same conditional GET / size cap / last-good rules). GPL data: never commit it,
  never embed it.
- Parse with serde (be lenient: unknown fields ignored, malformed entries skipped and counted).
- Expose ServiceCatalog: id, name, group, icon (SVG string as provided), translated names by locale with
  English fallback.
- FilterSetConfig.services (already a Vec<String>) → the services' rules join the set with
  RuleSource::Service{id}; unknown ids reported, not fatal.
- Tests with a small hand-written fixture catalog (NOT copied from AdGuard data).
```

## C1: Engine polish and acceptance (then Checkpoint D)

```text
Task C1 in tasks/todo.md.

Do:
- Finalise the FilterEngine API to match SPEC-filtering.md "Interface (sketch)"; remove dead code.
- Deduplicate the RR type-name table (builder.rs has a copy of modifiers.rs's TYPE_NAMES — make one pub(crate)).
- crates/dnscraft-filtering/README.md in the style of crates/dnscraft-resolver/README.md: what it is, syntax
  table, priority rules, error-code table (every code()), limits/constants table, how to run the real-list tool.
- Coverage ≥ 80 %: `cargo llvm-cov -p dnscraft-filtering`.
- Fuzz `rule_parse` 10 min clean.
- Real-list acceptance: build time, steady RSS, reload peak, skip report — all into progress.md, ticking the
  8 success criteria of SPEC-filtering.md with evidence.
- Then hand back to Claude for the Checkpoint D review (do not mark Checkpoint D yourself).
```
