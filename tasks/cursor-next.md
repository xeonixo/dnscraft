# Next tasks for Cursor — after `filtering`

> Ready-to-paste briefs, one per task. Each brief is self-contained.
> Previous briefs (filtering, all done): [archive/cursor-filtering.md](archive/cursor-filtering.md).
> Background: [SPEC.md](../SPEC.md) · [CAPABILITY-MAP.md](../CAPABILITY-MAP.md) · [progress.md](progress.md).

## Status (updated 2026-10-25)

- `resolver` and `filtering`: complete (filtering Checkpoint D approved 2026-10-25). R2 (per-query forward-zone allow-list) done.
- `clients`, `tls`, `policy`: specs approved. **P1 done by Claude** — plans in `tasks/plan-{clients,tls,policy}.md` + `todo-*.md`, **approved by the owner 2026-10-25** incl. the dependency table; Pebble local only; order policy + tls, then clients.
- Spec drafts S1–S3: done, archived in [archive/cursor-specs.md](archive/cursor-specs.md).
- Deep-name p99 ≈ 19 µs accepted by the owner → T3 dropped.
- **T1 done** (Record derives type from RData).

## Order

| # | Brief | Kind | Blocks |
|---|---|---|---|
| 1 | ~~T1 — `Record` enforces rtype ↔ RDATA~~ | tech debt (proto) | done |
| 2 | ~~R2 — per-query forward-zone allow-list in the resolver~~ | feature (resolver) | done |
| 3 | ~~P1 — plan + tasks for clients, then tls, then policy~~ | planning | done (Claude), approved |
| 5 | B — build tasks from `tasks/todo-<module>.md` (brief below) | implementation | – (plans approved) |
| 4 | T2 — fetcher TLS error classification | tech debt (filtering, small) | – |

T2 can run any time. B may start now — order: policy (P1→P4) and tls (L1→L4), clients last (C1→…; O1 is a manual owner check before C7).

## Round 2026-10-25 evening — three parallel Cursor agents

Claude review (2026-10-25) of the checkpoints: **policy Checkpoint B passed**, **clients Checkpoint A
passed**, clients Checkpoint B **not** passed (engine/sync bugs below), tls ready for Checkpoint C apart from
the hardening items below. DoD green at review time (fmt, clippy `-D warnings`, all tests of the three
crates; `cargo tree -i aws-lc-rs` / `openssl-sys` empty).

| Agent | Brief | Works in | Owns (only touch these) |
|---|---|---|---|
| 1 | **C11** clients review fixes | main working tree (clients crate is still uncommitted) | `crates/dnscraft-clients/**`, `tasks/todo-clients.md` |
| 2 | **P9b → P10 → P11 → P12** rebind for SVCB hints, policy operations, golden tests | worktree `../dnscraft-policy`, branch `policy-p10` | `crates/dnscraft-policy/**`, `tasks/todo-policy.md` |
| 3 | **L12 + T2** tls hardening, zeroize, cargo-deny, fetcher TLS codes | worktree `../dnscraft-tls`, branch `tls-l12` | `crates/dnscraft-tls/**`, `crates/dnscraft-filtering/src/fetch*.rs` + its tests, `deny.toml`, `.github/workflows/ci.yml`, `tasks/todo-tls.md` |

Parallel-work rules (paste with the general rules):

```text
Three agents work at the same time. Agent 1 works in the main working tree; agents 2 and 3 each create a
git worktree first (git worktree add ../dnscraft-<name> -b <branch>) so a half-finished edit in one crate
never breaks the workspace build of another. Only touch the files your brief owns. No new dependencies and
no Cargo.lock changes — except the owner-approved `zeroize` workspace line (Agents 1 and 3). tasks/progress.md is shared: edit it only at the very end, re-read it right before
editing, add your entry at the top of the Log, and stage explicit paths only (never git add -A / commit -a).
Agents 2 and 3: rebase onto main before you finish; the owner merges (fast-forward) after Claude's review.
```

## C11: clients review fixes (Agent 1)

```text
Context: Claude reviewed clients C1–C10 (progress.md "Current state"). Checkpoint A passed; Checkpoint B
is blocked by the bugs below. The crate is still uncommitted.

Step 0: commit the existing work as is: stage crates/dnscraft-clients, Cargo.toml, Cargo.lock,
tasks/plan-clients.md, tasks/todo-clients.md, tasks/progress.md, tasks/todo-policy.md, tasks/cursor-next.md, SPEC-policy.md
explicitly → "clients: C1–C10 UniFi client directory" (the last three carry Claude's review and the owner's
decisions) and push.
Agents 2 and 3 start only after this commit exists (their worktrees branch from it). Then fix, one regression test per item that FAILS before the fix:

Required
1. src/engine.rs install_snapshot: when the content hash is unchanged it returns early and DROPS the new
   State (and obs/nets). State carries ipv6_last_seen and retain timestamps, so a continuously observed
   IPv6 address keeps the timestamp of the last *rebuild*; when it disappears hours later it expires at
   once instead of after ipv6_ttl. persist_cache then writes the stale state too. Fix: always store
   state/obs/nets; only skip the lookup swap + generation bump when the hash is unchanged.
   Test (ManualClock): IPv6 seen at t0 (rebuild), unchanged syncs until t0+2·ttl, address gone at
   t0+2·ttl+1 → still indexed until (last observation + ttl).
2. src/sync.rs merge_observations returns by_id.into_values() — HashMap order is random, and
   hash_content hashes obs in order, so with ≥ 2 clients the hash changes on every poll and the snapshot
   is rebuilt every 60 s (defeats the spec's change detection). tests/engine.rs unchanged_data_no_rebuild
   only seeds ONE client, so it cannot catch this. Fix: sort observations (and networks) by id before
   returning, or make the hash order-independent. Test: seed ≥ 5 Integration + classic clients, two
   syncs → second `!rebuilt`; run it 20× in a loop locally.
3. No serialisation between the poll loop, sync_now and apply_config. run_sync clones the config at the
   start; an apply_config during a slow sync is overwritten by the sync result built with the OLD manuals;
   two concurrent syncs can install the older result last. Fix: one tokio::sync::Mutex (single-flight,
   like tls TlsEngine::do_issue) held across "read config → fetch → build → install → persist"; apply_config
   takes the same lock. Test: mock gateway with a delayed response, apply_config adding a manual while
   sync_now is in flight → after both finish the manual is in lookup().
4. apply_config calls install_snapshot before storing the new config, so refresh_status_counts reports
   the old manual_count / poll_interval. Store config first (inside the lock from 3). Test on status().
5. start_scheduler waits a full jittered poll interval before the first live sync (comment says "first sync
   soon"). Without a cache that means up to 66 s of manuals-only after every restart. Sync immediately on
   start (then the normal cadence). Test with ManualClock: attempt count 1 without advancing the clock.
6. tests/engine.rs:312 `assert!(ok.classic_error.is_none() || ok.rebuilt || !ok.rebuilt)` is a tautology.
   Replace with real assertions.

Optional (do them if time allows, each small)
- gateway.rs: classify TLS errors by walking the source chain and downcasting to rustls::Error
  (InvalidCertificate → tls.untrusted) instead of string matching; drop the duplicate Connect branch in
  map_transport.
- tls.rs: remove `CryptoProvider::install_default` (process-wide side effect in a library; the binary
  decides). Build GatewayClient once and rebuild only on config change instead of on every poll.
- sync_now while backoff is active returns a fake HTTP 429; give it its own code `clients.sync.backoff`
  (add to the code-uniqueness test and README failure table).
- classic.rs: validate the site key from the gateway (`[A-Za-z0-9_-]{1,64}`) before putting it into a URL path.
- cache.rs: read with a size cap (File::take(MAX+1)) instead of metadata-then-read (TOCTOU); persist only
  when state/obs changed (avoids an fsync every minute).
- apply_config: if UniFi was disabled at boot (no key loaded) and is now enabled, try read_secret once.

Owner-approved addition (required)
7. zeroize (owner approved 2026-10-25): add `zeroize = { version = "1.9", default-features = false,
   features = ["alloc"] }` to [workspace.dependencies] (zeroize 1.9.1 is already in Cargo.lock via rustls —
   no new crate) and to dnscraft-clients. `Secret` wipes its buffer on drop (Zeroizing<String> or
   impl Drop + Zeroize); `Clone` stays allowed. Avoid extra plain copies of the key (engine.rs
   apply_config/new_with_secret currently copy it via `expose().to_owned()` — pass the Secret instead).
   Agent 3 adds the same line to the workspace; on rebase keep one identical entry.

Then: re-run coverage (llvm-cov), update the success-criteria table, tick Checkpoint B boxes in
tasks/todo-clients.md EXCEPT "Lead review", log entry, commit "clients: C11 review fixes". STOP —
Checkpoint B re-review + Checkpoint C security review are Claude's.
```

## C11b: clients re-review follow-ups (Agent 1)

```text
Claude re-reviewed C11 in the working tree (progress.md, newest entry). Fixes 1–6 are correct. Before
Checkpoint B can pass:
1. Flaky test: tests/engine.rs poll_cadence_respects_jitter_bounds failed 5 of 6 full-suite runs. It waits
   for the immediate first sync with wall-clock sleeps (80 ms); under load the TLS mock sync has not
   finished, the scheduler computes its deadline after clock.advance(80s), and the +120 s poll never fires.
   Make it deterministic: wait until the first sync has completed (e.g. loop on status().last_success /
   a test-only "parked" Notify with a generous timeout) before advancing the ManualClock; same check for
   every engine test that sleeps for the first sync (two_clients_…, unchanged_hash_…). Prove it: run
   `cargo test -p dnscraft-clients` 20× in a loop, 0 failures, and paste the count in the log entry.
2. apply_config writes the new config before merge::build, which can still fail (TooMany, FQDN/domain
   errors after validation). Then the error is returned but the bad config stays active and every later
   poll fails with it. Order under the lock: validate → build with the new config → only on success store
   config + install snapshot + persist. Regression test: a config that passes validate but fails build
   → apply_config errs, status()/lookup() unchanged, next sync_now succeeds with the old config.
3. Item 7 of C11 (zeroize for clients `Secret`) — still required.
4. Commit everything listed in C11 step 0 plus your fixes ("clients: C1–C11 UniFi client directory" is
   fine as one commit), add your Log entry, push.
Optional: hold sync_lock only around build+install (fetch outside, rebuild with the config current at
install time) so a config save never waits on gateway timeouts; dedicated race test for apply_config
during an in-flight sync (mock with delayed response).
STOP for Claude's Checkpoint B tick + Checkpoint C security review.
```

## P10 → P12: policy operations and golden tests (Agent 2)

```text
Precondition met: policy Checkpoint B passed (Claude, 2026-10-25). Do P9b first (below), then P10, P11,
P12 from tasks/todo-policy.md in order, one commit each ("policy: P9b …", "policy: P10 …"), B template rules.

P10b — follow-ups from Claude's P10 review (progress.md, newest policy entry), BEFORE P9b, one commit
"policy: P10b pause trace, stats scope":
- DecisionStep::ProtectionPaused { scope } recorded once when the profile/global pause is active (test
  query shows why a blocked name passed). Test.
- Do not count test queries (`!loggable`) in stats(); test.
- Reload test that adds a new view + profile and checks both are counted (kills the surviving mutant
  "ensure() skips new profiles").
- Nits: reject PauseUntil::For(ZERO) with a config code (or document), drop stats of removed ids,
  serialise apply_config with a Mutex around build+swap, `clients()`/`filter()` → pub(crate) or
  #[doc(hidden)], `resume` without Result if it cannot fail.

P9b — rebind for SVCB/HTTPS hints + additional section (owner decision 2026-10-25, SPEC-policy.md step 10):
- In steps/rebind.rs, for HTTPS/SVCB records in the answer section: parse SvcParam key 4 (ipv4hint,
  value = n × 4 bytes) and key 6 (ipv6hint, n × 16 bytes) from dnscraft_proto::SvcbData::params (opaque
  bytes; RFC 9460 §7.3, cite it); remove private addresses (same is_private_for_rebind); if a hint becomes
  empty drop that param; keep the record and key order. A malformed hint length → leave the record
  unchanged (do not drop data you cannot parse) and add a test for it.
- Strip private A/AAAA from the additional section too.
- Any change → clear AD, drop EDE, DecisionStep::RebindStripped counts all removed addresses.
- Same skip rules (disabled, exception, exempt forward zone, synthetic). Tests: HTTPS with mixed hints,
  all-private hint dropped, ipv6hint, additional section, exception skips, malformed hint untouched, AD/EDE.
- Add P9b to tasks/todo-policy.md (Phase 2, after P9) with ticked criteria.

Notes from the review to apply while you are there:
- P10: PolicyEngine currently holds a plain Arc<PolicySnapshot>; hot reload needs the same pattern as
  filtering (RwLock<Arc<…>> cloned under a short lock, never held across .await). apply_config must not
  swap on validation failure (test). Pause is checked at steps 4/6/8/9 only — add a test that rebind,
  AAAA suppression and canaries still run while paused.
- engine.rs handle(): the early-return `emit(draft, synth, ctx.client_id.clone(), loggable, None, None)`
  block is repeated six times; when you touch handle() for P10, fold it into one helper/closure.
- Rebind NODATA (all addresses stripped) has no SOA in the authority section, so clients cannot
  negative-cache it (RFC 2308 §2.2). Add the synthetic SOA used elsewhere (synth.rs) — small, with test.
- P12 README: document the rebind scope (A/AAAA, SVCB/HTTPS hints, additional section) in the pipeline table.
- P12: golden tests for spec criteria 1–5, bench (p50 < 1 ms, record numbers), coverage ≥ 80 %, README.

STOP at Checkpoint C (independent review is Claude's; owner approval).
```

## L12 + T2: tls hardening and Checkpoint C prep (Agent 3)

```text
Context: tls L1–L11 done, Checkpoint B passed. Claude's security pass for Checkpoint C found no blocker;
do these before the formal review. Each fix with a test that fails before it. One commit for L12, one for T2.

L12 (crates/dnscraft-tls)
1. Retry-After (open nit from Checkpoint B): cloudflare.rs appends "; Retry-After: …" to the message text
   and the scheduler parses it back. Carry it as a structured field (`retry_after: Option<Duration>` on
   the error variant) and use that in the backoff; keep the 6 h cap. Test: 429 with Retry-After: 120 →
   next attempt exactly 120 s later on the ManualClock.
2. SNI: parse_client_id_sni returns the label in the client's case and accept_public_sni passes it to the
   registry as is; Client IDs are [a-z0-9-], so "KID.dns.example.com" is rejected while "kid.…" is accepted.
   Lowercase (ASCII) the label before the registry check, or document that registries must compare
   case-insensitively — pick one, test both spellings. Also reject labels outside [a-z0-9-]{1,63} as Other.
3. CertStore::load: tighten key.pem / account.json to 0600 (and warn with a stable code
   `tls.store.permissions`) if they are group/world readable, e.g. after a restore from backup. Test with a
   0644 file.
4. Write the owner's manual staging acceptance checklist into the README (Checkpoint C item 3): exact
   config, env vars, the commands, what to look for in status/state.json, how to switch to production,
   how to roll back. No real domains — example.com placeholders.
5. Coverage is 77 % (< 80 %). Add tests for the uncovered non-Pebble paths in engine.rs / acme.rs (list
   them from llvm-cov); if a gap remains, list it with a reason in progress.md.

T2 (crates/dnscraft-filtering): use the existing brief "T2: Fetcher TLS error classification" below,
unchanged. Same technique as item 1 of the clients optional list: walk the source chain and downcast to
rustls::Error instead of matching message text.

Owner-approved additions (2026-10-25), part of L12:
6. zeroize for tls `Secret` (and `KeyPem` if it holds key bytes): same workspace line as Agent 1 —
   `zeroize = { version = "1.9", default-features = false, features = ["alloc"] }` (1.9.1 already in
   Cargo.lock via rustls). Wipe on drop; no extra plain copies of the token. On rebase keep one identical
   [workspace.dependencies] entry and regenerate Cargo.lock with `cargo check` (never hand-edit it).
7. cargo-deny: add deny.toml at the repo root — [licenses] allow-list compatible with MIT OR Apache-2.0
   (check every license in the current tree with `cargo deny check licenses`, list exceptions with a
   reason; the filtering services catalog is runtime data, not a crate); [bans] deny `aws-lc-rs`,
   `aws-lc-sys`, `openssl`, `openssl-sys`, warn on multiple versions; [advisories] RustSec db, no ignores
   without a written reason; [sources] crates.io only. Add a `deny` job to .github/workflows/ci.yml using
   EmbarkStudios/cargo-deny-action pinned to a release tag (cite the README). Install cargo-deny locally
   (`cargo install cargo-deny --locked`) and run `cargo deny check` green before committing. You own
   deny.toml and .github/workflows/ci.yml for this round. Separate commit "ci: cargo-deny".

Tick only the boxes you completed in tasks/todo-tls.md (not "Independent security review", not "Owner
approval"). STOP.
```

## Rules for every task (paste once per session)

```text
Project: DNScraft, Rust workspace in this repo. Public repository: never commit personal network details
(real subnets, hostnames, hardware, IPs, API keys) — use documentation ranges (192.0.2.0/24, 198.51.100.0/24,
2001:db8::/32, fd00::/8 examples) and example.com/example.net names.
Read first: SPEC.md, CAPABILITY-MAP.md, the "Current state" and "Log" in tasks/progress.md, and the brief's
referenced files.
Conventions:
- English code, comments and docs (chat may be German). No unwrap()/expect() outside tests. No unsafe.
  No new dependencies without asking the owner. Every public item documented. Every error variant has a
  stable code() ("area.reason") covered by a code-uniqueness test.
- Tests never touch the internet or real UniFi/Cloudflare/ACME endpoints (mock servers only, see SPEC.md
  Testing Strategy).
- Bug fixes need a regression test that fails before the fix.
- Claims about external APIs/RFCs/crates must be checked against the official source; cite the URL in the
  spec or PR text. Mark anything you could not verify as "unverified".
Definition of done for code tasks (run all, all green):
  cargo fmt --all --check
  cargo clippy --workspace --all-targets --locked -- -D warnings
  cargo test --workspace --locked
Spec tasks: no code; markdown only; end with the open questions for the owner and STOP.
Then: add a dated entry at the top of the "Log" in tasks/progress.md, update "Current state", make one commit
per task ending with the Co-Authored-By line used in earlier commits. Push.
```

---

## T1: `Record` enforces rtype ↔ RDATA (proto)

```text
Follow-up from progress.md (Task W2): `dnscraft_proto::Record` does not enforce that `rtype` matches the
RData variant (e.g. rtype A with RData::Aaaa can be constructed and encoded).

Do:
- Make the invariant unrepresentable or checked: preferred — derive the type from the RData (RData::rtype(),
  RData::Unknown keeps its explicit type) and remove the separate field, or make fields private with a
  checked constructor returning an error with a stable code. Pick the option with the smaller blast radius
  across crates (resolver, testkit, filtering use Record); explain the choice in the commit message.
- Decoding must keep rejecting/handling mismatches exactly as today (no behaviour change on the wire).
- Regression test that the invalid combination can no longer be built (or returns the error); existing
  oracle/proptest suites stay green; run the three proto fuzz targets 60 s each as a smoke test.
Files: crates/dnscraft-proto/src/record.rs (+ call sites). Scope: S–M.
```

## R2: Per-query forward-zone allow-list (resolver)

```text
Needed by SPEC-policy.md ("Forward zones vs profiles", decision 5: approved). A profile may restrict which
forward zones apply; other names recurse normally. Read SPEC-policy.md (Forward zones vs profiles, DNS
rebind protection) and SPEC-resolver.md (forward zones) first.

Do:
- Give `ForwardZone` (crates/dnscraft-resolver/src/config.rs) a stable `id: ForwardZoneId` (newtype over
  a string, charset like filtering's ListId: [a-z0-9-], validated; duplicate ids → config error with a
  stable code).
- Extend `RequestFlags` (src/types.rs) with `forward_zones: Option<Arc<[ForwardZoneId]>>`: `None` = all
  configured zones apply (today's behaviour), `Some(ids)` = only those zones may forward; a name under a
  non-allowed zone is resolved recursively from the root as if the zone did not exist.
- Cache correctness: the same name can now have a forwarded and a recursive answer. The cache and in-flight
  coalescing keys must include the effective route (forward zone id or "recursive"), so a profile without
  the zone never gets the forwarded answer and vice versa. Regression test for exactly that.
- Report the route on the answer (e.g. `Answer.forward_zone: Option<ForwardZoneId>`), because policy logs
  it and exempts forward-zone answers from rebind protection.
- Local zones (RFC 6303) keep their current interaction with forward zones; loop protection unchanged.
- Tests with the testkit: allowed zone forwards, disallowed zone recurses, None = all, cache separation,
  coalescing separation, route reported. Update the resolver README configuration table.
Files: crates/dnscraft-resolver/src/{config.rs,types.rs,forward.rs,lib.rs,cache.rs,inflight.rs} (+ tests). Scope: M.
```

## P1: Plan and tasks for an approved spec (template)

```text
Precondition: progress.md logs SPEC-<module>.md as approved by the owner. Order: clients, tls, policy —
one module per run, STOP after each.

Do:
- Write the new module's plan to tasks/plan-<module>.md and tasks/todo-<module>.md.
- Plan: phases, dependency order, risks, checkpoints (every 2–4 tasks, last one = review + owner approval).
  Tasks in exactly the format of tasks/archive/resolver-todo.md: Description, Acceptance criteria
  (checkboxes), Verification command, Dependencies, Files, Scope (S/M; split anything bigger).
- New dependencies (crate, version, features, why, alternatives; ring-only crypto, no aws-lc/openssl)
  are listed in the plan for one-time owner approval. Check versions with `cargo search` and cite docs.rs.
- Cross-module needs go into the plan as explicit dependencies (e.g. policy needs R2, the
  ClientDirectory trait lives in policy, control-api adapts clients).
- Add ready-to-paste briefs for the first 3–5 tasks to this file.
- Commit "plan: <module> plan and tasks". STOP for owner approval of the plan before any code.
```

## B: Build one task from a module todo (template)

```text
Precondition: the owner approved tasks/plan-<module>.md (logged in progress.md) and the dependency table in
tasks/archive/policy-plan.md. Work on exactly ONE task id (e.g. P1, L2, C3) from tasks/todo-<module>.md.

Do:
- Read the task's Description, Acceptance criteria, Dependencies and Files, the plan's Architecture Decisions
  and "Cross-module decisions" in tasks/archive/policy-plan.md, and the spec sections the task touches.
- Check the task's Dependencies are ticked; if not, STOP and say which is missing.
- Implement with tests first where practical. Stay inside the listed files; if you must touch more, say why in
  the commit message. Dependencies only from the approved table, with the listed features; for tls run
  `cargo tree -i aws-lc-rs` (must be empty).
- Tick the task's acceptance boxes and its entry in the plan's Task List, add a Log entry in progress.md.
- One commit "<module>: <task id> <short title>". At a checkpoint line: STOP for review.
```

## T2: Fetcher TLS error classification (filtering)

```text
Known gap from progress.md (Task L2): the fetcher maps TLS failures to an error code by matching the error
message text, and that path is untested.

Do:
- Classify via the error source chain (std::error::Error::source → rustls::Error / io errors) instead of
  string matching; keep the existing codes.
- Tests with the local test server: (a) TLS server with a self-signed cert → TLS code, (b) plain HTTP on an
  https URL → TLS/protocol code, (c) connection refused → connect code. Use the test hatch that already
  exists for local sources; no new dependencies unless a test-only cert generator is needed (ask first —
  rcgen is likely already in the tree via hickory test deps, check `cargo tree` before asking).
Files: crates/dnscraft-filtering/src/fetch.rs, tests/fetch.rs. Scope: S.
```
