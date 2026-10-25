# Next tasks for Cursor — after `filtering`

> Ready-to-paste briefs, one per task. Each brief is self-contained.
> Previous briefs (filtering, all done): [archive/cursor-filtering.md](archive/cursor-filtering.md).
> Background: [SPEC.md](../SPEC.md) · [CAPABILITY-MAP.md](../CAPABILITY-MAP.md) · [progress.md](progress.md).

## Status (updated 2026-10-25)

- `resolver` and `filtering`: complete (filtering Checkpoint D approved 2026-10-25). R2 (per-query forward-zone allow-list) done.
- `clients`, `tls`, `policy`: specs approved. **P1 done by Claude** — plans in `tasks/plan-{clients,tls,policy}.md` + `todo-*.md`, **awaiting owner approval** (dependency table + open questions in plan-policy.md).
- Spec drafts S1–S3: done, archived in [archive/cursor-specs.md](archive/cursor-specs.md).
- Deep-name p99 ≈ 19 µs accepted by the owner → T3 dropped.
- **T1 done** (Record derives type from RData).

## Order

| # | Brief | Kind | Blocks |
|---|---|---|---|
| 1 | ~~T1 — `Record` enforces rtype ↔ RDATA~~ | tech debt (proto) | done |
| 2 | ~~R2 — per-query forward-zone allow-list in the resolver~~ | feature (resolver) | done |
| 3 | ~~P1 — plan + tasks for clients, then tls, then policy~~ | planning | done (Claude), owner approval pending |
| 5 | B — build tasks from `tasks/todo-<module>.md` (brief below) | implementation | owner approval of the plan + dependencies |
| 4 | T2 — fetcher TLS error classification | tech debt (filtering, small) | – |

T2 can run any time. B starts after the owner approves the plans — suggested order: policy (P1→P4) and tls (L1→L4), clients last (C1→…; O1 is a manual owner check before C7).

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
tasks/plan-policy.md. Work on exactly ONE task id (e.g. P1, L2, C3) from tasks/todo-<module>.md.

Do:
- Read the task's Description, Acceptance criteria, Dependencies and Files, the plan's Architecture Decisions
  and "Cross-module decisions" in tasks/plan-policy.md, and the spec sections the task touches.
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
