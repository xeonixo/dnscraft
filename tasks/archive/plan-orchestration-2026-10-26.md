# Orchestration Plan — Next Round

> Cross-module coordination plan. Per-module task detail lives in the existing
> `plan-<module>.md` / `todo-<module>.md` files; this file only fixes *which* work
> streams run now, in what order, and where the review gates are.
> Date: 2026-10-26. Authority: [progress.md](progress.md) "Current state".

## Current state (from progress.md)

| Module | State | Next |
|---|---|---|
| `resolver`, `filtering`, `clients`, `tls`, `policy` | complete | – |
| `listeners` | N13 done; N14 (minimal binary) done but needs fix round | **N14 fix round → Checkpoint D** |
| `control-api` | A3–A5 done | **Checkpoint B** (server-core review), then A6+ |
| `mcp` | spec + plan + briefing ready, 0 tasks done | **Stage 1 (M0) → Checkpoint D0** |
| `web-ui`, `cluster` | no spec yet | blocked — needs a SPEC task first |

Working tree is clean at HEAD `3ddcfbb`.

## Dependency graph

```
resolver, filtering, clients, tls ─┐
                                   ├─► policy ─► listeners ─► [N14 fixes → Checkpoint D]
                                   └─► control-api ─► [Checkpoint B] ─► A6…A14 ─► Checkpoint F
                                                                                     │
                                              mcp ──► M0 ──► M1…M19 (read/write tools)│
                                                                                     └─► M20…M27 (needs control-api F)
web-ui, cluster ──► no spec, not scheduled
```

Cross-module gates that order future work:

- **mcp M1–M5** (reopen filtering/resolver/policy) wait on **D0** (owner approves `rmcp`).
- **mcp M20–M27** wait on **control-api Checkpoint F**.
- **control-api A6+** waits on **Checkpoint B** approval.
- **web-ui / cluster** wait on their own SPEC (not yet written).

## Work streams this round (parallel, disjoint files)

### Stream 1 — `listeners` N14 fix round (implementation agent)
Authority: [briefing-n14-fixes.md](briefing-n14-fixes.md) · [todo-listeners.md](todo-listeners.md) N14.
Fix **C1, C2, R1–R5, S1–S4** in `crates/dnscraft` (with `dnscraft-listeners`/`fuzz` in the test/clippy
scope). Core acceptance conditions:

- No `ManualClock` in production (`C1`); secrets never in `Debug`/`Serialize` (`C2`).
- `deny_unknown_fields` + stable `dnscraft.*` error codes, fail-fast on bind failure (`R1–R3`).
- Real end-to-end UDP test replacing the "unit-tested only" shortcut; untick the N14 boxes that are not
  actually met (`R4`).
- Don't claim unapproved deps; mark `toml` "pending owner approval" (`R5`, owner decision **D1**).
- Async stdout writer → dedicated thread, dropped-event count; TLS `*_FILE` env vars; minimal `tracing`
  (`S1–S4`).
- N14 scope stays *minimal bootstrap* until the owner decides (**D2**).

Files: `crates/dnscraft/**`, `crates/dnscraft-listeners/**`, `fuzz/`, `deploy/dnscraft.example.toml`,
root `Cargo.toml`/`Cargo.lock` (own hunks only), `tasks/progress.md`.

**STOP: Checkpoint D** — independent security review (public exposure, amplification, admission, bans,
resource caps, TLS) + owner approval. Then archive the module.

### Stream 2 — `mcp` Stage 1, M0 (documentation agent — no repo code)
Authority: [briefing-mcp-start.md](briefing-mcp-start.md) · [mcp-todo.md](archive/mcp-todo.md) M0.
Produce the `rmcp` 3.7.0 dependency pack (crate list vs. current `Cargo.lock`, `cargo deny` result,
`cargo tree` crypto checks), answer the SPEC-mcp "Unverified details" bullets with `file:line`, write
`docs/adr/0006-mcp-rmcp-stateless.md` (Status: Proposed), fill the dependency table in
[mcp-plan.md](archive/mcp-plan.md). Work in a throw-away crate **outside** the repo; no builds, no repo code.

Files: `docs/adr/0006-mcp-rmcp-stateless.md`, `tasks/archive/mcp-plan.md` (table only), `tasks/progress.md`.

**STOP: Checkpoint D0** — owner approves `rmcp` + transitive crates (or chooses fallback). This unblocks M1–M5.

### Stream 3 — `control-api` Checkpoint B (orchestrator review — no implementation)
Run the full-workspace DoD, then review the server core (A3 router/envelopes/pagination, A4 TLS bootstrap,
A5 rate limiting): diff, `fmt`, `clippy --workspace --all-targets`, `cargo test --workspace`, `cargo deny`,
crypto trees, and the A5 rate-limit claims. Outcome: approve → A6 starts; or send back a fix list.

Files: none (review only). `tasks/progress.md` ticked on approval.

## Parallelization rules (from cursor-next.md)

- Each agent: own git worktree **or** explicit-path staging only (`git add -p`); never `git add -A` /
  `commit -a` / `stash` / `checkout` of another stream's files.
- Disjoint file ownership (see Stream files). Shared files (`tasks/progress.md`, root `Cargo.toml`,
  `Cargo.lock`): re-read right before editing, stage own hunks only, add the Log entry at the top.
- No new dependencies without an owner-approved message quoted in the commit; no `Cargo.lock` churn.
- No `CARGO_TARGET_DIR` in `/tmp`; no `cargo clean`; wait if cargo blocks on the build lock.

## Review protocol (orchestrator checks each agent's work afterward)

Per the project workflow, before ticking any checkpoint I verify:

1. `git log --oneline` shows one commit per finding/task with the required `Co-Authored-By` line.
2. Gates actually green: `fmt --check`, `clippy --workspace --all-targets --locked -- -D warnings`,
   `cargo test` (workspace or affected crates), `cargo deny check`, `cargo tree -i aws-lc-rs|aws-lc-sys|openssl-sys|native-tls` empty.
3. Acceptance criteria genuinely met (not just ticked): for bug fixes, a regression test that fails
   before the fix (mutation probe: revert → test fails → restore).
4. Scope discipline (no other agent's files touched), no secrets in logs/`Debug`, no test helpers in prod.

## Checkpoints

| Stop | Who | Decision |
|---|---|---|
| **Checkpoint D** (listeners) | security auditor + owner | approve/return |
| **Checkpoint D0** (mcp) | owner | approve `rmcp` or fallback |
| **Checkpoint B** (control-api) | orchestrator | approve → A6+ |

## Beyond this round (gated)

- **mcp Stage 2 (M1–M5)** — after D0; additive changes in filtering/resolver/policy → Checkpoint P.
- **control-api Phase 3 (A6–A9 auth) → Checkpoint C**, then A10–A14 → Checkpoint F.
- **mcp Stage 3–5 (M6–M19)** — after P; read tools → R, write tools → W.
- **mcp Phase 3 (M20–M27)** — after control-api Checkpoint F.
- **web-ui / cluster** — need SPEC tasks (no spec yet); propose starting only after the owner asks.

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Shared-file collision (`progress.md`, manifests) | Med | worktree per agent or explicit-path staging; orchestrator re-checks |
| Agent ticks acceptance boxes it didn't prove (N14 already did this once) | High | review protocol §3: mutation probe + re-verify each box |
| `toml` dep / N14 scope claimed as approved when they aren't | Med | owner decisions D1/D2 stay open; agent reports, doesn't decide |
| rmcp findings contradict SPEC-mcp | Med | M0 is docs-only and STOPs at D0 before any rmcp code (M8 re-checks) |

## Open questions (for the owner)

1. **Model naming** — no `deepseek-v4-flash[1m]` agent type exists in this tooling (Agent `model` enum is
   `sonnet|opus|haiku|fable`; the available execution agent is `general-purpose`). Plan: dispatch
   `general-purpose` agents for Streams 1–2. If "deepseek-v4-flash[1m]" maps to a specific agent config,
   name it and I'll use it.
2. **D1** — approve the `toml` dependency (recommended) or reject.
3. **D2** — N14 scope: full original text vs. minimal bootstrap + follow-up tasks (default until decided: minimal).
4. **Dispatch now?** — confirm before I spawn the two agents (the /plan gate is human approval).
