# Briefs for Cursor agents

> Reusable rules and templates. Task-specific briefs are given in chat and archived when the round is done.
> Finished briefs: [archive/cursor-filtering.md](archive/cursor-filtering.md),
> [archive/cursor-specs.md](archive/cursor-specs.md),
> [archive/cursor-clients-tls-policy.md](archive/cursor-clients-tls-policy.md).
> Background: [SPEC.md](../SPEC.md) · [CAPABILITY-MAP.md](../CAPABILITY-MAP.md) · [progress.md](progress.md).

## Status (updated 2026-10-26)

- `resolver`, `filtering`, `clients`, `tls`, `policy`: complete.
- `listeners`: Checkpoint C approved 2026-10-26; Phase 3 next (N10 DDR, N11 runtime, N12 h3, N13, N14), STOP at Checkpoint D.
- Docs catch-up (D1–D6) done 2026-10-26: root README, crate READMEs, CAPABILITY-MAP Status,
  ADRs 0002–0005; see progress.md Log.

## Rules for every task (paste once per session)

```text
Project: DNScraft, Rust workspace in this repo. Public repository: never commit personal network details
(real subnets, hostnames, hardware, IPs, API keys, domains, e-mail) — use documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 2001:db8::/32, fd00::/8 examples) and example.com/example.net names.
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
- Crypto: ring only; `cargo tree -i aws-lc-rs` and `cargo tree -i openssl-sys` must stay empty.
Definition of done for code tasks (run all, all green):
  cargo fmt --all --check
  cargo clippy --workspace --all-targets --locked -- -D warnings
  cargo test --workspace --locked
  cargo deny check
Spec tasks: no code; markdown only; end with the open questions for the owner and STOP.
Then: add a dated entry at the top of the "Log" in tasks/progress.md, update "Current state", make one commit
per task ending with the Co-Authored-By line used in earlier commits. Push.
```

## Parallel-work rules (paste when several agents run at once)

```text
Several agents work at the same time. Only touch the files your brief owns. Either give each agent its own
git worktree (git worktree add ../dnscraft-<name> -b <branch>; rebase onto main before you finish, the owner
fast-forwards after Claude's review) or, in a shared working tree, stage explicit paths only (never
git add -A / commit -a). No new dependencies and no Cargo.lock changes unless the brief says so.
tasks/progress.md is shared: edit it only at the very end, re-read it right before editing, and add your
entry at the top of the Log.
```

## S: Spec for a new module (template)

```text
Precondition: the module is listed in CAPABILITY-MAP.md and its dependencies are complete.

Do:
- Write SPEC-<module>.md in the structure of the existing specs (e.g. SPEC-policy.md): Objective, scope /
  non-goals, interfaces to the neighbouring modules (exact Rust types where they cross a crate boundary),
  configuration excerpt, limits and defaults, error codes, security considerations, testing strategy,
  success criteria (numbered, testable), open questions for the owner.
- Ground every protocol detail in the RFC / official docs and cite it; list candidate dependencies with
  version, features, licence and why (ring-only crypto).
- Update CAPABILITY-MAP.md (Spec column). Commit "spec: <module> draft". STOP for owner approval.
```

## P1: Plan and tasks for an approved spec (template)

```text
Precondition: progress.md logs SPEC-<module>.md as approved by the owner.

Do:
- Write the module's plan to tasks/plan-<module>.md and tasks/todo-<module>.md.
- Plan: phases, dependency order, risks, checkpoints (every 2–4 tasks, last one = review + owner approval).
  Tasks in exactly the format of tasks/archive/policy-todo.md: Description, Acceptance criteria
  (checkboxes), Verification command, Dependencies, Files, Scope (S/M; split anything bigger).
- New dependencies (crate, version, features, why, alternatives; ring-only crypto, no aws-lc/openssl)
  are listed in the plan for one-time owner approval. Check versions with `cargo search` and cite docs.rs.
- Cross-module needs go into the plan as explicit dependencies.
- Commit "plan: <module> plan and tasks". STOP for owner approval of the plan before any code.
```

## B: Build one task from a module todo (template)

```text
Precondition: the owner approved tasks/plan-<module>.md (logged in progress.md) incl. its dependency table.
Work on exactly ONE task id from tasks/todo-<module>.md.

Do:
- Read the task's Description, Acceptance criteria, Dependencies and Files, the plan's Architecture
  Decisions, and the spec sections the task touches.
- Check the task's Dependencies are ticked; if not, STOP and say which is missing.
- Implement with tests first where practical. Stay inside the listed files; if you must touch more, say why
  in the commit message. Dependencies only from the approved table, with the listed features.
- Tick the task's acceptance boxes and its entry in the plan's Task List, add a Log entry in progress.md.
- One commit "<module>: <task id> <short title>". At a checkpoint line: STOP for review.
```

## Archiving a finished module

When the owner approves the last checkpoint: `git mv tasks/plan-<m>.md tasks/archive/<m>-plan.md` and
`git mv tasks/todo-<m>.md tasks/archive/<m>-todo.md`, fix the relative links inside (`../SPEC…` →
`../../SPEC…`, `progress.md` → `../progress.md`), update "Current state" in progress.md.
