# Progress log

Resume point for interrupted sessions. Newest entry first.
Task details: [todo.md](todo.md) · Plan: [plan.md](plan.md)

**Workflow:** each task is implemented by a Haiku/Sonnet subagent, reviewed by the lead
(diff, `fmt`, `clippy`, tests), ticked off in `todo.md`, logged here, and committed.

## Current state

- Phase: 1 (Foundation)
- Phase 1 done. ADR-0001 accepted as **Option D** (in-house wire format + DNSSEC logic, `ring` for crypto).
- Checkpoint A passed (plan + new deps approved).
- In progress: Task W1 — Domain names and compression (Sonnet agent)
- Blockers: none

## Log

- 2026-10-24 — Owner chose Option D at Checkpoint A. ADR amended, SPEC/map updated, plan revised: new phase 1b (W1–W5), Task 9 split into 9a/9b.

- 2026-10-24 — Task 2 done (Sonnet agent, reviewed; key claims re-verified on crates.io/GitHub): `hickory-recursor` abandoned, successor experimental and missing serve-stale/forward zones/EDE/NTA/dedup/ports; ADR-0001 proposes Option C. Plan revised accordingly.

- 2026-10-24 — Task 3 done (Sonnet agent, reviewed): hand-written authoritative responder on tokio + hickory-proto 0.26.3; 5 integration tests, stable over 3 runs. Review findings carried into Task 8: DS at zone cut must be answered by the parent; wildcard support missing.

- 2026-10-24 — Task 1 done (Haiku agent, reviewed): workspace, toolchain pin, lints, CI workflow. fmt/clippy/test green locally.

- 2026-10-24 — Specs approved and pushed. Plan approved. Toolchain installed (Rust 1.99.1, dig, kdig).
