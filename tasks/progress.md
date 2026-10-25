# Progress log

Resume point for interrupted sessions. Newest entry first.
Active plans: `tasks/plan-<module>.md` / `tasks/todo-<module>.md` (none open right now).
Briefs and reusable templates for Cursor agents: [cursor-next.md](cursor-next.md).

**Archive:** [archive/](archive/) holds the plans and tasks of every finished module, the old briefs, and the
full log of 2026-10-24 … 25 ([archive/progress-2026-10.md](archive/progress-2026-10.md)) — including the
success-criteria tables, measurements and review findings of resolver, filtering, clients, tls and policy.

**Workflow:** Cursor agents (or Haiku/Sonnet subagents) implement one task at a time; Claude reviews
(diff, `fmt`, `clippy`, tests, mutation probes, temporary probe tests); each task is ticked off in its
`todo-<module>.md`, logged here and committed.

## Current state

| Module | State | Plan / tasks | Evidence |
|---|---|---|---|
| `resolver` | COMPLETE (Checkpoint E, 2026-10-25) | [plan](archive/resolver-plan.md) · [tasks](archive/resolver-todo.md) | archived log |
| `filtering` | COMPLETE (Checkpoint D, 2026-10-25) | [plan](archive/filtering-plan.md) · [tasks](archive/filtering-todo.md) | archived log |
| `clients` | COMPLETE (Checkpoint C, 2026-10-25) | [plan](archive/clients-plan.md) · [tasks](archive/clients-todo.md) | archived log, coverage 86.2 % |
| `tls` | COMPLETE (Checkpoint C, 2026-10-25, LE staging accepted) | [plan](archive/tls-plan.md) · [tasks](archive/tls-todo.md) | archived log, coverage 80.3 % |
| `policy` | COMPLETE (Checkpoint C, 2026-10-25; P13 SafeSearch, P14 schedules) | [plan](archive/policy-plan.md) · [tasks](archive/policy-todo.md) | archived log, coverage 92.9 % |
| `listeners` | next — spec not written yet | – | – |
| `control-api`, `web-ui`, `mcp`, `cluster` | pending (see [CAPABILITY-MAP.md](../CAPABILITY-MAP.md)) | – | – |

- Toolchain: MSRV **1.88**, toolchain `stable`; all dependencies on their latest stable versions
  (2026-10-25); ring-only TLS enforced by `cargo deny` bans; `cargo deny check` runs in CI.
- Blockers: none.
- Open owner questions: schedule windows in local time (needs a time-zone dependency; today UTC week
  offsets, see SPEC-policy.md "Schedules").
- Optional follow-ups noted in reviews (not blocking): clients — record fetch errors only for
  non-superseded fetches; policy — `strip_rrsigs_covering` filters by type, not (owner, type);
  tls — `RETRY_AFTER_MAX_LEN` cap untested.

## Log

- 2026-10-25 — **Tasks cleaned up** (Claude): tls plan/tasks archived (archive/tls-plan.md, tls-todo.md);
  the finished briefs of the clients/tls/policy round moved to archive/cursor-clients-tls-policy.md;
  cursor-next.md now holds only the reusable rules and templates; the full log up to now moved to
  archive/progress-2026-10.md. References in SPEC-tls.md, the filtering README and safesearch_table.rs
  point to the archived log.
