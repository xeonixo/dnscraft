# Progress log

Resume point for interrupted sessions. Newest entry first.
Active plans: [plan-listeners.md](plan-listeners.md) / [todo-listeners.md](todo-listeners.md).
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
| `listeners` | spec + plan **approved** 2026-10-25; next: L0 + N0 spike | [plan](plan-listeners.md) · [tasks](todo-listeners.md) | [SPEC-listeners.md](../SPEC-listeners.md) |
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

- 2026-10-25 — **Owner approved SPEC-listeners.md, the plan and the dependency table** with all six recommendations: deps as listed; HTTP/3 in v1 (late task N12); wildcard binds supported, concrete addresses preferred; public Do53 dropped silently; minimal `dnscraft` binary (N14) in scope; DDR opportunistic only. Next: L0 + N0 (Cursor).

- 2026-10-25 — **listeners: spec draft + plan + tasks** (Claude). SPEC-listeners.md (draft): listener model (id, protocol, address, exposure), admission (source class, public Do53 dropped, Client ID via SNI / DoH path, token buckets, bounded ban table), shared message core, per-transport rules (RFC 1035/6891/7766/7828/7858/8484/9113/9114/9250/8467/9462 to verify and cite at implement time), TLS via `tls::CertResolver`, DDR, query events, runtime/reload, 8 success criteria, 6 open owner questions. Plan: one Cursor agent, 16 tasks (L0 policy accessor, N0 spike for pktinfo/quinn ring-only/h3/hyper, N1–N13, optional N14 minimal binary), checkpoints A–D. Dependencies for approval: quinn 0.11 (ring-only features), quinn-udp 0.6, hyper 1 + hyper-util 0.1, h3 0.0.8 + h3-quinn 0.0.10, base64 (if not in the tree), toml (N14). **STOP: owner approval.**

- 2026-10-25 — **Tasks cleaned up** (Claude): tls plan/tasks archived (archive/tls-plan.md, tls-todo.md);
  the finished briefs of the clients/tls/policy round moved to archive/cursor-clients-tls-policy.md;
  cursor-next.md now holds only the reusable rules and templates; the full log up to now moved to
  archive/progress-2026-10.md. References in SPEC-tls.md, the filtering README and safesearch_table.rs
  point to the archived log.
