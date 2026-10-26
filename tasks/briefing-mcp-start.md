# Briefing: `mcp` module (for deepseek-v4-pro), stages 1-5

> Paste this file as the first message of a session. Authority: [SPEC-mcp.md](../SPEC-mcp.md). Plan:
> [plan-mcp.md](plan-mcp.md). Tasks: [todo-mcp.md](todo-mcp.md). Phase 3 (M20-M27) is briefed separately.

```text
ROLE AND SCOPE
You build the `mcp` module of DNScraft (Rust workspace) following an approved-by-owner plan. You work in
stages. After each stage you STOP and report; the owner and Claude review; the next stage is started with a
separate message. Never continue past a STOP on your own.

READ FIRST (in this order)
1. SPEC-mcp.md (authority; when code and spec disagree, stop and report, never change either silently)
2. tasks/plan-mcp.md (architecture decisions, risks, and the block "Agent rules for every MCP task":
   follow it literally, it is part of this briefing)
3. tasks/todo-mcp.md (your tasks, acceptance criteria, verification commands, files)
4. tasks/progress.md ("Current state" and the top of the "Log"), docs/adr/0002 and docs/adr/0005

OWNER DECISIONS ALREADY MADE
- Reopening the finished modules filtering/resolver/policy for the additive tasks M1-M5 is approved
  (additive changes only, regression tests, no behaviour change for existing callers).
- Phase 0 and Phase 1/2 may run in parallel with the control-api agent (other files). Phase 3 (M20-M25) is
  NOT part of this briefing.
- Open for later checkpoints (do not decide): rmcp approval (Checkpoint D0), the three defaults in the plan's
  Open question 4, client compatibility check.
- NEW EXTERNAL DEPENDENCIES: only those approved at Checkpoint D0 (rmcp with the listed features). Any other
  crate (for example a TOML parser, a test helper): STOP and ask first with crate, version, features,
  licence, ring-only cargo tree and cargo deny result. "Owner-approved" must be a real message from the
  owner that you can quote; never write it into a log or commit on assumption.

WORKING ENVIRONMENT (learned the hard way)
- The control-api agent and possibly a listeners agent have UNCOMMITTED changes in the working tree
  (crates/dnscraft-api/**, crates/dnscraft-listeners/**, fuzz/, root Cargo.toml/Cargo.lock,
  tasks/progress.md). Never touch their files. Before every commit run `git status` and
  `git diff <shared files>`; stage only your own hunks with `git add -p`; explicit paths only; never
  `git add -A`, `git commit -a`, `git stash`, `git checkout -- <others' files>`.
- Do NOT set CARGO_TARGET_DIR to /tmp (tmpfs with a small quota). No `cargo clean`. If cargo blocks on the
  build lock, another agent is building: wait.
- Run the workspace test command only if the workspace compiles; if another agent's WIP breaks it, run the
  affected crates (`-p`) and say so in the commit message.
- Public repository: documentation ranges and example.com/.net only.
- Production code never uses test helpers: no ManualClock outside tests (use the crate's SystemClock),
  no test-only constructors, no unwrap()/expect() outside tests.
- A secret-carrying type never derives Debug/Serialize with the secret inside; use a redacting wrapper.
- You do not push. You do not tick acceptance boxes or Checkpoints without a commit and evidence.
- You do not report "done" until `git log` shows the commit(s) required by the stage. Quote
  `git log --oneline` in your report.

PER-TASK WORKFLOW
1. Read the task (Description, Acceptance criteria, Verification, Dependencies, Files). If a dependency is
   not done, STOP and say which.
2. Tests first where practical (regression test must fail before a fix; say so in the commit message).
3. Implement only inside the task's Files (touching more: explain in the commit message).
4. Run the definition of done: cargo fmt --all --check; cargo clippy --workspace --all-targets --locked
   -- -D warnings; cargo test (workspace or affected crates); cargo deny check; cargo tree -i aws-lc-rs,
   aws-lc-sys, openssl-sys, native-tls all empty.
5. Tick the task's acceptance boxes ONLY for criteria you proved; add a dated entry at the top of the Log in
   tasks/progress.md (re-read the file right before editing); commit: "<crate>: M<n> <title>" in English,
   ending with the Co-Authored-By line used in earlier commits (see `git log`).
6. Report problems, deviations from the task text, and spec/plan contradictions honestly. A task whose
   acceptance criteria are not all met is NOT done: say which are missing instead of ticking it.

STAGES

STAGE 1 (start here): M0 only. Documentation, no Rust code in the repo. Work in a throw-away crate in the
scratchpad/temp area outside the repo (metadata and source reading only, no builds). Produce the dependency
pack and the rmcp findings exactly as the task requires, write docs/adr/0006-mcp-rmcp-stateless.md
(Status: Proposed) and fill the dependency table in tasks/plan-mcp.md. One commit. Then STOP at
CHECKPOINT D0. Report: the new-crates list, the cargo deny result, the answers to the six open rmcp
questions (with file:line), and your keep-rmcp-or-fallback recommendation.

STAGE 2 (after the owner's message "D0 approved"): M1, M2, M3, M4, M5 in this order (M1-M3 filtering,
M4 resolver, M5 policy). One commit per task. Run the affected crates' full test suites after each task.
STOP at CHECKPOINT P. Report per task: tests added, and the mutation probe you did (revert the key change,
show the new test fails, restore).

STAGE 3 (after "P approved"): M6, M7, M8, M9, M10. M8 is the risky vertical slice through rmcp: if the
findings contradict the spec, STOP and report. STOP at CHECKPOINT T (transport + auth security review by
Claude). Report the rmcp facts you recorded in the ADR.

STAGE 4 (after "T approved"): M11, M12, M13, M14. STOP at CHECKPOINT R.

STAGE 5 (after "R approved"): M15, M16, M17, M18, M19. STOP at CHECKPOINT W. Include the mutation-probe list
required by M19.

(Phase 3, M20-M27, is briefed separately after control-api Checkpoint F.)

REPORT FORMAT AT EVERY STOP
- Stage and tasks done, with `git log --oneline` of your commits
- Gates: fmt, clippy, tests (counts), deny, crypto trees — actual results
- Per task: acceptance criteria met (list), anything skipped or deviating, with the reason
- Spec/plan contradictions or gaps you found
- Open questions for the owner
- The exact next stage you are waiting for

Start with STAGE 1 now.
```

## Checkpoints

| Stop | Reviewer | Decision |
|---|---|---|
| **D0** after M0 | owner | approve `rmcp` and the new transitive crates (or choose the fallback) |
| **P** after M5 | Claude | additive changes in filtering/resolver/policy |
| **T** after M10 | Claude | transport + auth security review; owner confirms the three defaults |
| **R** after M14 | Claude | all 8 read tools against the mock backend |
| **W** after M19 | Claude | write tools, injection and rule-safety probes |

Continue with one line per stage, for example: "D0 approved, continue with STAGE 2."
