# Common brief for every DNScraft agent (read fully first)

Repo: /Users/barner/projects/dnscraft (Rust workspace). Public repo: never commit personal network details;
use documentation ranges (192.0.2.0/24, 2001:db8::/32) and example.com/.net.

## Read first
`tasks/cursor-next.md` (rules + definition of done), `SPEC.md`, your crate's `SPEC-*.md`,
`tasks/todo-spec-gaps.md` (your section — NOTE it is partly stale: many items are already fixed in code; verify each
item against the actual code and git log before working on it, tick what is already done),
`tasks/progress.md` (top of the log), and the other `tasks/todo-*.md` / `tasks/plan-*.md` that mention your crate.

## Your job
1. Audit: for each still-open item in your scope, check the code. Also diff your SPEC against the crate for
   features that were added to the SPEC later and never planned/built. Add those as new items in
   `tasks/todo-spec-gaps.md` under your section if found.
2. Fix everything that is `[code]` severity-ordered (🔴 → 🟠 → 🟡) and implement newly found missing features.
   `[spec]` items: update the SPEC to match the deliberate code decision (small, factual edits).
   `[owner]` items that need a real product decision: do NOT guess — leave open and list them in your report
   with the question and your recommendation. Exception: if an item is `[owner]` but SPEC/ADR/plan already decides it, just do it.
3. Every fix needs a regression test that fails without the fix. Tests never touch the internet.
4. Tick items in the todo files you touched; add a dated entry at the top of the Log in `tasks/progress.md`
   (keep it short, ≤15 lines).

## Hard rules
- English code/comments/docs. No `unwrap()/expect()` outside tests, no `unsafe`, every public item documented,
  every error variant has a stable `code()`; code-uniqueness tests must stay green.
- No new dependencies, no Cargo.lock changes unless your brief explicitly allows a workspace-internal path dep
  or a documented lock change (e.g. fuzz/). Crypto: ring only.
- Other agents work in parallel in the SAME working tree on other crates. Touch only files you own (listed in your
  assignment). Public API changes in your crate must be additive. Never run `git add -A`, `git commit -a`,
  `git stash`, `git checkout`, `git reset` or anything that touches files you don't own.
- Commit with explicit paths: `git add <paths> && git commit -- <paths>` (so staged files of other agents are not
  swept in). Message `type(scope): summary (IDs)`, ending with
  `Co-Authored-By: Claude <noreply@anthropic.com>`. Do NOT push.
- Run only crate-scoped gates with `CARGO_TARGET_DIR=target`:
  `cargo fmt -p <crate> -- --check`, `cargo clippy -p <crate> --all-targets --locked -- -D warnings`,
  `cargo test -p <crate> --locked`. If another crate is transiently broken by a parallel agent, wait and retry;
  don't fix it yourself.
- Leave `web/` alone (WebUI out of scope). Leave uncommitted `web/` and `.pnpm-store/` alone.
- Follow the ponytail ethos: smallest working change, reuse existing helpers (esp. `dnscraft-common`), no speculative abstractions.

## Final report (your last message, ≤30 lines)
Done items (IDs), items left open + why (with owner question/recommendation), new features found+built, gate results
(exact commands + pass/fail counts), any cross-crate API change, commit SHAs.
