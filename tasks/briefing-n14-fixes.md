# Briefing: N14 fix round (`crates/dnscraft`) and Task G wrap-up corrections

> For the listeners agent. Paste the block below as the first message. Context: Claude review of
> `9be1e58` (S1), `cef4489` (S2), `298a14d` (N14), `1a22189` (R3), `c2de42c` (wrap-up). S1, S2 and R3 are
> approved. N14 needs the fixes below before Checkpoint D (independent security review + owner approval).

```text
Task: N14 fix round. Fix C1, C2, R1-R5 and S1-S4 in crates/dnscraft. STOP for Claude re-review when done.
Do not start Checkpoint D. Do not touch crates/dnscraft-api (another agent), SPEC files, or other agents'
uncommitted changes. Shared manifests (root Cargo.toml, Cargo.lock) and tasks/progress.md: check `git diff`
and stage only your own hunks (git add -p), explicit paths only. No CARGO_TARGET_DIR in /tmp, no cargo clean.
Regression test FIRST for every fix (it must fail before the fix; say so in the commit message). One commit
per finding: "dnscraft: fix <id> <title>", English, Co-Authored-By line as in earlier commits. Do not push.
Do not tick acceptance boxes or report "done" until `git log` shows one commit per finding and every
criterion of the task text is met. A box with "not run" or "tested differently than specified" is NOT met:
leave it unticked and say why.

Evidence (all reproduced by Claude on HEAD c2de42c):
- engine.rs builds the PolicyEngine with `ManualClock::new(SystemTime::now())` from dnscraft_filtering: a
  clock frozen at process start is used in production.
- config.rs: `#[derive(Debug)] pub struct TlsSecrets { chain_pem, key_pem }` prints the private key under {:?}.
- A config with misspelled keys (`exposur = "public"`, `tpyo_key = 1`) is accepted silently.
- A config whose only listener cannot bind (`address = "192.0.2.1:5300"`) prints "dnscraft: listening", keeps
  running and exits 0 on SIGTERM: ListenerSet::start records bind failures in status only.
- Errors are free-form strings; no stable error code is printed. Exit code is always 2.
- The binary has no log on/off switch (every query with client IP + qname goes to stdout), no data_dir, no
  forward zones, no filter lists, no configurable default view/profile; the sample config is in
  crates/dnscraft/ and does not bind, so "starts from the sample config and answers dig" was never shown.
- The wrap-up ticked N14's acceptance boxes although: the dig/kdig box is "not run", and the integration test
  does not send a UDP query (event formatting is only unit-tested). Claude did show manually that a UDP query
  produces one valid JSON line with the hostile qname correctly escaped; that must become an automated test.
- Log/commit text says "toml 1.1.8 ... owner-approved". No such owner approval was given in the review
  conversation. The dependency decision is the owner's; see D1.

C1 (critical) No test helpers in production.
  Replace ManualClock by the real system clock in engine.rs (use the crate's/`dnscraft_filtering`
  `SystemClock`; check what dnscraft_policy and dnscraft_listeners expect and wire the right one per
  ADR 0005). Regression test: build the engine and prove time advances (policy pause/schedule or filtering
  temporary-allow expiry observed through the real clock, with a short real wait of at most ~50 ms, or an
  injectable clock parameter on the library `build()` so tests can pass a ManualClock while production
  passes SystemClock; prefer the injectable parameter). Add a grep-style test or clippy `disallowed_types`
  entry that fails the build if ManualClock appears in non-test code of this crate.

C2 (critical) Secrets never in Debug/Serialize.
  Wrap the key material (and the chain if you like) in a redacting type (Debug prints "[REDACTED]",
  zeroize on drop; the workspace has `zeroize`). Test: format!("{:?}") of the config/secrets never
  contains the PEM text. Also make sure no error message or log line ever includes env values.

R1 deny_unknown_fields on Config and ListenerToml (and every nested struct). Test: misspelled key -> exit 2
   with the unknown-field message and the stable code from R2.
R2 Stable error codes: Error variants carry `code()` ("dnscraft.config.parse", "dnscraft.config.unknown_field"
   if distinguishable, "dnscraft.config.invalid_listener", "dnscraft.config.tls_env_incomplete",
   "dnscraft.startup.bind", "dnscraft.startup.resolver", ...). Print `dnscraft: <code>: <message>` to
   stderr; uniqueness/format test as in other crates; exit code stays 2 for all startup/config errors.
R3 Fail fast on bind failure: after ListenerSet::start, inspect status(); if ANY configured listener has a
   bind error, shut down and exit 2 with code dnscraft.startup.bind naming the listener id and address
   (no secrets). Add a config switch `allow_partial_bind = false` (default) if you want to keep the
   listener-set behaviour available. Print "listening" only after all binds succeeded and include the bound
   addresses on stderr. Test: unbindable address -> exit 2; port 0 listeners -> bound addresses printed.
R4 Scope and acceptance:
   a) Do not silently shrink the task. Either implement what the N14 text in tasks/todo-listeners.md lists
      (data_dir, resolver forward zones/root hints, filter lists, one default view/profile, optional tls
      module) OR keep the minimal scope but rewrite the N14 task text and acceptance criteria to the actual
      minimal scope, listing every omitted item as an explicit follow-up task (N14b...), and mark N14 as
      "minimal bootstrap" in progress.md. The owner decides which (D2); until then do the second option.
   b) Add `[log] queries = true|false` (default true, as specified) and, if trivial, `ip_truncate`.
   c) Move the sample to deploy/dnscraft.example.toml. It must contain a loopback high-port UDP+TCP
      listener that actually runs (127.0.0.1:5300) with the public/documentation-address listeners commented
      out as examples.
   d) Automated end-to-end test (replace the "unit-tested only" shortcut): spawn the binary on 127.0.0.1:0
      (read the bound port from stderr), send one UDP query for a name with hostile characters
      (a label with `"`, `\`, a control byte, an embedded newline) under `localhost.`, assert one answer, one
      valid JSON stdout line, qname escaped (no raw control byte), then SIGTERM -> exit 0 within the grace
      period. No internet needed (localhost zone).
   e) Untick the N14 boxes in todo-listeners.md that are not met until they are.
R5 Dependencies: do not add or keep unapproved crates on assumption. Quote the owner message if one exists;
   otherwise mark `toml` as "pending owner approval" in the log (D1), leave the code as is, and state the
   alternative (a hand-rolled minimal parser is NOT recommended; serde + toml is the sensible choice).
   Correct the log text that claims owner approval.

S1 (should) The event writer does blocking stdout writes inside an async task: move it to a dedicated thread
   (or spawn_blocking loop) with a bounded channel; count dropped events (`events_dropped` from the sink) and
   print the number once at shutdown.
S2 (should) Add `DNSCRAFT_TLS_CERT_FILE` / `DNSCRAFT_TLS_KEY_FILE` (paths) next to the PEM-in-env variables;
   exactly one source per secret, otherwise stable error; key file permissions checked (warn if group/other
   readable). Document in the README.
S3 (should) Tests: half-configured TLS env -> exit 2 + code; public plaintext listener -> exit 2 (listener
   validation) + code; stderr contains the stable code in each exit-2 test.
S4 (should) Initialise a minimal `tracing` subscriber (stderr, level from `RUST_LOG`, default warn) so listener
   warnings are visible; no secrets in any log line (test with a capturing subscriber if cheap).

Owner decisions pending (do not decide; implement the stated default, report):
 D1 `toml` dependency: approve (recommended) or reject.
 D2 N14 scope: full original text vs minimal bootstrap + follow-up tasks (default until decided: minimal).

Definition of done per commit: cargo fmt --all --check; cargo clippy -p dnscraft -p dnscraft-listeners
--all-targets --locked -- -D warnings (workspace if it compiles); cargo test -p dnscraft -p
dnscraft-listeners; cargo deny check; cargo tree -i aws-lc-rs / aws-lc-sys / openssl-sys / native-tls empty.
Final report: `git log --oneline` of your commits, gates with actual numbers, per finding "met / not met",
open questions. Then STOP.
```
