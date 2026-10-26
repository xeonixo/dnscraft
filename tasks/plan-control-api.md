# Implementation Plan: `control-api` module

> Spec: [SPEC-control-api.md](../../SPEC-control-api.md) · Project spec: [SPEC.md](../../SPEC.md) ·
> Tasks: [todo-control-api.md](todo-control-api.md) · Resume log: [progress.md](../progress.md) ·
> Capability map: [CAPABILITY-MAP.md](../../CAPABILITY-MAP.md)

## Overview

Build `crates/dnscraft-api` (module id `control-api`). The API is the primary
configuration boundary for the web UI and the later `mcp` module. It owns SQLite
persistence, query-log storage, statistics, audit log, authentication, and the
HTTP surface. It does **not** implement DNS behaviour; it calls the existing
module APIs (`policy`, `clients`, `listeners`, `tls`, `resolver`) and persists
their configuration as typed values.

This plan copies the shape of the finished `policy` plan: small task ids,
checkpoints every 2–4 tasks, acceptance criteria as checkboxes, one commit per
task, and a final owner-approval checkpoint.

## Architecture Decisions

These decisions follow the approved `SPEC-control-api.md` "Decisions" table. We
do **not** re-decide those questions; we only turn them into build and test
boundaries.

1. **Single crate, module id `control-api`.** Crate name `dnscraft-api`
   (`crates/dnscraft-api`). Internal-only API listener; never served on public
   DNS listeners (`listeners` routes only `/dns-query/...` there).

2. **Web framework.** `axum` on the workspace `hyper`/`tokio` stack. Alternative
   (hand-rolled `hyper`) is more code and more risk for routing, extractors, and
   middleware. `tower-http` is promoted to a direct dependency with the `trace`
   feature only; if it causes friction it is dropped in favour of `tracing`
   spans.

3. **Storage.** SQLite via `rusqlite` with `bundled` SQLite (no system lib, no
   native crypto). The API is async, so every SQLite operation runs through
   `tokio::task::spawn_blocking`. v1 uses a single writer connection behind a
   `std::sync::Mutex` plus read-only helpers; no connection pool yet (the
   control-plane load is small). Migrations run at first open and record
   `PRAGMA user_version`.

4. **Query-log back-pressure.** `control-api` consumes the bounded
   `QueryEventSink` from `listeners`. A dedicated channel plus a persistent
   writer task batch-inserts into SQLite. When the channel is full, events are
   dropped and `control_api.query_log.dropped` is incremented; DNS answering is
   never blocked.

5. **Config atomic apply/rollback.** Persist the full validated configuration
   as a new version in one SQLite transaction. Apply modules leaf-first:
   `filtering` → `clients` → `policy` → `listeners` → `tls`. If any module
   fails, re-apply the previous snapshot, mark the version failed, and return
   the module's stable error code. Expose `config_version` for optimistic
   concurrency (`If-Match`).

6. **TLS bootstrap.** Direct TLS is the default (`control_api.tls = true`). The
   HTTP server resolves a certificate by asking the shared `tls::CertResolver`
   (ACME) first; while `CertResolver::has_cert()` is false it serves a persisted
   self-signed `rcgen` certificate. The switch is automatic, no restart. The
   self-signed cert is ECDSA P-256, validity 1 year, SANs = configured node
   hostname + `localhost`, private key mode 0600, regenerated when expired or
   the hostname changes. `tls_mode` (`acme` | `self_signed`) and SHA-256
   fingerprint are exposed in status. Reverse-proxy mode (`tls = false` +
   `trusted_proxies`) is optional.

7. **Auth.** Session ids and bearer tokens are random (`ring::rand`) and stored
   only as `ring::digest::SHA256` hashes. Break-glass passwords use `argon2`
   (Argon2id). CSRF uses the synchronizer-token pattern for cookie sessions;
   bearer-token requests do not require CSRF. OIDC uses Authorization Code +
   PKCE S256 + nonce.

8. **OpenID Connect integration.** `openidconnect` is the preferred crate. It
   is **ring-only** (no `aws-lc-rs`/`openssl-sys`), but it pulls the RustCrypto
   `rsa`/`crypto-bigint`/`p256`/`p384` stack, which trips **two** `cargo deny`
   advisories (see Dependencies). The plan therefore records both paths and
   leaves the final choice to the owner:
   - **Primary:** `openidconnect` with `default-features = false` (no bundled
     `reqwest`/`curl` client) plus a small custom async HTTP client over the
     workspace `reqwest` 0.13 (`rustls-no-provider` + ring). Two `[advisories]
     ignore` entries with written justifications (both advisories concern
     private-key timing; control-api uses the crates for public-key signature
     *verification* only).
   - **Fallback:** hand-rolled discovery/JWKS/JWT validation on
     `ring::signature` (RS256/ES256/EdDSA) + workspace `reqwest`, recorded in an
     ADR. No RustCrypto stack, zero advisory ignores.

   Either way it is tested in A9 against an in-process mock provider; no real
   Authentik/Cloudflare is ever contacted in CI.

9. **Secrets redaction.** Config exports and audit before/after snapshots mask
   secret material (tokens, keys, OIDC client secret, UniFi API key). Private
   keys are never returned by any endpoint and never written to audit JSON
   except as `"redacted"` or a digest.

## Crate layout

```
crates/dnscraft-api/
├── Cargo.toml
├── src/
│   ├── lib.rs                 // exports, module docs
│   ├── config.rs              // ControlApiConfig + validation (internal-only bind)
│   ├── error.rs               // ControlApiError with stable code() + uniqueness test
│   ├── server.rs              // axum router, listener, startup/shutdown
│   ├── tls.rs                 // ACME/self-signed resolver + persistence
│   ├── storage/
│   │   ├── mod.rs
│   │   ├── db.rs              // spawn_blocking wrapper, single connection
│   │   ├── migrations.rs      // schema DDL + user_version
│   │   ├── config_store.rs    // kv + config_versions
│   │   └── audit.rs
│   ├── api/
│   │   ├── mod.rs
│   │   ├── router.rs
│   │   ├── response.rs        // {data} / {error} envelopes
│   │   ├── pagination.rs
│   │   ├── rate_limit.rs
│   │   ├── auth/
│   │   │   ├── mod.rs
│   │   │   ├── sessions.rs
│   │   │   ├── csrf.rs
│   │   │   ├── tokens.rs
│   │   │   ├── roles.rs
│   │   │   ├── local.rs
│   │   │   └── oidc.rs
│   │   ├── config_routes.rs
│   │   ├── clients_routes.rs
│   │   ├── filter_routes.rs
│   │   ├── listener_routes.rs
│   │   ├── tls_routes.rs
│   │   ├── query_log_routes.rs
│   │   └── stats_routes.rs
│   ├── query_log.rs           // QueryEventSink consumer + retention/filtering
│   ├── stats.rs               // rollups and aggregations
│   ├── modules.rs             // narrow apply/status traits + fakes
│   └── audit.rs               // audit record creation/redaction
└── tests/
    ├── api_core.rs
    ├── config_apply.rs
    ├── auth_local.rs
    ├── auth_oidc.rs
    ├── config_http.rs
    ├── query_log.rs
    ├── stats_export.rs
    └── security.rs
```

All code/comments/docs are English. `unsafe` is forbidden workspace-wide
(workspace lint `unsafe_code = "forbid"`).

## Phases and task list

Suggested phase order from the brief, adopted with one adjustment: the server
core is split so TLS bootstrap, rate limiting, and the auth primitives are each
their own task (security-critical concerns get their own items). Checkpoints
every 2–4 tasks; the last is Claude review + owner approval.

- **Phase 0 — Skeleton:** A0
- **Phase 1 — Storage:** A1, A2
- **Phase 2 — Server core:** A3, A4, A5
- **Phase 3 — Auth:** A6, A7, A8, A9
- **Phase 4 — Config endpoints:** A10, A11
- **Phase 5 — Query log + statistics:** A12, A13
- **Phase 6 — Hardening:** A14

Checkpoints:

- **Checkpoint A** after A2 (storage + snapshot/version + audit redaction)
- **Checkpoint B** after A5 (server core + TLS bootstrap + rate limit)
- **Checkpoint C** after A9 (full auth incl. mock OIDC)
- **Checkpoint D** after A11 (config endpoints)
- **Checkpoint E** after A13 (query log + stats + export)
- **Checkpoint F** after A14 (hardening; **Claude review + owner approval**)

### Task dependencies

```
A0 → A1 → A2 → A3 ─┬─ A4 (TLS bootstrap)
                   ├─ A5 (rate limiting)
                   └─ A6 (sessions/CSRF) → A7 (tokens/roles) → A8 (local login)
                        → A9 (OIDC) → A10 (apply/rollback) → A11 (CRUD)
                        → A12 (query log) → A13 (stats/export) → A14 (hardening)
```

`A4`, `A5` and `A6` all depend only on `A3` and may be built in any order.
`A10`/`A11` need the auth layer (all mutating endpoints are role-checked).
`A12` needs the listener sink and config from `A3`/`A11`.

## Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| `openidconnect` pulls RustCrypto `rsa`/`crypto-bigint` with 2 advisories (`RUSTSEC-2026-0387`, `RUSTSEC-2023-0071`) → `cargo deny check` fails | Med | Both advisories concern private-key timing; control-api uses the crates for public-key signature *verification* only. Primary path: two `[advisories] ignore` entries with written justifications (owner approves the `deny.toml` change). Fallback: hand-rolled validation on `ring::signature`, recorded in an ADR. |
| SQLite blocking in the async runtime | High | Every DB call via `tokio::task::spawn_blocking`; no DB call on the reactor. Single writer connection for v1. |
| `QueryEventSink` back-pressure stalls DNS answering | High | The listener sink is already non-blocking (`try_send`); control-api consumes it via a bounded `mpsc` + batching writer. On full, drop and count. |
| `listeners` crate still evolving | Low/Med | Control-api depends only on the public API (`ListenerSet`, `QueryEventSink`, `ListenersConfig`). Adapters in `src/modules.rs` localize any change. A14 re-checks against the current listener API. |
| `rcgen` self-signed switch race / renewal | Med | A4 tests `tls_mode` transitions and automatic fallback with a fake resolver that changes after start. The self-signed cert is persisted atomically; private-key mode is checked in a test. |
| Audit before/after leaks secrets | High | Redaction is applied before persistence and again before export; A2/A14 assert no known secret appears. |
| Rate-limit bypass via forwarded headers | Med | Reverse-proxy mode honours `X-Forwarded-For`/`X-Forwarded-Proto` only from `trusted_proxies`; direct sockets use the peer IP and ignore forwarded headers. |
| MSRV drift (`rusqlite` 0.41 / `uuid` 1.29 declare rust-version 1.89 > workspace 1.88) | Low | Pin `rusqlite` 0.40.0 (no declared MSRV) and `uuid` 1.26.0 (1.85), or the owner bumps the declared MSRV to 1.89. Toolchain is `stable` (currently 1.99). |

## Dependencies for owner approval

Workspace dependencies are reused with the versions/features pinned in the root
`Cargo.toml` (`tokio`, `serde`, `serde_json`, `time`, `base64`, `ring`, `http`,
`hyper`, `hyper-util`, `http-body-util`, `bytes`, `reqwest` 0.13
`rustls-no-provider`, `rustls`, `tokio-rustls`, `rcgen`, `tracing`, `thiserror`).
The root already provides the runtime, crypto and TLS stack.

Versions below were checked with `cargo search` / `cargo info` on 2026-10-26.
The ring-only dry check ran in a scratch crate outside the repo (see
"Dry-check results").

| Crate | Version | Features | Why | Alternative | Licence | Dry-check result |
|---|---|---|---|---|---|---|
| `axum` | 0.8.9 | `default-features = false`, `json`, `query`, `http1`, `tokio`, `tracing` | Router/extractors on the existing hyper/tokio stack | hand-rolled `hyper` (more code) | MIT | ring-only ✓, deny ✓ |
| `tower-http` | 0.6.11 | `default-features = false`, `trace` | Tracing middleware | omit, use `tracing` spans | MIT | ring-only ✓, deny ✓ (already in `Cargo.lock` via `reqwest`) |
| `rusqlite` | 0.40.0 | `bundled` | SQLite persistence, fixed by SPEC.md; `bundled` compiles C SQLite, no system lib | pure-Rust SQLite alternative (less mature) | MIT | ring-only ✓, deny ✓ (no crypto) |
| `argon2` | 0.6.0 | default (`alloc`,`getrandom`,`password-hash`) | Argon2id for break-glass login (RFC 9106) | `ring::pbkdf2` (PBKDF2-HMAC-SHA256) | MIT OR Apache-2.0 | ring-only ✓, deny ✓ (pure Rust) |
| `uuid` | 1.26.0 | `v4` | Entity IDs (RFC 4122) | `ring::rand` + hex (no new dep) | MIT OR Apache-2.0 | ring-only ✓, deny ✓ |
| `openidconnect` | 4.0.1 | `default-features = false` + custom async HTTP client over workspace `reqwest` | Discovery, JWKS and ID-token validation | hand-rolled on `ring::signature` + `reqwest` | MIT | **ring-only ✓** (no aws-lc/openssl), but **deny advisories ✗** (2) — see below |

Notes:

- **argon2 0.6.0** dropped the `std` feature of 0.5.x; the default features are
  `alloc` + `getrandom` + `password-hash`, which is what `Argon2::default()`
  (Argon2id) needs. Single-threaded (no `parallel`/`rayon`) is fine for
  break-glass login.
- **tower-http** 0.6.11 is already in `Cargo.lock` transitively via `reqwest`
  0.13; promoting it to a direct dependency reuses that version (no second
  tower-http major). 0.7.1 is the latest but would add a second major.
- **openidconnect** — see the dedicated section below.

### Dry-check results (scratch crate, never in this repo)

Composition tested: `axum` + `tower-http` + `rusqlite` + `argon2` + `uuid` +
`reqwest` (workspace flags) + `rustls` (workspace flags) — **without**
`openidconnect`:

```
$ cargo tree -i aws-lc-rs      → error: package ID specification `aws-lc-rs` did not match any packages
$ cargo tree -i aws-lc-sys     → error: ... did not match any packages
$ cargo tree -i openssl-sys    → error: ... did not match any packages
$ cargo tree -i openssl        → error: ... did not match any packages
$ cargo tree -i native-tls     → error: ... did not match any packages
$ cargo deny check             → advisories ok, bans ok, licenses ok, sources ok
```

With **openidconnect 4.0.1** added (both `default-features = false` and default
features were tested):

```
$ cargo tree -i aws-lc-rs / aws-lc-sys / openssl-sys / openssl / native-tls
  → all "did not match any packages"          (ring-only is satisfied)
$ cargo deny check
  → advisories FAILED  (bans ok, licenses ok, sources ok)
```

The two advisories are both in the RustCrypto stack that `openidconnect` pulls
for JWKS/JWT signature verification (`rsa`, `crypto-bigint`, `p256`, `p384`):

1. **RUSTSEC-2026-0387** — `crypto-bigint 0.5.5`: timing variability in
   constant-time operations (fixed in 0.7.6, but that upgrade is in the
   upstream's hands, not ours).
2. **RUSTSEC-2023-0071** — `rsa 0.9.10` ("Marvin Attack"): no patch available
   (`patched = []`).

Both advisories describe timing side-channels on **private-key** operations
(signing/decryption). Control-api only ever *verifies* ID-token signatures with
public keys, so neither attack applies to our usage. To keep the workspace
`cargo deny check` green, one of these is required:

- **(a) Approve `openidconnect` + two `[advisories] ignore` entries** with the
  written justification above. This is the lower bug-risk choice (battle-tested
  against alg-confusion / key-confusion / JWKS rotation). The `deny.toml` change
  is a "ask first" policy change and needs owner approval.
- **(b) Hand-roll OIDC validation on `ring::signature`** (RS256/ES256/EdDSA
  verify, JWKS parsing, JWT claim validation, discovery via workspace `reqwest`).
  No RustCrypto stack, `cargo deny check` fully green with zero ignores, smaller
  binary — but ~400–600 lines of subtle protocol code and a new ADR.

The plan's recommendation is **(a)**, with **(b)** as the documented fallback if
the owner prefers a strictly single-crypto-stack / zero-ignore posture. This is
an explicit open question below.

### Not needed

`sha2` (use `ring::digest` for token/session hashing), a separate `reqwest`
entry (workspace 0.13 with the ring provider, as in `dnscraft-tls`), `base64`
and `time` (workspace).

## Success-criteria traceability

| Spec criterion | Task(s) |
|---|---|
| 1. Documented `/api/v1` endpoints + envelopes/status codes | A3, A10, A11, A12, A13 |
| 2. Config PUT atomic applies/rolls back all modules | A2, A10 |
| 3. Query-log endpoints enriched/filter/order/paginate with 10 000 rows | A12 |
| 4. “Why blocked?” full DecisionRecord | A12 |
| 5. Mock OIDC flow works; invalid/expired claims rejected | A9 |
| 6. Break-glass login locks after failures and writes audit events | A8 |
| 7. Viewer/admin role separation; MCP scopes map | A7, A14 |
| 8. Audit log with before/after digests + login failures | A2, A8 |
| 9. Internal-only binding enforcement | A4, A14 |
| 10. No real external Auth/OIDC/Cloudflare; DoD green | A9, A14 |
| 11. TLS bootstrap self-signed → ACME switch without restart | A4 |
| 12. NDJSON export primary streaming format + CSV convenience | A13 |
| 13. Audit before/after snapshots mask secrets | A2, A10, A14 |

## Open questions for the owner

1. **`openidconnect` advisory decision (the only blocking one):** approve
   `openidconnect` with two `[advisories] ignore` entries (RUSTSEC-2026-0387,
   RUSTSEC-2023-0071, verify-only justification), or should control-api hand-roll
   OIDC validation on `ring` instead (zero ignores, but more code + an ADR)?
   Recommendation: approve `openidconnect` + ignores.
2. **MSRV:** `rusqlite` 0.41.0 and `uuid` 1.29.0 declare rust-version 1.89,
   above the workspace's 1.88. May we bump the declared MSRV to 1.89 (toolchain
   is already `stable` 1.99), or should we pin `rusqlite` 0.40.0 + `uuid` 1.26.0?
   Recommendation: pin to 0.40.0/1.26.0 to honour the declared MSRV.
3. `tower-http` is already in `Cargo.lock` transitively via `reqwest`; may we
   promote it to a direct dependency with `trace` only (version stays 0.6.11),
   or avoid it and use plain `tracing` spans?
4. Confirm that `control_api.tls.self_signed` remains a warning-level status
   (not a startup-blocking error) for first-run UX.
