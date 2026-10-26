# Implementation Plan: `control-api` module

> Spec: [SPEC-control-api.md](../../SPEC-control-api.md) · Project spec: [SPEC.md](../../SPEC.md) ·
> Tasks: [todo-control-api.md](todo-control-api.md) · Resume log: [progress.md](../progress.md) ·
> Capability map: [CAPABILITY-MAP.md](../../CAPABILITY-MAP.md)

## Overview

Build `crates/dnscraft-api` (module id `control-api`). The API is the primary
configuration boundary for the web UI and later `mcp`. It owns SQLite
persistence, query-log storage, statistics, audit log, authentication, and the
HTTP surface. It does **not** implement DNS behaviour; it calls the existing
module APIs (`policy`, `clients`, `listeners`, `tls`) and persists their config.

This plan copies the shape used by the finished `policy` plan:
small task ids, checkpoints every 2–4 tasks, acceptance criteria as checkboxes,
one task per commit, and a final owner-approval checkpoint.

## Architecture Decisions

These decisions follow the approved `SPEC-control-api.md` “Decisions” table. We
do **not** re-decide those questions; we only turn them into build and test
boundaries.

1. **Single crate, module id `control-api`.** Crate name `dnscraft-api`
   (`crates/dnscraft-api`). Internal-only API listener; never served on public
   DNS listeners.

2. **Web framework.** Use `axum` on the workspace `hyper`/`tokio` stack.
   Alternatives (hand-rolled `hyper`) are more code and more risk for routing,
   extractors, and middleware. `tower-http` is used only for tracing middleware;
   if it causes friction, it may be omitted in favour of `tracing` spans.

3. **Storage.** SQLite via `rusqlite` with `bundled` SQLite. The API is
   async, so every SQLite operation is executed through
   `tokio::task::spawn_blocking`. For v1 the process uses a single writer
   connection protected by a `std::sync::Mutex`, plus read-only helpers on that
   same connection. Migrations run at first open. No connection pool yet: the
   control-plane load is small, and SPIFFE-style connection pooling is out of
   scope.

4. **Query-log back-pressure.** `control-api` consumes the bounded
   `QueryEventSink` from `listeners`. A dedicated channel plus a persistent
   writer task batches inserts into SQLite. When the channel is full, events
   are dropped and `control_api.query_log.dropped` is incremented. DNS answering
   is never blocked.

5. **Config atomic apply/rollback.** Persist the full validated configuration
   as a new version in a SQLite transaction. Apply modules in leaf-first order:
   `filtering` → `clients` → `policy` → `listeners` → `tls`. If any module
   fails, re-apply the previous snapshot. Expose the version for optimistic
   concurrency.

6. **TLS bootstrap.** Direct TLS is default (`control_api.tls = true`). The
   HTTP server uses a resolver that first asks the shared ACME
   `tls::CertResolver`; while no ACME certificate exists it serves a persisted
   self-signed `rcgen` certificate. The switch is automatic and does not require
   a restart. The self-signed cert is ECDSA P-256, validity 1 year, SANs =
   configured node hostname + `localhost`, private key mode 0600. `tls_mode`
   (`acme` | `self_signed`) and SHA-256 fingerprint are exposed in status. The
   self-signed cert is regenerated when expired or when the node hostname
   changes. Reverse-proxy mode (`tls = false` + `trusted_proxies`) is optional.

7. **Auth.** Session ids and bearer tokens are random and stored only as
   hashes (`ring::digest::SHA256`). Password hashing for break-glass login is
   `argon2` (Argon2id). CSRF uses the synchronizer token pattern for cookie
   sessions; bearer-token requests do not require CSRF. OIDC follows
   Authorization Code + PKCE + nonce.

8. **OpenID connect integration.** Candidate `openidconnect` is approved if and
   only if its dependency tree is ring-only and passes `cargo deny check`. If
   not, implement the same discovery/JWKS validation hand-rolled on `ring` +
   `reqwest` and record an ADR. This is tested in A5 against an in-process mock
   provider; no real Authentik is ever contacted in CI.

9. **Secrets redaction.** Config exports and audit before/after snapshots must
   mask secret material (tokens, keys, OIDC client secret, UniFi API key).
   Private keys are never returned by any API and never written to audit JSON
   except as a digest or `"redacted"`.

## Crate layout

```
crates/dnscraft-api/
├── Cargo.toml
├── src/
│   ├── lib.rs                 // exports, module docs
│   ├── config.rs              // control_api config/validation
│   ├── error.rs               // ControlApiError stable code()
│   ├── server.rs              // axum router, listener, startup/shutdown
│   ├── tls.rs                 // ACME/self-signed resolver + persistence
│   ├── storage/
│   │   ├── mod.rs
│   │   ├── db.rs              // spawn_blocking wrapper, connection
│   │   ├── migrations.rs     // schema DDL
│   │   ├── config_store.rs   // kv + config_versions
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
│   ├── modules.rs             // narrow apply/facade traits
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

All code/comments/docs are English. `unsafe` is forbidden workspace-wide.

## Phases and task list

Suggested phase order from the brief, adopted as-is:

- **Phase 0 — Skeleton:** A0
- **Phase 1 — Storage:** A1, A2
- **Phase 2 — Server core:** A3
- **Phase 3 — Auth:** A4, A5
- **Phase 4 — Config endpoints:** A6
- **Phase 5 — Query log + statistics:** A7, A8
- **Phase 6 — Hardening:** A9

Checkpoints:

- **Checkpoint A** after A2 (storage and config snapshot/version)
- **Checkpoint B** after A5 (server core + auth, incl. mock OIDC)
- **Checkpoint C** after A8 (config endpoints + query log + stats)
- **Checkpoint D** after A9 (hardening; Claude review + owner approval)

### Task dependencies

```
A0
└── A1
    └── A2
        └── A3
            ├── A4
            │   └── A5
            └── A6 (also depends on A5)
                    └── A7
                        └── A8
                            └── A9
```

`A6` needs the auth layer from A4/A5 because all mutating endpoints are
role-checked. `A7` needs the listener sink and config from A3/A6.

## Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| `openidconnect` is not ring-only | Med/High | A5 starts with the candidate; if `cargo tree -i aws-lc-rs`/`aws-lc-sys`/`openssl-sys` is non-empty or `cargo deny check` fails, fall back to the hand-rolled `ring`+`reqwest` implementation and record an ADR. |
| SQLite blocking in async runtime | High | Every DB call via `tokio::task::spawn_blocking`; no DB call on the reactor. Single writer connection for v1. |
| QueryEventSink back-pressure stalls DNS answering | High | Listener sink is already non-blocking; control-api consumes it via a bounded `mpsc` + batching writer task. On full, drop and count. |
| `listeners` crate still evolving | Low/Med | Control-api depends on the public API; if an upstream method changes, adapters in `src/modules.rs` localize the change. Final hardening A9 includes an integration check against the current listener API. |
| `rcgen` self-signed cert switch race / renewal | Med | A3 specifically tests `tls_mode` transitions and automatic fallback. Self-signed cert is persisted atomically, private key mode checked in test. |
| Audit before/after leaks secrets | High | Redaction applied before persistence; security tests in A9 assert no known secret appears. |
| Rate limit bypass via forwarded headers | Med | Reverse-proxy mode honours `X-Forwarded-For` only from `trusted_proxies`; direct sockets ignore forwarded headers and use peer IP. |

## Dependencies for owner approval

Workspace dependencies are reused with versions/features pinned in the root
`Cargo.toml`. The root already provides the runtime and crypto stack. New
direct dependencies are listed below.

| Crate | Candidate version/features | Why | Alternative | Licence | Ring-only checked? |
|---|---|---|---|---|---|
| `axum` | latest 0.8.x; `json`, `query`, `http1`; no default TLS | Router/extractors on existing hyper/tokio | hand-rolled hyper (more code) | MIT | **Unverified** — dry check required before code |
| `tower-http` | 0.6.11 (already transitive in Cargo.lock via reqwest); `trace` only | Tracing middleware | omit, use tracing spans | MIT | **Unverified** — promote only if dry check passes |
| `rusqlite` | latest stable; `bundled` | SQLite persistence, fixed by SPEC.md | pure-Rust SQLite alternative less mature | MIT | **Unverified** — dry check required for dependency tree (bundled compiles C SQLite) |
| `argon2` | latest 0.5.x; `std` | Argon2id for break-glass login | `ring::pbkdf2` (PBKDF2-HMAC-SHA256) | MIT/Apache-2.0 | **Unverified** — pure Rust, but still dry check |
| `uuid` | latest 1.x; `v4` | Entity IDs | `ring::rand` + hex (no new dep) | MIT/Apache-2.0 | **Unverified** — dry check required |
| `openidconnect` | latest stable; **no** `reqwest` default features; custom HTTP client | Discovery, JWKS and ID-token validation | hand-rolled on `ring` + `reqwest` | MIT/Apache-2.0 | **Unverified** — this is the highest-risk crate; cannot be approved until dry check proves no aws-lc/openssl |

Dry-check commands to run in a scratch copy **before** this plan is approved:

```
cargo tree -i aws-lc-rs
cargo tree -i aws-lc-sys
cargo tree -i openssl-sys
cargo deny check
```

All must be empty/green. The repository already bans aws-lc and openssl in
`deny.toml`.

## Success-criteria traceability

| Spec criterion | Task(s) |
|---|---|
| 1. Documented `/api/v1` endpoints + envelopes/status codes | A3, A6, A7, A8 |
| 2. Config PUT atomic applies/rolls back all modules | A2, A6 |
| 3. Query-log endpoints enriched/filter/order/paginate with 10 000 rows | A7 |
| 4. “Why blocked?” full DecisionRecord | A7 |
| 5. Mock OIDC flow works; invalid/expired/weekly claims rejected | A5 |
| 6. Break-glass login locks after failures and writes audit events | A4 |
| 7. Viewer/admin role separation; MCP scopes map | A4, A5, A9 |
| 8. Audit log with before/after digests + login failures | A2, A4 |
| 9. Internal-only binding enforcement | A3, A9 |
| 10. No real external Auth/OIDC/Cloudflare; DoD green | A5, A9 |
| 11. TLS bootstrap self-signed → ACME switch without restart | A3 |
| 12. NDJSON export primary streaming format + CSV convenience | A8 |
| 13. Audit before/after snapshots mask secrets | A2, A6, A9 |

## Open questions for the owner

1. Approve the dependency table above, understanding that `openidconnect`,
   `axum`, `rusqlite`, `argon2`, and `uuid` need one dry-check pass before
   code starts. If the dry check cannot be run by the implementing agent, the
   owner must run it and record the result here before giving the go.
2. `tower-http` is already in `Cargo.lock` transitively via `reqwest`; may we
   promote it to a direct dependency with `trace` only, or should we avoid it
   and use plain `tracing` spans in handlers?
3. Confirm that `control_api.tls.self_signed` should remain a warning-level
   status, not a startup-blocking error, for first-run UX.
