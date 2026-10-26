# Tasks: `control-api` module

> Plan: [plan-control-api.md](plan-control-api.md) · Spec: [SPEC-control-api.md](../../SPEC-control-api.md) ·
> Resume log: [progress.md](../progress.md)
>
> Definition of done per task: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
> `cargo test --workspace --locked` green; lead review; committed.
> Tests use in-memory/temporary SQLite and mock servers only; never the internet and never real
> Authentik/Cloudflare/ACME. Documentation ranges and `example.com`/`example.net` only.

## Phase 0: Skeleton

## Task A0: Crate skeleton, config model, error type

**Description:** Create `crates/dnscraft-api` as a new workspace member (workspace
lints). Dependencies: `thiserror`, `serde`, `serde_json`, `tracing` (workspace), plus
the workspace crypto/runtime crates as needed. Contents:
- `ControlApiConfig` with bootstrap fields matching SPEC-control-api.md:
  `bind`, `port`, `tls`, `trusted_proxies`, `auth`, `query_log`, `rate_limit`.
- `ControlApiError` with every stable `code()` from the spec's error table,
  including `control_api.tls.self_signed` as an informational variant.
- Validation helpers: `bind` must be loopback/private/ULA, never `0.0.0.0` or `::`;
  `retention_days`, `ip_truncate`, rate-limit values, and session/token TTLs must be
  within their documented limits.
No I/O, no routing yet.

**Acceptance criteria:**
- [x] Every error variant has a unique `code()` (enumerating test); every public item documented.
- [x] Error-code uniqueness also covers the MCP-alignment codes: `control_api.auth.unauthenticated`, `control_api.auth.invalid_scope`, `control_api.auth.invalid_origin` (added with A7), plus `control_api.method_not_allowed` and `control_api.payload_too_large` (already implemented).
- [x] `ControlApiConfig` rejects `0.0.0.0`/`::` and accepts loopback, RFC 1918, and ULA addresses.
- [x] Invalid `retention_days`, `ip_truncate`, rate-limit, and TTL values return the documented code.
- [x] No `unwrap()`/`expect()` outside tests; no unsafe.

**Verification:** `cargo test -p dnscraft-api error`

**Dependencies:** plan + dependency table approved

**Files:** `crates/dnscraft-api/Cargo.toml`, `src/lib.rs`, `src/config.rs`, `src/error.rs`

**Scope:** S

## Phase 1: Storage

## Task A1: SQLite storage and migrations

**Description:** Add `rusqlite` with `bundled` SQLite. Create the schema in
`src/storage/migrations.rs` and a `Db` wrapper that executes all calls via
`tokio::task::spawn_blocking` around a single `std::sync::Mutex<Connection>`.
Tables: `kv`, `config_versions`, `audit_log`, `sessions`, `tokens`,
`query_log`, `stats_hourly`, `stats_daily`.
All SQL uses bind parameters; user-provided strings never become SQL text.

**Acceptance criteria:**
- [x] Migrations are idempotent and record `user_version`.
- [x] `kv` get/set and config snapshot store/load round-trips.
- [x] `audit_log` insert/read works and returns records ordered by time/id.
- [x] A crafted SQL-injection string in a query-log filter/value is treated as data and
      returns no rows or `not_found`, never a syntax error (regression test).

**Verification:** `cargo test -p dnscraft-api storage`

**Dependencies:** A0

**Files:** `src/storage/mod.rs`, `src/storage/db.rs`, `src/storage/migrations.rs`,
`src/storage/kv.rs`, `src/storage/audit.rs`, `tests/storage.rs`

**Scope:** M

## Task A2: Config snapshot/version store + audit log with secret redaction

**Description:** Implement `ConfigStore` (kv + `config_versions`) and the audit log
(append-only). This task owns **secret masking**: before a config snapshot or an audit
before/after pair is persisted, every known secret field (OIDC client secret, UniFi API
key, token/session material, TLS private keys) is replaced with `"redacted"` or a digest.
A single redaction helper is shared by config export and audit, so masking cannot be
forgotten on one path.

**Acceptance criteria:**
- [x] A config version round-trips through `config_versions` with its `config_version`.
- [x] Audit rows are append-only and carry `before_digest`/`after_digest` plus redacted snapshots.
- [x] A fake secret placed in config appears as `"redacted"` in both the stored snapshot and
      the audit before/after; the plaintext never reaches SQLite (regression test).
- [x] Token/session *secret* keys (`client_secret`, `api_key`, `session_id`, `bearer`) are
      redacted by token match, and non-secret durations/counts (`*_ttl`, `*_timeout`,
      `*_max_attempts`) are kept (R1 token-based redaction + allow-list; tests in `audit.rs`).
- [x] Rollback-by-version is prepared: a stored version can be read back as the exact snapshot.

**Verification:** `cargo test -p dnscraft-api config_store`

**Dependencies:** A1

**Files:** `src/storage/config_store.rs`, `src/storage/audit.rs`, `src/audit.rs`,
`tests/config_store.rs`

**Scope:** M

## Checkpoint A: Storage
- [ ] DoD green; migrations, snapshot/version, and audit redaction reviewed (lead review)
- [x] progress.md updated

## Phase 2: Server core

## Task A3: HTTP server core — router, envelopes, pagination

**Description:** Build the minimal axum server:
- `GET /healthz`, `GET /readyz`, and the `/api/v1` router prefix.
- `{data}` / `{error}` envelopes exactly as in the spec.
- Pagination helper (`limit` default 50 max 500, `offset`, `next_offset`, `has_more`).
- Versioned routes (v1 only for now); unknown route → `control_api.not_found` envelope.
- `control_api.internal` invariant boundary.

**Acceptance criteria:**
- [x] `/healthz` and `/readyz` respond; `/readyz` returns `control_api.not_ready` when a module is not ready.
- [x] Unknown route returns the documented `{error}` envelope with `control_api.not_found`.
- [x] Pagination defaults, caps, and `next_offset`/`has_more` behave as specified.

**Verification:** `cargo test -p dnscraft-api api_core`

**Dependencies:** A2

**Files:** `src/server.rs`, `src/api/mod.rs`, `src/api/router.rs`,
`src/api/response.rs`, `src/api/pagination.rs`, `tests/api_core.rs`

**Scope:** M

## Task A4: Internal-only bind + TLS bootstrap (self-signed → ACME switch)

**Description:** Enforce **internal-only binding** and implement the TLS bootstrap:
- Bind only to loopback/private/ULA; `0.0.0.0`/`::` and public addresses rejected.
- TLS resolver that asks `tls::CertResolver` (ACME) first and falls back to a persisted
  self-signed `rcgen` certificate while `CertResolver::has_cert()` is false.
- Self-signed cert: ECDSA P-256, validity 1 year, SANs = node hostname + `localhost`,
  private key mode 0600, regenerated when expired or the hostname changes.
- Status exposes `tls_mode` (`acme` | `self_signed`) and the SHA-256 fingerprint, plus the
  `control_api.tls.self_signed` warning while self-signed.
- Reverse-proxy mode (`tls = false` + `trusted_proxies`): forwarded headers honoured only
  from trusted proxies; `Secure` cookie follows `X-Forwarded-Proto`.

**Acceptance criteria:**
- [x] API starts only on allowed bind addresses; `0.0.0.0`/`::` returns `control_api.config.invalid`.
- [x] TLS serves a persisted self-signed certificate when no ACME cert exists; status exposes
      `tls_mode` and SHA-256 fingerprint.
- [x] After a fake `CertResolver` presents a cert, the same listener switches without restart
      (fake resolver toggles after start; regression test).
- [x] Private key file is mode 0600 (test asserts); self-signed cert never served for a hostname
      that has an ACME cert.
- [ ] Forwarded headers are honoured only from `trusted_proxies`; direct socket ignores them.

**Verification:** `cargo test -p dnscraft-api tls_bind`

**Dependencies:** A3

**Files:** `src/tls.rs`, `src/server.rs`, `tests/tls_bind.rs`

**Scope:** M

## Task A5: Rate limiting

**Description:** In-memory token-bucket rate limiter per source IP and per authenticated
principal, with the configured defaults (read 100/s burst 200, write 20/s burst 40, auth
10/s burst 20). Exceeded → `429` with `control_api.rate_limited`. Buckets use the injectable
clock (no wall-clock sleeps). The limiter is consulted in a single middleware.

**Acceptance criteria:**
- [x] Read/write/auth endpoints are rate-limited at their documented defaults.
- [x] Exceeded rate returns `429` with the `control_api.rate_limited` envelope.
- [x] Bucket refill is clock-driven; a `ManualClock` test shows refill without sleeping.
- [x] A flood beyond the burst is capped (regression test), and the source IP is taken from
      the trusted peer, not a spoofable header (unless `trusted_proxies`).

**Verification:** `cargo test -p dnscraft-api rate_limit`

**Dependencies:** A3

**Files:** `src/api/rate_limit.rs`, `tests/rate_limit.rs`

**Scope:** S

## Checkpoint B: Server core
- [ ] DoD green; server core + TLS bootstrap + rate limit reviewed (lead review)
- [ ] progress.md updated

## Phase 3: Auth

## Task A6: Sessions + CSRF

**Description:** Implement cookie sessions and **CSRF**:
- Opaque session id (random via `ring::rand`), stored hashed (`ring::digest::SHA256`).
- Absolute (12 h) + idle (60 min) expiry on the injectable clock; logout invalidates.
- HttpOnly; Secure when TLS/forwarded-proto; SameSite=Lax.
- Synchronizer-token CSRF: required for all mutating cookie-session requests;
  bearer-token requests are exempt.

**Acceptance criteria:**
- [x] Session id is stored only as a hash; the plaintext is never persisted.
- [x] Idle and absolute expiry are enforced with a manual clock (no sleeps).
- [x] CSRF: a mutating cookie-session request without/with a wrong token is rejected with
      `control_api.auth.csrf`; a bearer-token request without CSRF is accepted (regression test).
- [x] Logout invalidates the session immediately.
- [x] Cookie sessions are `viewer`/`admin` only and authorize `/api/v1` only; a session cookie on `/mcp/v1` is not accepted (MCP uses bearer tokens exclusively).

**Verification:** `cargo test -p dnscraft-api auth_session`

**Dependencies:** A3

**Files:** `src/api/auth/mod.rs`, `src/api/auth/sessions.rs`, `src/api/auth/csrf.rs`,
`tests/auth_session.rs`

**Scope:** M

## Task A7: Bearer tokens + roles (RBAC)

**Description:** Implement bearer API tokens and centralized role checks:
- Token generated with `ring::rand`, returned exactly once; stored only as SHA-256 hash;
  revoked by deleting the hash. Optional expiry.
- **Four scopes from the start:** `viewer`/`admin` (valid only on `/api/v1`) and
  `mcp:read`/`mcp:write` (valid only on `/mcp/v1`). Scope enum plus a per-endpoint-family
  validity check; no token is valid on both families.
- Token creation via `POST /api/v1/auth/tokens`, admin only; all four scopes selectable;
  the response carries the `control_api.tls.self_signed` warning while the bootstrap
  certificate is served.
- `Authorization: Bearer <token>` authentication; no CSRF required.
- One RBAC middleware maps every route to a required scope and enforces the endpoint family;
  `viewer` cannot call admin routes; an `mcp:read` token cannot call write tools (the MCP
  layer surfaces that as a tool-level `control_api.auth.insufficient_scope`).
- `control_api.auth.unauthenticated` (401) on a missing, malformed, unknown, revoked or
  expired bearer token; `control_api.auth.invalid_scope` (403) on a token from the wrong
  endpoint family; `control_api.auth.insufficient_scope` (403) on a permission the role
  lacks. `control_api.auth.unknown_token` is reserved for token-management calls that
  address a token id.

**Acceptance criteria:**
- [x] Token plaintext is returned exactly once; later responses never contain it; DB stores
      only the SHA-256 hash (regression test).
- [x] A revoked token immediately fails with `control_api.auth.unauthenticated` (401).
- [x] The scope enum is `viewer` | `admin` | `mcp:read` | `mcp:write`; `viewer` cannot call
      an admin-only route; `admin` can.
- [x] Per-endpoint-family validity: a `viewer`/`admin` token on `/mcp/v1` and an
      `mcp:read`/`mcp:write` token on `/api/v1` are rejected with
      `control_api.auth.invalid_scope`; no token is valid on both families (regression test).
- [x] Missing/malformed token → 401 `control_api.auth.unauthenticated`; a permission the
      role lacks → 403 `control_api.auth.insufficient_scope`.
- [x] Token creation requires admin; all four scopes can be selected; the self-signed
      warning is present while `tls_mode = self_signed`.
- [x] The three new auth codes are added to `ControlApiError` and covered by the A0
      uniqueness test.
- [x] No plaintext token appears in logs or audit.

**Verification:** `cargo test -p dnscraft-api auth_token`

**Dependencies:** A6

**Files:** `src/api/auth/tokens.rs`, `src/api/auth/roles.rs`, `tests/auth_token.rs`

**Scope:** M

## Task A8: Break-glass local login + lockout

**Description:** Implement local break-glass login with **lockout**:
- Password hashing via `argon2` (Argon2id, RFC 9106).
- Lockout after `local_login_max_attempts` (5) within `local_login_lock_window` (15 min)
  on the injectable clock → `423` with `control_api.auth.locked`.
- Every success/failure is written to the audit log; passwords never appear in logs/DB.

**Acceptance criteria:**
- [ ] Correct password creates a session; wrong password fails with `control_api.auth.local`.
- [ ] Lockout after 5 failures; `423 control_api.auth.locked`; unlocks after window expiry
      (manual clock, no sleeps — regression test).
- [ ] Every local login success/failure is audited; the password itself is never stored or logged.
- [ ] Argon2id is used (config/verify via the `argon2` crate, not PBKDF2).

**Verification:** `cargo test -p dnscraft-api auth_local`

**Dependencies:** A7

**Files:** `src/api/auth/local.rs`, `tests/auth_local.rs`

**Scope:** M

## Task A9: OIDC flow + mock provider

**Description:** Implement OIDC Authorization Code + PKCE S256 + nonce.
- Discovery + JWKS; ID-token validation (`iss`, `aud`, `nonce`, `exp`, `iat`, `at_hash`).
- Role mapping: no admin group claim → `viewer`; configured admin group present → `admin`.
- Test against an in-process mock OIDC provider (discovery, authorization, token, JWKS).
- Use `openidconnect` (per plan decision) or the hand-rolled `ring` fallback, per owner
  approval; no real Authentik/internet in CI.

**Acceptance criteria:**
- [ ] Happy path with the mock provider creates a session and maps viewer/admin by the groups claim.
- [ ] Invalid signature, expired token, wrong audience, wrong issuer, missing nonce are rejected
      with `control_api.auth.oidc` (regression tests).
- [ ] State/nonce/PKCE are validated and one-time only; reuse fails.
- [ ] alg=none and HS256/alg-confusion are rejected (threat-model regression test).
- [ ] No real internet/OIDC provider is contacted in tests.

**Verification:** `cargo test -p dnscraft-api auth_oidc`

**Dependencies:** A8

**Files:** `src/api/auth/oidc.rs`, `tests/auth_oidc.rs`

**Scope:** M

## Checkpoint C: Auth
- [ ] DoD green; sessions/CSRF, tokens/roles, local login, OIDC reviewed (lead review)
- [ ] progress.md updated

## Phase 4: Config endpoints

## Task A10: Config apply/rollback service + `GET/PUT /config`

**Description:** Implement the atomic apply service and expose it:
- `GET /api/v1/config` (secrets excluded), `PUT /api/v1/config` (atomic), `GET
  /api/v1/config/versions`, `POST /api/v1/config/versions/{version}/rollback`.
- Apply order: `filtering` → `clients` → `policy` → `listeners` → `tls`; on any failure,
  re-apply the previous snapshot and return the module's stable code.
- Narrow module traits (`ApplyFiltering`, `ApplyClients`, `ApplyPolicy`,
  `ApplyListeners`, `ApplyTls`) so tests use fakes. Optimistic concurrency via `If-Match`.
- **`mcp_rules` merge contract:** a `PUT /config` that omits `mcp_rules` carries the stored
  rules over per filter set; an explicit `"mcp_rules": []` deletes them; an unknown field
  in the request body is rejected with `control_api.config.invalid` (never silently
  dropped). Until M0 introduces the typed field, test this at the snapshot/JSON boundary
  with fixtures containing an `mcp_rules` key.

**Acceptance criteria:**
- [ ] Valid config persists, applies, and increments `config_version`; invalid config returns
      the stable code and calls no module apply.
- [ ] Apply order is exactly filtering → clients → policy → listeners → tls.
- [ ] When `policy` fails, the previous config is replayed and is active again (rollback
      regression test).
- [ ] Rollback by version restores that exact snapshot (including any `mcp_rules`) and is audited.
- [ ] `PUT /config` without `mcp_rules` preserves the stored rules; an explicit empty list
      deletes them; an unknown field returns `control_api.config.invalid` (regression tests
      for all three cases).
- [ ] `GET /config` excludes secrets; module validation errors propagate the module code.

**Verification:** `cargo test -p dnscraft-api config_apply`

**Dependencies:** A9

**Files:** `src/config_apply.rs`, `src/modules.rs`, `src/api/config_routes.rs`,
`tests/config_apply.rs`

**Scope:** M

## Task A11: Per-module config CRUD routes

**Description:** Expose the per-module configuration routes under `/api/v1` using the typed
DTOs from the modules (no parallel string types):
- policy views/profiles/pause, clients manual + sync, filter-sets/lists, listeners, tls.
- All mutating paths require admin; all return the error envelope with module codes where
  applicable (`policy.config.*`, `clients.config.*`, `listeners.config.*`, `tls.config.*`).

**Acceptance criteria:**
- [ ] Every documented CRUD endpoint exists with the correct request/response shape.
- [ ] Cross-module validation (profile → view, forward-zone id exists) is performed before apply.
- [ ] A module validation error is returned with the module's code, not a generic control-api code.

**Verification:** `cargo test -p dnscraft-api config_http`

**Dependencies:** A10

**Files:** `src/api/clients_routes.rs`, `src/api/filter_routes.rs`,
`src/api/listener_routes.rs`, `src/api/tls_routes.rs`, `src/api/config_routes.rs`,
`tests/config_http.rs`

**Scope:** M

## Checkpoint D: Config endpoints
- [ ] DoD green; config apply/rollback + CRUD reviewed (lead review)
- [ ] progress.md updated

## Phase 5: Query log + statistics

## Task A12: Query-log consumer, storage, filtering, “why blocked?”

**Description:** Implement the `QueryEventSink` consumer:
- Receive bounded `listeners::QueryEvent`s and batch-insert into SQLite.
- Full sink drops events and increments `control_api.query_log.dropped`; answering never blocks.
- Retention by `retention_days`; `ip_truncate` applied at write.
- Filter parameters (`from`/`to`, `client_id`, `domain`, `protocol`, `status`,
  `only_blocked`, `order_by`, `limit`/`offset`) and pagination.
- `GET /api/v1/query-log` list/search; `GET /api/v1/query-log/{id}` returns the full
  `policy::DecisionRecord` for “why blocked?”.

**Acceptance criteria:**
- [ ] With 10 000 inserted rows, filter/order/pagination works within defaults and the row cap.
- [ ] Query events are enriched with `clients` data when a matching client exists.
- [ ] Retention deletes rows older than the configured window.
- [ ] “why blocked?” returns the full `DecisionRecord` steps/filter/timings.
- [ ] Full sink drops events and does not block DNS answering; the counter increments
      (regression test).

**Verification:** `cargo test -p dnscraft-api query_log`

**Dependencies:** A11

**Files:** `src/query_log.rs`, `src/api/query_log_routes.rs`, `tests/query_log.rs`

**Scope:** M

## Task A13: Statistics rollups + export (NDJSON primary, CSV secondary)

**Description:** Implement:
- Hourly and daily rollups into `stats_hourly`/`stats_daily` (365-day retention).
- Top clients/domains/cache stats endpoints with the documented cardinality caps.
- `GET /api/v1/query-log/export.ndjson` (streaming, primary) and
  `GET /api/v1/query-log/export.csv` (convenience). Both obey the current filter and retention.

**Acceptance criteria:**
- [ ] NDJSON export streams records and obeys the current filters.
- [ ] CSV export returns the same filtered set.
- [ ] Rollup tables are populated for hourly/daily windows; rollup retention is 365 days.
- [ ] Top clients/domains respect cardinality caps.
- [ ] Export contains no secret material or client data beyond the documented schema.

**Verification:** `cargo test -p dnscraft-api stats_export`

**Dependencies:** A12

**Files:** `src/stats.rs`, `src/api/stats_routes.rs`, `tests/stats_export.rs`

**Scope:** M

## Checkpoint E: Query log + statistics
- [ ] DoD green; query log + stats + export reviewed (lead review)
- [ ] progress.md updated

## Phase 6: Hardening

## Task A14: Hardening, threat-model tests, coverage, README, final DoD

**Description:** Final hardening pass:
- Internal-only bind tests, threat-model tests (SQL injection, path traversal, CSRF bypass,
  forwarded-header spoofing, token/session replay, secret leakage, alg-confusion).
- Assert the API is never reachable via a public DoH/DoT listener (public router serves only
  `/dns-query/...`).
- README, coverage, and traceability close against every spec success criterion.

**Acceptance criteria:**
- [ ] Security regression tests pass for every listed threat.
- [ ] API cannot be reached on public listener ports.
- [ ] `cargo fmt`, `clippy -D warnings`, `cargo test --workspace`, `cargo deny check` green.
- [ ] No new aws-lc/openssl in the dependency tree (and any advisory ignores are the approved ones).
- [ ] Coverage of non-HTTP glue logic ≥ 80 % OR the gap is documented and accepted.
- [ ] README explains internal-only bind, TLS bootstrap, secrets policy, and the stable
      error-code contract.

**Verification:** full DoD

**Dependencies:** A13

**Files:** `README.md`, `tests/security.rs`, all previously touched files as needed

**Scope:** M

## Checkpoint F: Complete
- [ ] Spec success criteria 1–13; `cargo deny check` green
- [ ] Independent Claude review (auth, secrets redaction, TLS switch, apply/rollback)
- [ ] **Owner approval** (plan + dependency table)

## Phase M (after Checkpoint F): MCP backend

**Placeholder only.** No item below is approved or scheduled, and none belongs
to Phase 0–6. Each item needs an owner-approved plan. The contract is
SPEC-control-api.md § MCP-phase endpoints / § MCP-managed filter rules / § Auth /
§ MCP mount and SPEC-mcp.md.

### Endpoints

- `POST /api/v1/filtering/explain-block`
- `POST /api/v1/policy/test-query`
- `POST /api/v1/filtering/temporary-allows`
- `POST /api/v1/filtering/custom-rules`
- `DELETE /api/v1/filtering/custom-rules`
- `GET /api/v1/filtering/mcp-rules`
- `POST /api/v1/filtering/pause`
- `POST /api/v1/filtering/resume`

## Task M0: Prerequisites in filtering and resolver — needs owner-approved plan

**Description:** Add the public APIs the MCP backend needs, in their own crates:
- filtering: `McpRule`; `FilterSetConfig::mcp_rules`; `FilterEngine::set_paused_until`;
  `TempAllow.created_at`.
- resolver: a `no_cache_write` flag for cache reads.

Reality check (2026-10-26): `McpRule`, `mcp_rules`, `set_paused_until`,
`TempAllow.created_at` and `no_cache_write` do **not** exist in the current
public APIs. Each is a separate crate change and needs its own approved plan.

**Acceptance criteria:** defined by the approved prerequisite plans; not part of
the control-api v1 tasks.

**Dependencies:** Checkpoint F; owner approval.

## Task M1: `McpBackend` implementation — needs owner-approved plan

**Description:** Implement the `McpBackend` trait from
`crates/dnscraft-mcp/src/backend.rs` in control-api, calling the internal
services (policy, filtering, clients, query log, audit). Convert mcp DTOs at this
boundary only; no mcp types in storage.

**Acceptance criteria:** defined by the approved MCP-phase plan.

**Dependencies:** M0.

## Task M2: MCP-phase HTTP endpoints — needs owner-approved plan

**Description:** Implement the eight endpoints above with the exact shapes and
codes from SPEC-control-api.md § MCP-phase endpoints. `custom-rules` add/remove
are config mutations under the apply lock with the `mcp_rules` merge rule;
temporary allows and pauses stay runtime state.

**Acceptance criteria:** defined by the approved MCP-phase plan.

**Dependencies:** M0, M1.

## Task M3: Mount `/mcp/v1` — needs owner-approved plan

**Description:** Add the `mcp` crate as a dependency, build its service with the
backend, and mount it with `nest_service` on the internal listener. While MCP is
disabled, `/mcp/v1` returns 404 `control_api.not_found`. Includes the `rmcp`
dependency approval recorded in SPEC-mcp.md.

**Acceptance criteria:** defined by the approved MCP-phase plan.

**Dependencies:** M1, M2; owner approval of the `mcp`/`rmcp` dependencies.
