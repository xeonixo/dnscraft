# Tasks: `control-api` module

> Plan: [plan-control-api.md](plan-control-api.md) · Spec: [SPEC-control-api.md](../../SPEC-control-api.md) ·
> Resume log: [progress.md](../progress.md)
>
> Definition of done per task: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
> `cargo test --workspace --locked` green; lead review; committed.
> Tests use in-memory/temporary SQLite and mock servers only; never the internet and never real
> Authentik/Cloudflare/ACME. Documentation ranges and `example.com`/`example.net` only.

## Task A0: Crate skeleton, config model, error type

**Description:** Create `crates/dnscraft-api` as a new workspace member.
Dependencies: `thiserror`, `serde`, `serde_json`, `tracing` (workspace).
Contents:
- `ControlApiConfig` with bootstrap fields matching SPEC-control-api.md:
  `bind`, `port`, `tls`, `trusted_proxies`, `auth`, `query_log`, `rate_limit`.
- `ControlApiError` with every stable `code()` from the spec’s error table,
  including `control_api.tls.self_signed` as an informational variant.
- Validation helpers: `bind` must be loopback/private/ULA, never `0.0.0.0` or `::`;
  `retention_days`, `ip_truncate`, rate-limit values, and session/token TTLs must
  be within their documented limits.
No I/O, no routing yet.

**Acceptance criteria:**
- [ ] Every error variant has a unique `code()` (enumerating test); every public item documented.
- [ ] `ControlApiConfig` rejects `0.0.0.0`/`::` and accepts loopback, RFC 1918, and ULA addresses.
- [ ] Invalid `retention_days`, `ip_truncate`, rate-limit, and TTL values return the documented code.
- [ ] No `unwrap()`/`expect()` outside tests; no unsafe.

**Verification:** `cargo test -p dnscraft-api error`

**Dependencies:** plan approved

**Files:** `crates/dnscraft-api/Cargo.toml`, `src/lib.rs`, `src/config.rs`, `src/error.rs`

**Scope:** S

## Task A1: SQLite storage and migrations

**Description:** Add `rusqlite` with `bundled` SQLite. Create the schema in
`src/storage/migrations.rs` and a `Db` wrapper that executes all calls via
`tokio::task::spawn_blocking` around a single `std::sync::Mutex<Connection>`.
Tables: `kv`, `config_versions`, `audit_log`, `sessions`, `tokens`,
`query_log`, `stats_hourly`, `stats_daily`.
All SQL uses bind parameters; user-provided strings never become SQL text.

**Acceptance criteria:**
- [ ] Migrations are idempotent and record `user_version`.
- [ ] `kv` get/set and config snapshot store/load round-trips.
- [ ] `audit_log` insert/read works and returns records ordered by time/id.
- [ ] A crafted SQL-injection string in a query-log filter/value is treated as data and
      returns no rows or `not_found`, not a syntax error.

**Verification:** `cargo test -p dnscraft-api storage`

**Dependencies:** A0

**Files:** `src/storage/mod.rs`, `src/storage/db.rs`, `src/storage/migrations.rs`,
`src/storage/kv.rs`, `src/storage/audit.rs`, `tests/storage.rs`

**Scope:** M

## Task A2: Config snapshot/version + atomic apply/rollback

**Description:** Implement `ConfigStore` and the `apply_config` service function.
Validation order:
1. Full typed config validation.
2. `filtering` → `clients` → `policy` → `listeners` → `tls`.
3. On any failure, re-apply the previous snapshot.
Use narrow module traits (`ApplyFiltering`, `ApplyClients`, `ApplyPolicy`,
`ApplyListeners`, `ApplyTls`) so tests can use fakes. Store successful
config generations in `config_versions`.

**Acceptance criteria:**
- [ ] Valid config persists and increments `config_version`; invalid config returns
      stable code and does not call any module apply.
- [ ] Apply order is exactly filtering → clients → policy → listeners → tls.
- [ ] When `policy` fails, the previous config is replayed and returned older version is active.
- [ ] Rollback by version restores that exact snapshot and applies it atomically.
- [ ] Audit before/after redaction masks secrets; test with a mock config containing a fake key.

**Verification:** `cargo test -p dnscraft-api config_apply`

**Dependencies:** A1

**Files:** `src/storage/config_store.rs`, `src/config_apply.rs`, `src/modules.rs`,
`tests/config_apply.rs`

**Scope:** M

## Task A3: API server core, TLS bootstrap, error envelope, pagination, rate limiting

**Description:** Build the minimal axum server:
- `GET /healthz`, `GET /readyz`, and `/api/v1` router prefix.
- TLS resolver with `tls::CertResolver` + persisted `rcgen` self-signed
  certificate fallback; automatic switch to ACME cert.
- `{data}` / `{error}` envelopes from the spec.
- Pagination helper (`limit`, `offset`, `next_offset`, `has_more`).
- In-memory token-bucket rate limiter per source IP / principal with the
  configured defaults; returns `429` with `control_api.rate_limited`.
- Bind only to loopback/private/ULA; public and wildcard binds rejected.

**Acceptance criteria:**
- [ ] API starts only on allowed bind addresses; `0.0.0.0`/`::` returns
      `control_api.config.invalid`.
- [ ] TLS serves a persisted self-signed certificate when no ACME cert exists;
      status exposes `tls_mode` and SHA-256 fingerprint.
- [ ] After the ACME resolver presents a cert, the same listener switches
      without restart; test with a fake resolver that changes after start.
- [ ] Unknown route returns the documented `{error}` envelope with
      `control_api.not_found`.
- [ ] Rate limit returns `429` and the `Retry-After`/envelope is present.
- [ ] Pagination defaults, caps, and `next_offset`/`has_more` behave as specified.
- [ ] No real TLS handshakes outside loopback tests; no real ACME.

**Verification:** `cargo test -p dnscraft-api api_core`

**Dependencies:** A2

**Files:** `src/server.rs`, `src/tls.rs`, `src/api/mod.rs`, `src/api/router.rs`,
`src/api/response.rs`, `src/api/pagination.rs`, `src/api/rate_limit.rs`,
`tests/api_core.rs`

**Scope:** L

## Task A4: Auth sessions, CSRF, bearer tokens, roles, local break-glass login

**Description:** Implement auth primitive:
- Opaque session id generation, SHA-256 hashed storage, absolute + idle
  expiry, logout invalidation.
- CSRF synchronizer tokens for cookie sessions.
- Bearer API tokens generated with `ring::rand`, stored as SHA-256 hash only,
  revoked by deleting hash; viewer/admin scope enforcement.
- Local break-glass login using `argon2` Argon2id; lockout after 5 failed
  attempts in 15 minutes (`control_api.auth.locked`); success/failure audit.
- All role checks are centralized in one middleware.

**Acceptance criteria:**
- [ ] Token creation returns the plaintext token exactly once; later responses
      never contain it; DB stores only SHA-256 hash.
- [ ] Revoked token immediately fails auth with `control_api.auth.unknown_token`.
- [ ] CSRF required for cookie-session mutations, not for bearer-token requests.
- [ ] Session idle/absolute expiry enforced by injecting a manual clock.
- [ ] Local login is locked after 5 failures and unlocks after window expiry;
      every failure is audited.
- [ ] Viewer cannot call an admin-only route; admin can.
- [ ] Passwords never appear in logs or DB; audit records store only result/error.

**Verification:** `cargo test -p dnscraft-api auth_local`

**Dependencies:** A3

**Files:** `src/api/auth/mod.rs`, `src/api/auth/sessions.rs`, `src/api/auth/csrf.rs`,
`src/api/auth/tokens.rs`, `src/api/auth/roles.rs`, `src/api/auth/local.rs`,
`tests/auth_local.rs`

**Scope:** L

## Task A5: OIDC flow + mock provider

**Description:** Implement OIDC Authorization Code + PKCE S256 + nonce.
- Discovery and JWKS validation. Role mapping: no admin group → `viewer`;
  admin group present → `admin`.
- Test against an in-process mock OIDC provider (discovery, authorization,
  token, JWKS). No real Authentik/internet.
- If `openidconnect` is not ring-only after the dry check, use the
  `ring`+`reqwest` hand-rolled fallback and record an ADR.

**Acceptance criteria:**
- [ ] Happy path with mock provider creates a session and maps viewer/admin by groups claim.
- [ ] Invalid signature, expired token, wrong audience, wrong issuer, missing nonce are rejected
      with stable `control_api.auth.oidc` codes.
- [ ] State/nonce/PKCE are validated and one-time only; reuse fails.
- [ ] No real internet/OIDC provider contacted in tests.

**Verification:** `cargo test -p dnscraft-api auth_oidc`

**Dependencies:** A4

**Files:** `src/api/auth/oidc.rs`, `tests/auth_oidc.rs`

**Scope:** M

## Task A6: Configuration HTTP endpoints + atomic apply/rollback

**Description:** Expose policy/clients/filter-sets/listeners/tls configuration
endpoints under `/api/v1`. Use typed DTOs from the modules, not parallel types.
Endpoints:
- `GET /api/v1/config`
- `PUT /api/v1/config` with atomic apply
- `GET /api/v1/config/versions`
- `POST /api/v1/config/versions/{version}/rollback`
- Individual CRUD routes from the endpoint table.
All mutating paths require admin role; all return the error envelope with
module error codes where applicable.

**Acceptance criteria:**
- [ ] Every documented endpoint exists with correct request/response shape.
- [ ] `GET /api/v1/config` excludes secrets; `PUT /api/v1/config` applies,
      persists, and increments version.
- [ ] Rollback by version works and is audited.
- [ ] Module validation errors propagate the module code, not a generic control-api code.
- [ ] Audit before/after snapshots are redacted; a test places a fake secret and
      asserts it is masked.

**Verification:** `cargo test -p dnscraft-api config_http`

**Dependencies:** A3, A5

**Files:** `src/api/config_routes.rs`, `src/api/clients_routes.rs`,
`src/api/filter_routes.rs`, `src/api/listener_routes.rs`, `src/api/tls_routes.rs`,
`tests/config_http.rs`

**Scope:** L

## Task A7: Query-log consumer and storage/retention/filtering

**Description:** Implement the `QueryEventSink` consumer:
- Receive bounded `listeners::QueryEvent`s and batch insert into SQLite.
- Full sink drops and increments `control_api.query_log.dropped`; answering never blocks.
- Retain records by `retention_days`.
- Implement query-log filter parameters and pagination.
- `GET /api/v1/query-log` list/search; `GET /api/v1/query-log/{id}` returns
  full `DecisionRecord` for “why blocked?”.

**Acceptance criteria:**
- [ ] With 10 000 inserted rows, filter/order/pagination works within defaults.
- [ ] Query events are enriched with `clients` data when a matching client exists.
- [ ] Retention deletes rows older than configured retention.
- [ ] `why blocked` response contains the full `DecisionRecord` steps/filter/timings.
- [ ] Full sink drops events and does not block DNS answering; counter increments.

**Verification:** `cargo test -p dnscraft-api query_log`

**Dependencies:** A6

**Files:** `src/query_log.rs`, `src/api/query_log_routes.rs`, `tests/query_log.rs`

**Scope:** M

## Task A8: Statistics aggregates and export (NDJSON primary, CSV secondary)

**Description:** Implement:
- Hourly and daily rollups into `stats_hourly`/`stats_daily`.
- Top clients/domains/cache stats endpoints.
- `GET /api/v1/query-log/export.ndjson` (streaming primary export).
- `GET /api/v1/query-log/export.csv` (convenience export).
Both obey the current filter and retention.

**Acceptance criteria:**
- [ ] NDJSON export streams records in NDJSON format and obeys filters.
- [ ] CSV export is a convenience and returns same filtered set.
- [ ] Rollup tables populated for hourly/daily windows; retention 365 days for rollups.
- [ ] Top clients/domains respect cardinality caps.
- [ ] No secrets/client raw data beyond documented query-log schema.

**Verification:** `cargo test -p dnscraft-api stats_export`

**Dependencies:** A7

**Files:** `src/stats.rs`, `src/api/stats_routes.rs`, `tests/stats_export.rs`

**Scope:** M

## Task A9: Hardening, security tests, coverage, README, final DoD

**Description:** Final hardening pass:
- Internal-only bind tests, threat-model tests (path traversal, SQL injection,
  CSRF bypass, forwarded-header spoofing, token/session replay, secret leakage).
- Ensure API is never reachable via a public DoH/DoT listener (only
  `/dns-query/...` routes, not `/api/v1`).
- Add README, run coverage, and close traceability against all spec criteria.

**Acceptance criteria:**
- [ ] Security regression tests pass for all listed threats.
- [ ] API cannot be reached on public listener ports; any attempt returns 404
      on the DNS listener’s public router.
- [ ] `cargo fmt`, `clippy -D warnings`, `cargo test --workspace`, `cargo deny check`
      are green.
- [ ] No new aws-lc/openssl in the dependency tree.
- [ ] Coverage of non-HTTP glue logic ≥ 80 % OR gap documented and accepted.
- [ ] README explains internal-only bind, TLS bootstrap, secrets policy, and
      the stable error-code contract.

**Verification:** full DoD

**Dependencies:** A8

**Files:** `README.md`, `tests/security.rs`, all previously touched files as needed

**Scope:** M
