# dnscraft-api

Control API for DNScraft: HTTP REST API, configuration persistence, query log,
statistics, audit trail, and authentication (OIDC + local break-glass login + API
tokens). This crate is the internal-only configuration boundary for the web UI
and the MCP server.

Formal requirements: [`SPEC-control-api.md`](../../SPEC-control-api.md).
Plan / task list: [`tasks/todo-control-api.md`](../../tasks/todo-control-api.md).

## Status

**A0–A14 complete.** The crate is feature-complete for Checkpoint F:

- A0 crate skeleton, config model, stable error type
- A1 SQLite storage, migrations, kv store, audit log
- A2 config snapshot/version store + audit secret redaction
- A3 HTTP core: router, envelopes, pagination, body limits
- A4 rate limiting (peer-derived source IP, trusted-proxy allow-list)
- A5 policy profile/view/pause routes
- A6 client routes (manual + UniFi sync)
- A7 filter set/list routes and local list sources
- A8 listener and TLS configuration routes
- A9 query-log storage, filters, retention, "why blocked?"
- A10 OIDC Authorization Code + PKCE S256 + nonce
- A11 TLS bootstrap: self-signed fallback → ACME without restart
- A12 NDJSON/CSV streaming export
- A13 statistics aggregation and rollups
- A14 security regression suite, internal-only bind proof, this README

## What This Crate Does

- **Configuration persistence**: typed configuration for policy views/profiles,
  clients, filter lists/sets, UniFi settings, listeners, TLS, and auth, stored
  as versioned snapshots
- **Query log storage**: every DNS query with filterable metadata (device,
  VLAN, action, timestamp, latency)
- **Statistics aggregation**: dashboard metrics (queries/sec, cache hit rate,
  top domains, block rate) and hourly/daily rollups
- **Audit log**: every mutating action with actor, timestamp, and redacted
  before/after digests
- **Authentication**: OIDC via Authentik, local break-glass login, API bearer
  tokens with the four fixed scopes
- **HTTP API**: REST endpoints under `/api/v1/` and `/mcp/v1` with
  locale-neutral `area.reason` error codes

This crate does **not** decide which DNS answers are produced — it calls
`policy`, `clients`, `listeners`, `resolver` and `tls` APIs and persists their
configuration. It never serves public DNS traffic.

## Internal-Only Binding

The control API is a management plane and is **never** exposed on the public
DoH/DoT/DoQ listeners.

- `ControlApiConfig::validate` accepts only loopback, RFC 1918 private, and
  IPv6 ULA addresses. It rejects `0.0.0.0`, `::`, and every public address
  (`control_api.config.invalid`). `serve` validates before opening a socket, so
  a bad bind fails closed.
- Public DNS listeners classify request paths with
  `dnscraft_listeners::parse_doh_path`: they serve only `/dns-query` and a
  registered `/dns-query/{client_id}`. `/api/v1/...`, `/mcp/v1/...`,
  `/healthz`, `/readyz`, and every other path are `Other` and answered with a
  bare 404.
- The control-api router mounts no DNS query path.

Both directions are regression-tested in
`tests/security.rs::security_api_refuses_wildcard_and_public_bind_addresses`,
`security_public_doh_listener_serves_only_dns_query_paths`, and
`security_control_api_router_does_not_serve_dns_query_paths`.

## TLS Bootstrap

`ControlApiTls::bootstrap` creates and persists a self-signed ECDSA P-256
certificate when no ACME certificate exists yet. The status endpoint reports
`tls_mode` (`self_signed` or `acme`), the leaf fingerprint, and the
`control_api.tls.self_signed` warning. A `FallbackResolver` serves the
self-signed leaf until an ACME certificate is present, then switches to it on
the next handshake without a restart. When the process terminates TLS at a
reverse proxy instead, the TLS fields are omitted from status.

Covered by `src/tls.rs::status_flips_from_self_signed_to_acme`,
`handshake_serves_self_signed_then_switches_to_acme`, and
`tests/tls_bind.rs`.

## Secrets Policy

- Configuration secrets (OIDC client secret, TLS private key material) are held
  in `Secret`, which zeroizes on drop and serializes as `"redacted"`.
- Before a snapshot or audit `before`/`after` value reaches SQLite, secrets are
  masked and replaced with SHA-256 digests. Plaintext never enters the database,
  the audit log, or a query-log record.
- API tokens and session ids are stored only as SHA-256 hashes. A bearer token's
  plaintext is returned once at creation and never again.
- Internal error detail is logged but not copied into the HTTP envelope, which
  carries only the stable code and non-sensitive `params`.

No plaintext secret from config, environment, or request appears in an audit
row, query-log record, or error body; node-local error logs are out of scope.

Covered by `tests/config_store.rs::audit_redacts_secrets_and_digests`,
`tests/security.rs::security_secrets_never_leak_through_config_audit_or_errors`,
and `tests/auth_oidc.rs::client_secret_is_redacted_in_debug_and_serialized_config`.

## Stable Error-Code Contract

Every failure returns an HTTP status and a stable `area.reason` code in the
envelope `{ "error": { "code": "...", "params": { ... } } }`. Codes are
namespaced by area, for example:

| Code | Meaning |
|---|---|
| `control_api.not_found` | unknown route or resource |
| `control_api.method_not_allowed` | known path, wrong method |
| `control_api.config.invalid` | snapshot failed validation or traversal guard |
| `control_api.payload_too_large` | body exceeded 1 MiB |
| `control_api.rate_limited` | per-source rate limit |
| `control_api.not_ready` | `/readyz` module not ready |
| `control_api.auth.unauthenticated` | missing/invalid/revoked credential |
| `control_api.auth.csrf` | missing or mismatched synchronizer token |
| `control_api.auth.invalid_scope` | wrong endpoint family or insufficient scope |
| `control_api.auth.session_expired` | idle/absolute expiry or logout |
| `control_api.auth.locked` | break-glass account locked |
| `control_api.auth.oidc` | provider/token validation failure |
| `filter_store.invalid_source` | bad filter-list source |
| `filter_id.invalid_char` | invalid entity id |

Codes are stable API surface: add new codes rather than renaming existing ones.
`src/error.rs::tests::codes_are_unique_and_well_formed` asserts uniqueness and
shape.

## Security Threat-Model Tests

`tests/security.rs` consolidates the security-critical regressions:

| Threat | Test |
|---|---|
| Wildcard/public bind | `security_api_refuses_wildcard_and_public_bind_addresses` |
| API reachable via public listener | `security_public_doh_listener_serves_only_dns_query_paths` |
| API router serves DoH paths | `security_control_api_router_does_not_serve_dns_query_paths` |
| Path traversal | `security_path_traversal_is_rejected_on_every_config_path` |
| SQL injection | `security_sql_injection_is_treated_as_data` |
| CSRF bypass | `security_csrf_bypass_is_rejected_for_cookie_sessions` |
| Forwarded-header spoofing | `security_forwarded_header_spoofing_is_ignored_from_untrusted_peers` |
| Token/session replay | `security_revoked_token_and_logged_out_session_cannot_be_replayed` |
| Secret leakage | `security_secrets_never_leak_through_config_audit_or_errors` |
| Algorithm confusion | `src/api/auth/oidc.rs::alg_confusion_allow_list_is_asymmetric_only`, `tests/auth_oidc.rs::alg_none_is_rejected`, `hs256_alg_confusion_is_rejected` |

Path traversal is checked on the per-list route, the raw `PUT /config`
snapshot, the `data_dir` bootstrap field (not accepted from requests), and
route parameters. The raw-snapshot guard was added in A14 after the threat test
showed the per-list route alone could be bypassed with a hand-written snapshot.

## Storage Design

SQLite with a single-writer connection behind `Mutex`. Every database call runs
via `tokio::task::spawn_blocking` to avoid blocking the async runtime.

Migrations are idempotent and tracked via `PRAGMA user_version`. Schema:
`kv`, `config_versions`, `audit_log`, `sessions`, `tokens`, `local_accounts`,
`query_log`, `stats_hourly`, `stats_daily`.

All SQL uses bind parameters — never string interpolation. Covered by
`tests/storage.rs::sql_injection_is_treated_as_data` and
`tests/security.rs::security_sql_injection_is_treated_as_data`.

## Testing Strategy

- Injected `Clock`/`ManualClock` for every time-dependent path; no wall-clock
  sleeps.
- In-memory SQLite for storage, config, query-log, and stats tests.
- In-process mock OIDC provider and TLS connectors; tests never contact a real
  provider or the internet. All addresses are documentation ranges
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) or loopback.
- `cargo test -p dnscraft-api` runs the unit and integration suites; the
  workspace DoD adds `fmt`, `clippy -D warnings`, `cargo test --workspace`, and
  `cargo deny check`.

Line coverage for `dnscraft-api` measured with
`cargo llvm-cov -p dnscraft-api --summary-only` is **88.98 %** (functions
88.00 %, regions 88.36 %), above the 80 % bar. The workspace CI coverage job
still lists only the resolver/filtering/policy/listeners crates; adding
`dnscraft-api` there is a follow-up outside A14's scope.

## Traceability to SPEC Success Criteria

| # | Criterion (summary) | Closing tests |
|---|---|---|
| 1 | Documented `/api/v1` endpoints, status codes, error envelope | `tests/api_core.rs`, `tests/config_http.rs`, `tests/query_log.rs` (HTTP), `tests/stats_export.rs`, `tests/auth_*.rs`, `src/error.rs::codes_are_unique_and_well_formed` |
| 2 | Config PUT validates/persists/applies/increments; module failure rolls back | `tests/config_apply.rs::valid_config_applies_in_order_and_increments_version`, `policy_failure_replays_previous_snapshot_and_keeps_old_version` |
| 3 | Query log enriched with client fields; filter/order/pagination over 10 000 rows | `tests/query_log.rs::query_log_filters_order_and_pagination_over_ten_thousand_rows`, `query_log_events_are_enriched_with_client_data_and_ip_truncated` |
| 4 | "Why blocked?" includes the full decision record | `tests/query_log.rs::query_log_why_blocked_returns_the_full_decision_record` |
| 5 | OIDC with PKCE/nonce; invalid/expired ID token rejected | `tests/auth_oidc.rs::authorize_url_uses_discovery_pkce_s256_nonce_and_state`, `expired_token_is_rejected_with_auth_oidc`, `invalid_signature_is_rejected_with_auth_oidc`, `alg_none_is_rejected` |
| 6 | Break-glass login, 5-attempt/15-minute lockout, audit, Argon2id | `tests/auth_local.rs::correct_password_creates_a_cookie_session`, `lockout_after_max_attempts_unlocks_after_window_on_manual_clock`, `every_success_and_failure_is_audited_without_the_password`; `src/api/auth/local.rs` Argon2id verifier |
| 7 | Viewer vs admin; four scopes; wrong endpoint family rejected; no cross-family token | `tests/auth_token.rs::scopes_are_the_four_fixed_values`, `viewer_cannot_call_admin_route_but_admin_can`, `wrong_endpoint_family_is_rejected_with_invalid_scope`, `session_role_still_authorizes_api_and_is_enforced_by_rbac` |
| 8 | Coherent audit before/after digests; login failures audited | `tests/config_store.rs::audit_redacts_secrets_and_digests`, `audit_digest_is_over_redacted_snapshot`; `tests/auth_local.rs::every_success_and_failure_is_audited_without_the_password`, `audit_records_the_locked_attempt_too` |
| 9 | Internal-only binding; no answer on public listener ports | `src/config.rs::bind_rejects_wildcard_and_public`, `tests/security.rs::security_api_refuses_wildcard_and_public_bind_addresses`, `security_public_doh_listener_serves_only_dns_query_paths`, `security_control_api_router_does_not_serve_dns_query_paths` |
| 10 | No real provider contacted; fmt/clippy/test/deny green | In-process mock OIDC/TLS harnesses in `tests/auth_oidc.rs`, `tests/tls_bind.rs`; workspace DoD recorded for A14 |
| 11 | Self-signed served only before ACME; status mode/fingerprint; automatic switch | `src/tls.rs::status_flips_from_self_signed_to_acme`, `handshake_serves_self_signed_then_switches_to_acme`; `tests/tls_bind.rs::status_reports_tls_mode_fingerprint_and_self_signed_warning`, `bootstrap_creates_persisted_self_signed_cert` |
| 12 | NDJSON primary streaming export obeying filters/retention; CSV remains | `tests/stats_export.rs::stats_export_ndjson_streams_and_obeys_filters`, `stats_export_csv_returns_the_same_filtered_set` |
| 13 | Audit/config secrets masked; no plaintext secret in audit or query log | `tests/config_store.rs::audit_redacts_secrets_and_digests`, `tests/security.rs::security_secrets_never_leak_through_config_audit_or_errors`, `tests/auth_oidc.rs::client_secret_is_redacted_in_debug_and_serialized_config` |

## Dependencies

This crate depends on `policy` and `clients` APIs through narrow traits and on
`resolver`, `listeners`, and `tls` through read traits. Crypto is ring-only
(ADR-0002): there is no `aws-lc-rs`, `aws-lc-sys`, `openssl-sys`, or
`native-tls` in the dependency tree, enforced by `deny.toml`.

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or
[MIT license](../../LICENSE-MIT) at your option.
