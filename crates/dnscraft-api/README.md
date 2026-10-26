# dnscraft-api

Control API for DNScraft: HTTP REST API, configuration persistence, query log,
statistics, audit trail, and authentication (OIDC + local break-glass login + API
tokens). This crate is the internal-only configuration boundary for the web UI
and the later `mcp` module.

Formal requirements: [`SPEC-control-api.md`](../../SPEC-control-api.md).
Plan / remaining tasks: [`tasks/todo-control-api.md`](../../tasks/todo-control-api.md).

## Status

**A0 complete** (crate skeleton, config model, error type).
**A1 complete** (SQLite storage, migrations, kv store, audit log).
**A2 complete** (config snapshot/version store + audit secret redaction).
**Next: A3** (HTTP server core — router, envelopes, pagination).

See `tasks/todo-control-api.md` for the full task list.

## What This Crate Does

- **Configuration persistence**: Stores typed configuration for policy views/
  profiles, clients, filter lists, UniFi settings, listeners, TLS, and auth
  settings in SQLite
- **Query log storage**: Records every DNS query with filterable metadata
  (device, VLAN, action, timestamp, latency)
- **Statistics aggregation**: Computes dashboard metrics (queries/sec, cache
  hit rate, top domains, block rate)
- **Audit log**: Records every mutating action with actor, timestamp, and
  redacted old/new values
- **Authentication**: OIDC via Authentik, local break-glass login, API bearer
  tokens with roles (viewer/admin)
- **HTTP API**: REST endpoints under `/api/v1/` with locale-neutral error codes
  (`area.reason`) for the web UI

This crate does **not** decide which DNS answers are produced — it calls
`policy`, `clients`, `listeners`, `resolver` and `tls` APIs and persists their
configuration. It never serves public DNS traffic; it binds to an internal-only
address (default `127.0.0.1:8080`).

## Storage Design

SQLite with a single-writer connection behind `Mutex`. Every database call runs
via `tokio::task::spawn_blocking` to avoid blocking the async runtime.

Migrations are idempotent and tracked via `PRAGMA user_version`:

- **A1**: full schema — `kv`, `config_versions`, `audit_log`, `sessions`,
  `tokens`, `query_log`, `stats_hourly`, `stats_daily`
- **A2**: `ConfigStore` (versioned snapshots) and audit `before`/`after`
  redaction (SHA-256 digests, secrets masked before they reach SQLite)
- **A12**: `query_log` accessors, retention and export (table exists)
- **A13**: `stats_*` aggregation (tables exist; rollups later)

All SQL uses bind parameters — never string interpolation. See the
`sql_injection_is_treated_as_data` test for verification.

## API Surface (A0–A2)

```rust
use dnscraft_api::{Audit, ConfigChangeRecord, ConfigStore, Db};
use serde_json::json;

// 1. Open a database (idempotent migrations applied on open).
let db = Db::open_in_memory().await?;

// 2. Store a config snapshot; secrets are redacted before persist.
let store = ConfigStore::new(db.clone());
let version = store
    .store(&json!({
        "auth": { "oidc_client_secret": "s3cr3t", "issuer": "https://auth.example.net" }
    }))
    .await?;

// 3. Load it back (secrets come back as "redacted").
let snapshot = store.load(version).await?;

// 4. Record an audit row; before/after are redacted + SHA-256 digested.
let audit = Audit::new(db.clone());
let id = audit
    .record_config_change(ConfigChangeRecord {
        time: 1_730_000_000,
        node_id: "node1".into(),
        actor_id: "admin".into(),
        actor_type: "user".into(),
        config_version: Some(version),
        before: None,
        after: Some(json!({ "auth": { "oidc_client_secret": "s3cr3t" } })),
        result: "ok".into(),
        error_code: None,
    })
    .await?;
```

The HTTP server and auth flow are implemented in later tasks (A3+).

## Tests

```bash
cargo test -p dnscraft-api
```

Integration tests cover:
- Config validation (bind address, rate limits, retention bounds)
- SQLite migrations (idempotent, version tracking)
- Key-value round-trips
- Config snapshot versioning + secret redaction (plaintext never reaches SQLite)
- Audit log ordering, digesting, and redaction
- SQL injection prevention (`sql_injection_is_treated_as_data`)
- Error code stability (every error variant has a unique `code()`)

## Dependencies

This crate depends on `policy` and `clients` APIs (trait imports only; no Cargo
dependency yet). It reads `resolver`, `listeners` and `tls` state through narrow
read traits.

The web UI (`web-ui`) and MCP server (`mcp`) will consume this crate's API.

## Internal-Only Binding

The control API is **never** served on public DNS listeners. It binds to an
internal-only address (default `127.0.0.1:8080`). The config validator enforces
this: binding to `0.0.0.0` or `::` is rejected unless explicitly allowed in a
later feature flag for trusted networks.

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or
[MIT license](../../LICENSE-MIT) at your option.
