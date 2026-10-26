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
**Next: A2** (config snapshot/version store with secret redaction).

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

Migrations are idempotent and tracked via `PRAGMA user_version`. The schema is
refined incrementally:

- **A1**: `kv` table (key-value store) and `audit` table (append-only log)
- **A2**: `config_versions` table (config snapshots with secret redaction)
- **A12**: `query_log` full schema (currently placeholder)
- **A13**: `stats_rollups` (aggregated metrics)

All SQL uses bind parameters — never string interpolation. See the
`sql_injection_is_treated_as_data` test for verification.

## API Surface (A0, A1)

```rust
use dnscraft_api::{ControlApiConfig, Db, AuditRecord};

// 1. Load config (validate bind address, rate limits, retention)
let config = ControlApiConfig::from_toml_str(toml_str)?;

// 2. Open database (idempotent migrations applied on open)
let db = Db::open("path/to/control.db").await?;

// 3. Key-value store (versioned config snapshots later in A2)
db.kv_set("some_key", b"some_value").await?;
let val = db.kv_get("some_key").await?;

// 4. Audit log (append-only, ordered by timestamp)
db.audit_append(AuditRecord {
    timestamp: 1730000000,
    actor: "admin".into(),
    action: "config.update".into(),
    // ... resource, old_value, new_value
}).await?;
let records = db.audit_list_since(since_ts).await?;
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
- Audit log ordering and filtering
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
