# Plan: cluster

> Module id `cluster` · crate `crates/dnscraft-cluster` · depends on: `control-api`
> Spec: [SPEC-cluster.md](../SPEC-cluster.md) (DRAFT) · [SPEC-control-api.md](../SPEC-control-api.md)
> Status: owner-approved 2026-10-27. Tasks: [todo-cluster.md](todo-cluster.md).

## Context

One central master node + several sub-nodes form a self-hosted resolver fleet. The master sees
everything (query-log/statistics aggregation) and controls everything (sole config writer). A full
mesh ("everything everywhere") was rejected as too expensive. Priority is security.

`SPEC-cluster.md` (DRAFT, 867 lines) already captures this vision and is adopted as the spec:
**hub-and-spoke, one master, mTLS with a dedicated cluster CA + per-node certificate, full-snapshot
config sync (`config_version`/`If-Match`), write relay + durable offline queue, log/statistics
aggregation on the master.** No multi-master/quorum in v1.

**Research confirmation (external):** Technitium DNS v14 (single-primary/multiple-secondary, REST
sync), `secure_dns` (mTLS + per-node certs), terrapod (backfill/catch-up), datum-cloud/dns-operator
(Replicator + downstream agent). The spec matches established practice — no architectural rework.

**Owner decisions (locked):** (Q6) **auth-snapshot replication = YES** (sub-nodes authenticate bearer
tokens offline). All other open questions follow the spec recommendation: single master without
failover, offline conflict = reject-and-retry (head-of-line blocking), durable SQLite offline queue,
cluster-wide runtime broadcast, expired cert keeps serving + loud warning, clock-skew warning > 5 min,
no multi-entry.

## Current state (code reality-check, 2026-10-27)

- `crates/dnscraft-cluster` implemented (CL9–CL24): config validation, CA/join/identity/store,
  mTLS transport, full-snapshot sync, write relay + offline queue, runtime broadcast, log
  streaming/backfill, cert/auth push, quotas/skew, with loopback integration suites. CL26 added the
  `cluster_join_token` / `cluster_log_batch` / `cluster_config` fuzz targets, the crate README and
  the success-criteria traceability. **Remaining:** CL6/CL7 (control-api admin routes + status
  fields), CL15 (sub-node apply/TLS/auth-snapshot/DNS wiring), CL25 (security suite), Checkpoint F.
- `control-api` (`dnscraft-api`) COMPLETE (A0–A14, Checkpoint F owner-approved). Already provides:
  - Atomic apply path: `ConfigService` (`config_apply.rs:107`; `replace`/`mutate`/`mutate_unrecorded`/
    `rollback` under a serial `apply_lock`; `APPLY_ORDER` = filtering→clients→policy→listeners→tls).
  - Audit: `AuditRecord` (`storage/audit.rs:10`) already has `node_id`, `actor_id`, `actor_type`,
    `config_version`, before/after digests.
  - Query-log: `query_log` table already has a `node_id` column (v5); `QueryLogSink`/`insert_batch`.
  - Stats: `stats_hourly`/`stats_daily` + `run_rollup` — **no** `node_id` dimension.
  - RBAC: `Scope` (`viewer`/`admin`/`mcp:read`/`mcp:write`), `rbac_middleware`, `TokenStore` — but
    `requirement`/`authorize`/`is_config_path` are private (no public re-check).
  - TLS: `CertResolver::import` (`dnscraft-tls/src/resolver.rs:99`) already exists and its docstring
    says *"Intended for a future cluster push of cert+key to sub-nodes"*.
- **Contradictions Phase 0 must resolve:**
  1. Code returns **`409 control_api.config.version`** (`error.rs:66`, `response.rs:69`);
     `SPEC-control-api.md:660` and `SPEC-cluster.md` write **`412 control_api.config.conflict`**;
     `config.conflict` does not exist in code. Default: keep the shipped code
     (`409 control_api.config.version`) and align the specs; the RFC-7232-correct `412` is the
     alternative — confirm at Checkpoint 0.
  2. `apply_synced_config` is missing; the store auto-increments `version INTEGER PRIMARY KEY
     AUTOINCREMENT`, so adopting a master version verbatim needs a schema decision.

## Dependency graph

```
Phase 0  Spec/contract reconciliation (SPEC-cluster.md + SPEC-control-api.md; 409/412 decision)
   │
   ▼
Phase 1  control-api hooks + admin endpoints + data model
   ▼
Phase 2  cluster crate: transport + identity + join
   ▼
Phase 3  config sync (master → sub)
   ▼
Phase 4  write relay + offline queue + runtime broadcast (sub → master)
   ▼
Phase 5  log aggregation + stats
   ▼
Phase 6  TLS cert push + auth snapshot + quotas/skew
   ▼
Phase 7  hardening + fault injection + fuzz + docs + traceability → Checkpoint F
```

Each phase is a **vertical slice** (one complete master↔sub path), not a horizontal layer.

## Phases (vertical slices with checkpoints)

### Phase 0 — Spec & contract (docs only)
Resolve `SPEC-cluster.md` open questions (recommendations; Q6 = auth snapshot); align § "Required
control-api additions" with the actual state. Extend `SPEC-control-api.md` with concrete
request/response shapes for `POST /api/v1/cluster/join-tokens`, `GET /api/v1/cluster/nodes`,
`DELETE /api/v1/cluster/nodes/{id}`, `GET /api/v1/cluster/writes/{request_id}`; the transport route
schema (`POST /cluster/v1/enroll|logs|writes|heartbeat`, `GET /cluster/v1/stream` NDJSON); internal
hook signatures; status/stats `node_id` fields; and the `409`/`config.version` vs
`412`/`config.conflict` reconciliation. **STOP: Checkpoint 0** (owner approval).

### Phase 1 — control-api hooks + admin endpoints + data model
`apply_synced_config` + explicit-version store (schema); `auth_snapshot()` (encrypted) +
`apply_runtime_command()` + public RBAC re-check; query-log outbox (`seq` + outbox/ack table,
transactional enqueue in `insert_batch`); stats `node_id` dimension + `node_id` filter; status
cluster fields; `/api/v1/cluster/*` admin endpoints (admin-only); `cluster.*` error codes +
uniqueness. **STOP: Checkpoint 1**.

### Phase 2 — Cluster crate: transport + identity + join
Config validation (`role`/`node_id`/`master_url`/bind; non-private bind rejected). Master: CA gen
(`0600`), join-token mint/hash (TTL, one-time), enroll endpoint, node registry (fingerprint,
`joined_at`, `last_seen`, `applied_config_version`, revoke). Sub-node: key+CSR (`rcgen`), enroll,
mTLS connection. Transport: TLS 1.3 ring-only, HTTP/2, NDJSON stream, heartbeat, version handshake;
second internal mTLS listener via `nest_service` (mirror of `router.rs:184`). **STOP: Checkpoint 2**.

### Phase 3 — Config sync
Snapshot push (`ConfigPush {version, sha256, snapshot}`) on every apply/rollback; digest check; ack;
lag tracking; retry/backoff (never a partial snapshot). Reconnect `Hello {last_applied_version,
last_acked_log_seq}`; master-wins on divergence. Sub-node applies via `apply_synced_config`
(leaf-first); failure → rollback to previous version, keeps answering, `cluster.config.apply`.
Node-scoped policy views filtered; `mcp_rules` travels in the snapshot. **STOP: Checkpoint 3**.

### Phase 4 — Write relay + offline queue + runtime broadcast
Live relay (local auth → `WriteRelay {request_id, idempotency_key, if_match, method, path, body,
actor}`; master re-checks RBAC, no role escalation, canonical handler, audit with `node_id`).
Offline queue (opt-in, SQLite, FIFO; `202`/`400`/`503`; replay conflict + head-of-line blocking;
expiry). Runtime broadcast (pause/resume, temporary allow) cluster-wide; master-only ops never queued
offline. **STOP: Checkpoint 4**.

### Phase 5 — Log aggregation + stats
Outbox (transactional, `seq`), batches, contiguous ack, dedupe `(node_id, record_id)`+`(node_id,
seq)`, backfill from `last_acked_log_seq`, gap counting, buffer retention. Stats node_id rollups +
per-node breakdown; sub-node serves local view offline, never claims cluster-wide. **STOP:
Checkpoint 5**.

### Phase 6 — TLS cert push + auth snapshot + quotas/skew
`CertPush {chain, key}` → `CertResolver::import` hot-reload; sub-node never starts ACME while a
master is known. `AuthSnapshot` (encrypted) replication (owner: YES); session-invalidation epoch.
Quotas (relay/log/queue), clock-skew warning. **STOP: Checkpoint 6**.

### Phase 7 — Hardening, fault injection, fuzz, docs, traceability
Security suite (threat model), complete fault injection, fuzz targets (`cluster_join_token`,
`cluster_log_batch`, `cluster_config`), README, `CAPABILITY-MAP.md` row, SPEC success-criteria
traceability in `tasks/progress.md`, `cargo deny` + ring-only trees.
**STOP: Checkpoint F** (independent security review + owner approval + archive).

## Reuse (existing code)

- Atomic apply path + serial lock: `ConfigService` (`config_apply.rs:107`),
  `replace`/`mutate`/`mutate_unrecorded`/`rollback` (`:173/:219/:267/:351`).
- Audit: `AuditRecord` already has the required fields (`storage/audit.rs:10`); the write entry point
  is `ConfigChangeRecord` (`audit.rs:277`).
- Query-log: `QueryLog::insert_batch` (`query_log.rs:286`) + `query_log.node_id` (v5) — outbox/`seq`
  attach here transactionally.
- Stats: `run_rollup` (`stats.rs:257`) + `RollupRow` (`:100`) — add `node_id`.
- RBAC: `Scope` (`api/auth/roles.rs:48`), `TokenStore::authenticate` (`tokens.rs:189`),
  `rbac_middleware` (`roles.rs:258`); make `requirement`/`authorize` (`:166/:226`) public for the
  master re-check.
- Error codes: `ControlApiError::code()` + `codes_are_unique_and_well_formed` (`error.rs:199/:263`).
- TLS: `CertResolver::import` (`dnscraft-tls/src/resolver.rs:99`) for `CertPush`;
  `TlsEngine::upload_manual_cert` (`engine.rs:351`); `rcgen` + rustls `ring` (ADR-0002).
- `Clock`/`ManualClock`/`wait_until` (ADR-0005) for all time-based tests.

## Critical files (representative)

- New: `crates/dnscraft-cluster/` (config, ca/join, transport, registry, sync, relay, offline-queue,
  log-stream, cert-push, auth-snapshot, error).
- Change: `crates/dnscraft-api/src/{config_apply.rs, error.rs, server.rs, config.rs, lib.rs,
  storage/{db.rs, migrations.rs}, api/{router.rs, roles.rs, cluster_endpoints.rs}}`,
  `crates/dnscraft-api/tests/*`.
- Change (expose entry point only): `crates/dnscraft-api/src/tls.rs` (`upload_manual_cert` stub).
- Docs: `SPEC-control-api.md`, `SPEC-cluster.md`, `CAPABILITY-MAP.md`, `README.md`, `deny.toml`
  (goal: no new external deps — `rcgen`/`rustls`/SQLite already present).

## Verification (end-to-end)

1. Loopback fleet test: master + 3 sub-nodes on `127.0.0.1:0`, test CA, `ManualClock`.
2. Full matrix of the SPEC-cluster testing strategy (unit, transport, fault-injection, integration
   flows; no wall-clock waits; no real network).
3. Gates (Phase 7) plus a mutation probe per new hook (revert → test red → restore).
4. No test contacts the internet / ACME / Cloudflare / Authentik.
