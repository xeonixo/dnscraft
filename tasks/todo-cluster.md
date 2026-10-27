# Todo: cluster

> Contract & ordering: [plan-cluster.md](plan-cluster.md). Spec:
> [SPEC-cluster.md](../SPEC-cluster.md) · [SPEC-control-api.md](../SPEC-control-api.md).
> Tick items only when the owning crate's focused check passes. One commit per task, `Co-Authored-By`
> line, add a Log entry in `tasks/progress.md`.

## Phase 0 — Spec & contract (docs only)

- [x] CL0 `SPEC-cluster.md`: resolve § Open questions (recommendations; Q6 = auth-snapshot YES),
      align § "Required control-api additions" with the actual control-api state; status DRAFT→ready.
- [x] CL1 `SPEC-control-api.md`: concrete shapes for `/api/v1/cluster/join-tokens|nodes|nodes/{id}|writes/{request_id}`
      + `/cluster/v1/enroll|stream|logs|writes|heartbeat` schemas + internal hook signatures +
      status/stats `node_id` fields; resolve `409 config.version` vs `412 config.conflict` (keep shipped code).

## Phase 1 — control-api hooks + admin endpoints + data model

- [x] CL2 `apply_synced_config(snapshot, version)` + store method for explicit version (schema change
      to `config_versions` / replicated-origin column); adopt master version without local bump.
- [x] CL3a `auth_snapshot()` (hashes + non-secret OIDC + session epoch) + make
      `requirement`/`authorize` public for the master RBAC re-check.
- [x] CL3b `apply_runtime_command(kind, payload)` (pause/resume, temporary allow).
- [x] CL4 query-log outbox: `seq` + outbox/ack table, transactional enqueue in `QueryLog::insert_batch`.
- [x] CL5 stats `node_id` dimension in `stats_hourly`/`stats_daily` (migration + rollup SQL + `RollupRow`)
      + `node_id` filter on query-log/stats.
- [ ] CL6 `GET /api/v1/status` cluster fields (role, master reachability, applied version, lag,
      queue depth, last sync).
- [ ] CL7 admin endpoints `/api/v1/cluster/*` (admin-only, shapes from CL1).
- [x] CL8 `cluster.*` error codes + uniqueness test; reconcile `config.version`/`config.conflict`.

## Phase 2 — Cluster crate: transport + identity + join

- [x] CL9 cluster config validation (`role`/`node_id`/`master_url`/bind; non-private bind rejected).
- [x] CL10 master: cluster CA gen (`0600`), join-token mint/hash (TTL, one-time), node registry
       (fingerprint, joined_at, last_seen, applied_config_version, revoke). Enroll endpoint → CL12.
- [x] CL11 sub-node: key+CSR (`rcgen`), enroll, CA+node cert (in-process). mTLS connection → CL12.
- [x] CL12 transport: TLS 1.3 ring-only, HTTP/2, `GET /cluster/v1/stream` NDJSON, heartbeat, version
       handshake; separate mTLS listener (own bind/port), mTLS chain + fingerprint + revoke check.

## Phase 3 — Config sync

- [x] CL13 snapshot push `ConfigPush {version, sha256, snapshot}` on apply/rollback; digest check;
       ack; lag tracking; retry/backoff (never partial).
- [x] CL14 reconnect `Hello {last_applied_version, last_acked_log_seq}` + reconciliation (master-wins).
- [ ] CL15 sub-node apply via `apply_synced_config` (leaf-first); failure → rollback + keep answering
       + `cluster.config.apply`; node-scoped policy views filtered.

## Phase 4 — Write relay + offline queue + runtime broadcast

- [x] CL16 live relay (`WriteRelay` + master RBAC re-check + audit `node_id` + idempotency, no role escalation).
- [ ] CL17 offline queue (SQLite, FIFO, `202`/`400`/`503`, replay conflict + head-of-line blocking, expiry).
- [x] CL18 runtime broadcast (pause/resume, temporary allow) cluster-wide; master-only ops never queued offline.

## Phase 5 — Log aggregation + stats

- [ ] CL19 log outbox streaming + contiguous ack + dedupe `(node_id, record_id)`+`(node_id, seq)`.
- [ ] CL20 backfill from `last_acked_log_seq` + gap counting + buffer retention.
- [ ] CL21 stats node_id rollups + per-node breakdown + sub-node read model (local offline).

## Phase 6 — TLS cert push + auth snapshot + quotas/skew

- [ ] CL22 `CertPush {chain, key}` → `CertResolver::import` hot-reload; no ACME while master known.
- [ ] CL23 `AuthSnapshot` replication (encrypted) + session-invalidation epoch.
- [ ] CL24 quotas (relay/log/queue) + clock-skew warning.

## Phase 7 — Hardening, fault injection, fuzz, docs, traceability

- [ ] CL25 security suite (threat model) + complete fault-injection matrix.
- [ ] CL26 fuzz targets (`join_token`, `log_batch`) + README + `CAPABILITY-MAP.md` row +
       SPEC success-criteria traceability + final gates.

## Checkpoints

- [ ] Checkpoint 0 — Phase 0 spec reconciliation owner-approved.
- [ ] Checkpoint 1 — control-api hooks/admin/data-model green (`cargo test -p dnscraft-api`).
- [x] Checkpoint 2 — join + mTLS transport (loopback, happy path + wrong-CA/missing/unregistered/revoked).
- [ ] Checkpoint 3 — config sync converges under partition.
- [ ] Checkpoint 4 — relay exactly-once; queue survives restart; no role escalation.
- [ ] Checkpoint 5 — dedupe/backfill/gap; stats node_id.
- [ ] Checkpoint 6 — cert push + offline token auth + quotas.
- [ ] Checkpoint F — independent security review + owner approval + archive.

Final gates: `cargo fmt --check` · `clippy --workspace --all-targets --locked -- -D warnings` ·
`cargo test --workspace` · `cargo deny check` · `cargo tree -i aws-lc-rs|aws-lc-sys|openssl-sys|native-tls` empty.
