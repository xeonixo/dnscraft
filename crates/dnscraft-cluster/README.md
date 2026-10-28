# dnscraft-cluster

Master/sub-node cluster for DNScraft: one `master` plus zero or more
`sub_node`s form a resolver fleet. The master is the sole configuration
writer, the CA and join-token owner, and the aggregation point for query logs
and statistics. Sub-nodes answer DNS from the last applied snapshot, relay
writes to the master, buffer keyed writes while it is unreachable, and stream
local query logs back once it returns.

The crate owns the cluster protocol and state machine only. It does not depend
on `dnscraft-api` or any other DNScraft module except `dnscraft-common`: the
control API implements the hooks in [`src/sync.rs`](src/sync.rs),
[`src/relay.rs`](src/relay.rs) and [`src/log.rs`](src/log.rs) and mounts
[`ClusterServer`] on its own internal listener. DNS answering never waits on
the master.

**Status:** the crate is implemented and tested in isolation. The
control-api admin routes/status fields (CL6/CL7), the sub-node apply + TLS +
auth-snapshot wiring (CL15) and the assembler remain. See
[`SPEC-cluster.md`](../../SPEC-cluster.md) for the authoritative contract.

## Module layout

```text
src/
├── lib.rs       public re-exports
├── ca.rs        dedicated cluster CA (load/generate, `0600` key) + fingerprints
├── config.rs    `[cluster]` bootstrap config types and role/bind/URL validation
├── enroll.rs    enroll request/response wire shape + master-side enrollment
├── error.rs     `ClusterError` and the stable `cluster.*` codes
├── identity.rs  sub-node key + CSR generation and durable cert/key storage
├── store.rs     SQLite node registry: join tokens, fingerprints, revoke, applied version
├── server.rs    master mTLS HTTP/2 listener (enroll, stream, logs, writes, heartbeat)
├── client.rs    sub-node outbound mTLS client and NDJSON stream reader
├── sync.rs      stream records, snapshot push/ack/lag/retry, cert + auth push
├── relay.rs     write relay and volatile runtime-command broadcast
├── offline.rs   durable FIFO offline write queue with conflict/expiry semantics
├── log.rs       log batch validation, outbox streaming, contiguous ack, backfill
└── quota.rs     per-node relay/log/queue quotas and clock-skew detection
```

## Public API

Server (master side):

| Item | Purpose |
|---|---|
| `ClusterServer`, `ClusterServerConfig` | mTLS listener; start/shutdown, address, CA/leaf PEM accessors |
| `HeartbeatRequest`, `HeartbeatResponse`, `StatusWarning` | heartbeat and status warnings (stale config, queue depth, clock skew) |
| `ClusterCa` | load-or-generate the cluster CA; `cert_fingerprint` hashes a DER leaf |
| `ClusterStore`, `ClusterNode`, `MintedJoinToken` | node registry, one-time token mint/redeem, revoke, applied version |
| `enroll`, `EnrollRequest`, `EnrollResponse`, `PROTOCOL_VERSION` | in-process enrollment protocol and wire shape |
| `ConfigSync` | publish snapshots, track per-node lag and acks |
| `QuotaConfig` (via `ClusterConfig`) + quota state in the server | per-node rate and byte limits |

Client (sub-node side):

| Item | Purpose |
|---|---|
| `ClusterClient`, `ClusterStream` | outbound mTLS client; stream open/poll, log post, heartbeat, write relay, certificate renewal (`renew_if_due`) |
| `PendingNodeIdentity`, `NodeIdentity` | generate key + CSR, persist/load the issued cert and key |
| `OfflineWriteQueue` | enqueue/replay/status of buffered keyed writes |
| `LogStreamer`, `Backfill` | batch contiguous outbox rows, resume after an outage |

Records (the wire shapes):

| Item | Purpose |
|---|---|
| `Hello`, `ConfigPush`, `ConfigAck`, `CertPush`, `AuthSnapshotPush`, `StreamRecord`, `StreamError` | downstream NDJSON stream records |
| `LogBatch`, `LogRecord`, `LogAck` | log uploads and the contiguous acknowledgement |
| `WriteRelay`, `RelayedActor`, `RelayResponse`, `RuntimeCommand` | forwarded writes and volatile runtime commands |
| `NodeLag`, `canonical_snapshot_bytes`, `snapshot_digest` | lag tracking and the snapshot SHA-256 |

Traits implemented by the caller:

| Trait | Implemented by | Contract |
|---|---|---|
| `ConfigApplier` | control-api (CL15) | apply a full snapshot atomically; rollback on failure |
| `CertInstaller` | tls/assembler | install a pushed chain + key without restart; never order ACME while a master is known |
| `AuthSnapshotApplier` | control-api | apply the replicated token/session epoch |
| `WriteExecutor` | control-api | re-check RBAC, run the canonical write handler, audit with `node_id` |
| `RuntimeCommandApplier` | control-api | apply pause/resume and temporary allow locally |
| `LogOutbox` | query-log store | persist `seq`/ack cursor; return contiguous rows |
| `LogIngest` | query-log store | deduplicate `(node_id, record_id)` and `(node_id, seq)`; return the contiguous ack |

## Security model

- **Dedicated cluster CA, not the ACME certificate.** The public wildcard
  certificate is identical on every node, so it proves membership but not node
  identity. Each node instead gets a certificate from the cluster CA, with
  `node_id` as its DNS SAN and Common Name.
- **`node_id` comes from the certificate, never the payload.** Every protected
  request reads the SAN, looks the node up in the registry and requires the
  stored SHA-256 fingerprint to equal the presented certificate's fingerprint.
  Payload `node_id` values are rejected when they differ (for example in
  `LogBatch::validate`).
- **Revocation and one-time join.** Join tokens are bound to the intended
  `node_id`, short-lived and stored only as hashes; redemption is one-time and
  atomic with node registration. A revoked node or an unregistered fingerprint
  is refused before any route runs (`cluster.node.revoked` /
  `cluster.node.unknown`).
- **Bootstrap pinning.** Before enrollment the sub-node pins the master's
  bootstrap certificate fingerprint; the control-api self-signed certificate is
  never accepted silently. After enrollment the cluster CA is authoritative.
- **Transport.** TLS 1.3 only, rustls with the `ring` provider, mandatory
  client certificates on both sides, HTTP/2, no plaintext fallback. The cluster
  listener must bind to loopback or a private/ULA address; `0.0.0.0` and `::`
  are rejected at config validation.
- **Outbound-only sub-nodes.** Every session and upload is initiated by the
  sub-node. The master never opens a connection to a sub-node.
- **Secrets.** Join tokens and node private keys travel only over the mTLS
  channel. The CA key is written with mode `0600` and is never exported;
  `Secret` redacts tokens and keys from `Debug`; audit and query-log bodies are
  never logged by this crate.
- **No privilege escalation.** The relay forwards the authenticated
  `RelayedActor` unchanged and the master re-checks RBAC and executes the
  canonical handler itself; a sub-node cannot mint tokens, manage accounts or
  assert a higher role.

## Configuration

Node-local bootstrap only. These keys are **never** part of the replicated
snapshot; secrets come from the environment or `*_FILE`, not this file.

```toml
[cluster]
role = "standalone"                  # standalone | master | sub_node
node_id = ""                         # required for master/sub_node: 1-63 chars, [a-z0-9-]
# master_url = "https://master.dns.example.com:8443"   # required for sub_node; forbidden otherwise

[cluster.listen]                     # master only
bind = "192.0.2.10"                  # loopback or private/ULA only; never 0.0.0.0/::
port = 8443

[cluster.join]                       # master only
token_ttl = "15m"
node_cert_ttl = "90d"

[cluster.timing]
heartbeat_interval = "10s"
master_timeout = "5s"
config_apply_timeout = "30s"
reconnect_backoff = "1s"
reconnect_backoff_max = "60s"

[cluster.offline_writes]
enabled = true
queue_max_entries = 100              # 1-10000
max_age = "24h"                      # requires Idempotency-Key + If-Match

[cluster.log]
buffer_retention = "24h"             # must not exceed the master query-log retention
batch_max_records = 500              # 50-5000
batch_interval = "1s"                # 100ms-10s
max_batch_bytes = "1MiB"             # 64KiB-16MiB
max_inflight_batches = 4             # 1-16

[cluster.quota]                      # per-node, enforced on the master
max_relay_requests_per_second = 50   # 1-1000
max_log_bytes_per_second = "2MiB"    # 64KiB/s-64MiB/s
max_queued_offline_writes = 100      # <= offline_writes.queue_max_entries
clock_skew_warning = "5m"            # 30s-1h

[cluster.tls]
ca_cert = "data/cluster/ca.pem"
node_cert = "data/cluster/node.pem"
node_key = "data/cluster/node.key"   # prefer env / *_FILE in deployed configurations
```

`ClusterConfig::from_toml` parses the document and runs `validate`, which
enforces role consistency: `standalone` forbids `listen` and `master_url`;
`master` requires `listen` + `node_id` and forbids `master_url`; `sub_node`
requires `master_url` + `node_id` and forbids `listen`. `master_url` must be
`https://`. Durations accept `ms`/`s`/`m`/`h`/`d`; sizes accept
`KiB`/`MiB`/`GiB`.

## Error codes

Failures use the control-api envelope with a stable, locale-neutral
`cluster.<area>.<reason>` code. Codes owned by other modules are forwarded
unchanged (for example `control_api.config.version`,
`control_api.auth.insufficient_scope`).

| Code | When / HTTP |
|---|---|
| `cluster.internal` | Backend failure (filesystem, rcgen, SQLite) with no more specific code |
| `cluster.quota.exceeded` | A node exceeded one of its rate limits (`[cluster.quota]`, heartbeat, connection cap) or enroll attempts were rate-limited; `429` |
| `cluster.role.invalid` | Role/config mismatch (for example a sub-node without `master_url`) at startup; `500`/startup error |
| `cluster.master_unavailable` | A sub-node cannot reach the master for an operation that cannot be buffered; `503` |
| `cluster.master_conflict` | A second master or a node ahead of the master is detected; connection refused |
| `cluster.node.unknown` | `node_id`/certificate fingerprint not registered on the master |
| `cluster.node.revoked` | Revoked node identity; connection refused (`403` for API calls) |
| `cluster.node.already_joined` | `node_id` is already registered |
| `cluster.join.token_invalid` | Join token unknown, already used, or bound to another `node_id` |
| `cluster.join.token_expired` | Join token past its TTL |
| `cluster.transport.tls` | mTLS handshake or certificate validation failure |
| `cluster.protocol.version` | Unsupported cluster protocol version |
| `cluster.config.apply` | Sub-node failed to apply a pushed snapshot; stays on the previous version |
| `cluster.config.stale` | Applied version behind the master beyond the threshold (status warning) |
| `cluster.write_relay_failed` | Forwarded write transport failed before a master response; `503` |
| `cluster.offline_write_requires_idempotency` | Offline buffering requested without `Idempotency-Key` or `If-Match`; `400` |
| `cluster.offline_write_queue_full` | Offline queue cap reached; `503` |
| `cluster.offline_write_conflict` | Buffered write returned `409` on replay and was not applied |
| `cluster.offline_write_expired` | Buffered write exceeded `max_age` and was dropped |
| `cluster.log_stream.invalid` | Malformed, oversized, out-of-order or `node_id`-mismatched log batch |
| `cluster.log_buffer_dropped` | Sub-node dropped buffered log rows (status count) |
| `cluster.log_gap` | Master received a batch after a sequence gap (status count) |
| `cluster.runtime_command.failed` | Node failed to apply a broadcast runtime command |
| `cluster.cert_push.failed` | Sub-node failed to install a pushed certificate/key |
| `cluster.clock_skew` | Node clock skew above the threshold (status warning) |

With `role = "standalone"` the cluster routes do not exist and return
`404 control_api.not_found`; there is no separate "cluster disabled" code.

## Tests and fuzzing

- Unit tests per module, plus loopback integration suites under
  `tests/`: `join.rs` (enroll, mTLS rejections, stream hello, heartbeat, certificate renewal),
  `sync.rs` (push/apply/ack, digest mismatch, reconnect, cert/auth push),
  `relay.rs` (verbatim relay, retries, runtime broadcast), `logs.rs` (ordered
  ack, dedupe, backfill, gap) and `quota.rs` (relay/log/heartbeat/enroll floods,
  connection cap, clock skew, queue depth, stale config, master conflict).
- All network tests use `127.0.0.1:0` and a generated test CA; all time-based
  tests use `ManualClock` with no wall-clock waits and no internet.
- Fuzz targets live in [`fuzz/`](../../fuzz): `cluster_join_token`,
  `cluster_log_batch` and `cluster_config`.

```bash
cargo test -p dnscraft-cluster
cargo clippy -p dnscraft-cluster --all-targets -- -D warnings
cargo fmt -p dnscraft-cluster --check
```
