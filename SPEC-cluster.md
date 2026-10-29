# Spec: cluster

> Module id `cluster` · crate `crates/dnscraft-cluster` · depends on: `control-api`
> Project-wide decisions: [SPEC.md](SPEC.md)
> Status: **APPROVED — owner approved at Checkpoint 0 (2026-10-27); implementation complete (CL0–CL26)**

## Objective

Let one DNScraft master and several sub-nodes act as one self-hosted resolver
fleet: the master is the single writer of configuration and the aggregation
point for query logs and statistics; sub-nodes answer DNS from the last
configuration they received, accept writes from the UI/API and relay them to the
master, buffer work when the master is unreachable, and stream local query logs
back once it returns. The cluster must never make DNS answering depend on the
master being up, and it must never silently lose or reorder an administrative
write.

### Scope

- Two roles: `master` (exactly one in v1) and `sub_node` (zero or more). A node
  without a cluster is `standalone`.
- Hub-and-spoke topology: every sub-node connects **outbound** to the master; the
  master never opens a connection to a sub-node.
- Mutual TLS with a dedicated cluster CA and one certificate per node; node
  identity (`node_id`) is bound to the certificate, not to a shared secret.
- Configuration replication: master → sub-nodes, full snapshots, versioned with
  the existing `config_version` / `If-Match` mechanism.
- Write relay: sub-node → master, reusing the canonical `/api/v1` write surface;
  durable offline queue with conflict detection.
- Query-log streaming and backfill: sub-node → master, per-node ordered,
  deduplicated; statistics aggregation on the master.
- Distribution of TLS certificate + private key from the master (ACME owner) to
  sub-nodes, as required by [SPEC-tls.md](SPEC-tls.md) § Multi-node.
- Runtime-only state (filter-set pause/resume, temporary allows) is broadcast
  from the master so all nodes behave identically (see § Writes from any node).

### Non-goals

- No multi-master, no consensus/quorum, no automatic leader election or failover
  in v1 (single master; see § Decisions).
- No full mesh, no node-to-node traffic between sub-nodes, no cross-node query
  forwarding. Each sub-node answers DNS locally from its last applied config.
- No automatic node discovery (static `master_url` in v1; see § Decisions).
- No replication of the resolver cache, in-flight queries, sessions, or live
  connection state.
- No geo-distributed/multi-entry-node topology (deferred from SPEC-tls.md).
- Not a general database replication layer: only the explicit state listed here
  crosses the cluster channel.

## Architecture

### Node roles

| Role | Responsibilities | Cluster listener |
|---|---|---|
| `standalone` | Single node; cluster code idle. `/api/v1/cluster/*` returns `404 control_api.not_found`. | absent |
| `master` | Sole config writer, audit authority, log/stats aggregator, TLS/ACME owner, node registry, join-token issuer. Answers DNS like any node. | inbound on `cluster.listen` |
| `sub_node` | Answers DNS from the last applied snapshot, serves local reads, buffers logs, relays writes, buffers offline writes. Never orders ACME certificates. | none (outbound only) |

`role` is node-local bootstrap configuration and is **never** part of the
replicated config snapshot; otherwise the master's role would overwrite a
sub-node's role. The same applies to `node_id`, `master_url`, cluster paths and
timeouts.

### Topology and direction of control-plane traffic

```
                 control plane (mTLS, HTTP/2, cluster listener)
   sub-node A  ───────────────────────────────────────────────▶  master
   sub-node B  ───────────────────────────────────────────────▶  (config push,
   sub-node C  ───────────────────────────────────────────────▶   cert push,
        │  outbound connection, initiated by the sub-node         auth snapshot,
        │                                                        runtime commands)
        └── DNS answers locally, keeps last applied config
```

- All TCP connections are initiated by the sub-node to `master_url`. This is
  NAT-friendly: a sub-node needs no reachable inbound port and the master needs
  one internal listener only.
- Each sub-node holds one long-lived TLS connection to the master carrying:
  - a downstream `GET /cluster/v1/stream` response (config snapshots, TLS
    cert+key, auth snapshot, runtime commands, acks), and
  - upstream posts for log batches, write relay, heartbeat and enroll.
- The master's cluster listener binds only to loopback or a private/ULA address
  (same rule as control-api: never `0.0.0.0`/`::`) and is separate from the
  public DNS listeners. It is never reachable from the public internet.
- If the connection drops, the sub-node reconnects with exponential backoff and
  reconciles during the handshake (§ Configuration synchronisation).

### Node identity and join

**Decision: dedicated cluster CA + per-node certificate (mTLS), not the `tls`
module's ACME certificate and not a shared cluster secret.**

- The ACME wildcard certificate and private key are deliberately identical on
  every node (the master pushes them to sub-nodes). They prove cluster
  *membership*, not *node identity*: any node holding the key could impersonate
  any other.
- A shared cluster secret has the same problem and is replayable; revoking one
  node would require rotating the secret for all nodes.
- A per-node certificate signed by a cluster CA gives a distinct node identity
  (`node_id` in the subject/SAN), per-node revocation, and an auditable binding
  between a connection and the `node_id` written into every log record and audit
  entry. It uses only the existing ring-only stack (`rcgen`, `rustls` with the
  `ring` provider; ADR-0002).

Join procedure:

1. The master creates the cluster CA on first start (`cluster.ca_cert`,
   `cluster.ca_key` in the data directory; key mode `0600`, never exported).
2. An admin mints a **one-time join token** bound to the intended `node_id`,
   short TTL (default 15 min), stored only as a hash on the master.
3. The sub-node generates a key pair and CSR (`rcgen`), connects to
   `master_url`, presents the join token and `node_id`, and — after the master
   verifies token, node id and CSR — receives the cluster CA certificate and its
   signed node certificate (SAN `node_id`, default TTL 90 days, renewed over the
   established channel before expiry).
4. The master records `node_id`, certificate fingerprint, role, `joined_at`,
   `last_seen` and `applied_config_version` in `cluster_nodes`. Every subsequent
   connection is rejected unless the client certificate chains to the cluster CA
   **and** its fingerprint is registered and not revoked.
5. Bootstrap trust for step 3 (decided, see § Decisions): the sub-node pins the
   master's leaf certificate (PEM in `DNSCRAFT_CLUSTER_MASTER_CERT_FILE`) before
   it has the cluster CA, then switches to the cluster CA after enrollment; the
   self-signed bootstrap certificate of control-api must not be accepted silently.

**Renewal (implemented).** A sub-node renews its node certificate over the
established mTLS channel once two thirds of its lifetime have passed (the
check runs on every heartbeat interval; the window is derived from the
certificate's own validity, so no extra key is needed):

1. The sub-node builds a CSR for its **current** key and `node_id` and posts
   `RenewRequest { protocol, csr_pem }` to `POST /cluster/v1/renew`. The request
   is authenticated by the presented certificate, not by a join token.
2. The master re-checks the registration (revoked nodes are refused), requires
   the CSR to name the authenticated `node_id`, signs a certificate with the
   same profile as enrollment, and makes its fingerprint the node's current
   one. The previous certificate stays accepted until it expires, so a renewal
   whose response was lost cannot lock the node out; rustls still enforces the
   expiry of every certificate.
3. The sub-node writes the new certificate to its certificate path atomically
   (temporary file and rename), checks that it carries its own key and
   `node_id`, and rebuilds its mTLS client. Live streams keep running until
   they reconnect.

Decision: renewal **keeps the node key**. A new key would need a two-file
swap that cannot be atomic on disk (a crash between the two renames leaves a
mismatched pair). A compromised key is handled by revocation, as before.
Owner may later ask for key rotation; the open option is a single-file bundle.

`node_id` is a lowercase DNS label, 1–63 characters
(`[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?`), unique in the cluster and distinct from
reserved DNS labels and Client IDs (SPEC-tls.md § Multi-node). It is a node
identity, never an authorization subject.

### Transport

- TLS 1.3, rustls ring-only provider, client certificates mandatory on both
  sides (mTLS). No plaintext fallback, no cluster listener on a public address.
- HTTP/2 over the TLS connection. Downstream pushes are the response body of a
  long-lived `GET /cluster/v1/stream` (NDJSON records, one JSON object per line);
  upstream messages are ordinary `POST`s on the same connection (`/cluster/v1/logs`,
  `/cluster/v1/writes`, `/cluster/v1/heartbeat`, `/cluster/v1/renew`,
  `/cluster/v1/tls/certificate`). No custom framing or webhook
  callbacks.
- Cluster protocol version is negotiated in the first stream message; a version
  mismatch fails the session with `cluster.protocol.version` and the sub-node
  keeps serving locally.
- Compression is not used in v1: the channel is internal and TLS already
  protects it; a batch cap bounds memory instead (YAGNI).

## Configuration synchronisation

The cluster reuses the control-api configuration model exactly; it adds no new
config write shape. § Cluster hooks of [SPEC-control-api.md](SPEC-control-api.md)
is the contract.

### Push model

- The master pushes **full snapshots**, not deltas. `config_versions` already
  stores complete snapshots, rollback restores a complete snapshot, and a full
  snapshot is idempotent — this removes delta-ordering and partial-apply bugs.
- On every successful master config apply (including rollback, which produces an
  applied version), the master enqueues
  `ConfigPush { protocol, config_version, sha256, snapshot }` to every connected
  node. Snapshot secrets are excluded exactly as in `GET /api/v1/config`.
- The sub-node applies, verifies the digest, and acks `{ applied_version }`.
  The master tracks per-node lag. A node that has not acked within
  `config_apply_timeout` is reported `degraded` in status; pushes are retried
  with backoff, but the master never sends a partial snapshot.
- On connect/reconnect the sub-node sends
  `Hello { protocol, node_id, last_applied_version, last_acked_log_seq }`.
  - master version > applied: push the current snapshot immediately;
  - master version == applied: nothing to do;
  - applied > master (impossible with a single writer): the master is
    authoritative; the sub-node discards its newer state and adopts the master
    snapshot ("master-wins" for configuration divergence).
- A sub-node that has never synced and has no config cannot answer DNS; it
  reports `control_api.not_ready` until the first snapshot is applied.

### UniFi directory and secrets (clients module)

Config snapshots carry UniFi **profiles and bindings** (no API keys). Runtime
directory state and secrets use dedicated stream/uplink paths:

- **`SecretPush`** (downstream, targeted): master sends
  `{ type: "secret_push", profile_id, api_key }` only to that profile's
  `sync_owner`. The sub-node stores it node-locally (kv); it never appears in
  config exports or acks. Non-owners never receive the key.
- **`CloudflareTokenPush`** (downstream, targeted): master sends
  `{ type: "cloudflare_token_push", protocol, token }` (`token: null` clears)
  only to nodes with an **enabled** `tls.dyndns.nodes[]` profile while
  `tls.dyndns.enabled` is on. Sent on connect and whenever the master's token
  or the synced config changes (disabling the profile clears the node's copy).
  The sub-node stores it in the same kv entry as the master and updates its
  running TLS engine; its local `PUT /tls/cloudflare-token` is rejected. Never in
  snapshots, acks, status, audit or logs. **Compat:** an unknown record type
  ends an old node's stream, so the sub advertises `capabilities:
  ["cloudflare_token"]` in its `hello` and the master never sends the record to a
  node without it.
- **Directory uplink:** after a successful UniFi sync, the sync_owner
  `POST`s `/cluster/v1/clients-directory` with
  `{ profile_id, generation, clients: [...] }` (UniFi-sourced entries only).
- **`ClientsDirectoryPush`** (downstream): master fans the snapshot out to every
  connected node bound to that `profile_id`. Receivers replace only the UniFi
  portion of their local `ClientLookup`; manuals stay from the config snapshot.
- Solo / non-cluster: sync_owner == local node; no push or uplink required.

### Applying a synced config on a sub-node

The sub-node calls control-api's **same atomic apply path** used by
`PUT /api/v1/config`:

1. validate the full config and cross-module references;
2. persist the version (adopting the master's `config_version` the same value,
   never bumping it locally);
3. apply modules in leaf order (`filtering`, `clients`, `policy`, `listeners`,
   `tls` if needed);
4. on failure, re-apply the previous snapshot and report `cluster.config.apply`
   with the failing module's original code; the sub-node stays on the previous
   version and keeps answering DNS;
5. on success, expose the new version and ack the master.

`mcp_rules` travel inside the snapshot, so MCP-created rules replicate without a
separate path. Runtime-only state (pause/temporary allow) is not in a snapshot;
it is broadcast separately (§ Writes from any node).

The snapshot is uniform across nodes, but policy views and DNS listeners may be
**node-scoped** (a view's or listener's `nodes` list; see
[SPEC-policy.md](SPEC-policy.md) and [SPEC-listeners.md](SPEC-listeners.md)).
Each node filters entries to those valid for its own `node_id` at apply time;
the full snapshot is
still replicated so any node can adopt a view without a per-node diff.

### Conflicts

- Optimistic concurrency stays `config_version` + `If-Match`, and a mismatch is
  `409` with `control_api.config.version` (the shipped control-api returns 409;
  the spec formerly wrote `412 control_api.config.conflict`, now aligned to the code).
- Because **only the master writes**, there are no concurrent sub-node config
  writers and no tie-break rule is needed. Two cases remain:
  - **Forwarded live write**: the caller's `If-Match` is evaluated by the
    master; the `409` is relayed unchanged. The caller re-reads and retries.
  - **Offline-buffered write replayed after reconnect**: the master evaluates
    the original `If-Match` against its current version. If it no longer
    matches, the write is **not applied**; it is marked `conflict` and the
    caller must retry. There is no last-write-wins merge.
- A sub-node never accepts a direct config write locally, so a sub-node cannot
  fork configuration.

### Apply timeout and degraded nodes

- `[cluster.timing]` drives the transport: `heartbeat_interval` is the sub-node
  maintenance tick (heartbeat, then certificate renewal when due);
  `master_timeout` bounds each connect and the relay retry window;
  `reconnect_backoff`/`reconnect_backoff_max` shape the reconnect and relay
  retry loops, and offline-queue replay uses the same backoff for 5xx and
  transport retries.
- The master tracks, per node, when its oldest unacknowledged push was sent. A
  node still unacknowledged after `config_apply_timeout` is **degraded**: its
  heartbeat response carries `cluster.config.stale`, and the master status
  reports the count as `cluster.degraded_nodes`. Pushes keep being retried; the
  node is never sent a partial snapshot.

### Durable relayed answers

The master keeps the answer to each relayed write in `cluster.db`
(`relay_responses`, keyed by the dedupe key) for 24 h, so a retry that spans a
master restart returns the stored answer and is not applied twice. If storing
the answer fails after the write was applied, the failure is logged and the
answer is still returned; the retry window is then best-effort for that one
write.

### TLS certificate distribution

**Decided (owner, supersedes the earlier "private key never leaves the master"
/ per-node CSR relay rule): ACME runs ONLY on the master, and the master
synchronises the SAME certificate (chain + private key) to its sub-nodes over
the already authenticated mTLS cluster channel.** Reason: the per-node CSR relay
made the master order a *new* Let's Encrypt certificate for every sub-node
request and every sub-node restart, which exhausted the Let's Encrypt limit
(5 certificates per 168 h for the same identifier set). The private key
therefore *does* leave the master, deliberately, to authenticated cluster
members only.

- **Wire format:** `StreamRecord::TlsCertificatePush { protocol, chain_pem,
  key_pem }` (`type: "tls_certificate_push"`). Its `Debug` redacts the key; the
  key is never logged, never in status/audit/export, and never part of a config
  snapshot.
- **Capability gate:** a sub-node that can install it lists `tls_certificate`
  in its stream `Hello.capabilities` (only when it has a TLS engine), exactly
  like `cloudflare_token`. The master never sends the record to a node that did
  not advertise it (an older node would drop the stream on an unknown record).
- **When:** (a) right after a capable sub-node connects, (b) after every
  successful issuance/renewal on the master (the TLS engine's `on_issued`
  hook), to every connected capable sub-node. Nothing is sent when the master
  has no (or a revoked) certificate. Best-effort, no retry: a node that was
  offline gets the current certificate on reconnect.
- **Sub-node receive:** the TLS engine validates before touching anything: the
  PEM chain parses, the key matches the leaf, the leaf covers
  `dns.<public_domain>` and `*.dns.<public_domain>`, and its `notAfter` is
  newer than the installed certificate (an equal or older push is ignored, so
  reconnects are idempotent and a push cannot downgrade). Then it is persisted
  in the engine's store (`tls/`, mode `0600`, the same files a master has, so a
  restart keeps it) and hot-installed into the live `CertResolver` (no restart),
  and the engine status is refreshed. An invalid push is rejected with a logged
  warning (stable code, never the key) and changes nothing.
- **Master export:** the key is read through an internal engine method
  (`TlsEngine::cluster_certificate`) that no API, status or export route
  reaches; `export_cert` and the TLS status never contain it.
- **No CSR relay:** the master never starts an ACME order because a sub-node
  asked. `POST /cluster/v1/tls/certificate` is not wired in production and
  answers `cluster.internal` ("certificate relay disabled; certificates are
  pushed"). The `tls_renewed` notice is no longer sent; `TlsCsrSigner`,
  `CertInstaller` and `ClusterClient::request_tls_certificate` remain in
  `dnscraft-cluster` only as unreachable transport types.
- **Sub-nodes never order, from the first instant:** the TLS engine is
  constructed with the sub-node role (`TlsEngine::open_for_role`), so ACME is
  disabled before the renew scheduler exists. A bootstrap `[tls.acme]
  enabled = true` on a sub-node, `apply_config`, `renew_now`, `rotate_key` and
  `sign_csr` therefore never open an order or an ACME account.
- **Trade-off:** any cluster member now holds the public certificate's private
  key, so a compromised sub-node can impersonate the DoH/DoT endpoint until the
  certificate is replaced. Revoking a node (`disconnect`) stops further pushes
  but cannot recall the key; the certificate must then be rotated on the master
  (a new key is pushed to the remaining nodes).
- Only the master obtains/renews ACME certificates (SPEC-tls.md). Key material is
  never logged, exported, or written to audit.
- If the master is unreachable, the sub-node keeps the last certificate; if that
  certificate expires, encrypted listeners fail and status reports a warning.
  Certificate/key are stored mode `0600`.

## Writes from any node

The canonical write surface remains `/api/v1/config`, `/api/v1/config/versions`,
the policy/clients/filtering/listener/tls mutation endpoints, the MCP write
tools, and the MCP-phase filtering endpoints. The cluster does not add
alternative write endpoints.

### Live relay (master reachable)

1. The sub-node's control-api authenticates the caller with its **local** auth
   state (replicated snapshot; see below), applies the normal per-principal rate
   limits, and rejects before relaying if the caller is unauthorized.
2. It emits `WriteRelay { request_id, idempotency_key, if_match, method, path,
   body, actor }` to the master over the mTLS channel. `actor` records
   `actor_id`, `actor_type` (`user`/`token`) and the authenticated role/scope.
   Raw bearer tokens and session cookies are not forwarded.
3. The master treats the joined node as trusted transport but **re-applies the
   same RBAC check to the actor and operation** before executing the canonical
   handler. A sub-node cannot assert a stronger role than the actor holds.
4. The master executes the existing control-api path (validate → persist →
   atomic apply → audit), stores the `Idempotency-Key` response for at least
   24 h, writes the audit entry with `node_id` = originating sub-node, and
   returns the normal `{data}` / `{error}` envelope plus status code.
5. The sub-node relays the response verbatim. The caller sees the same
   contract as on the master.

Failure semantics:

- Transport error before a response: the sub-node retries the same
  `request_id`/`Idempotency-Key` until `master_timeout`. If the master already
  applied the write and the response was lost, the retry returns the stored
  response; no double apply.
- Retries exhausted:
  - with an `Idempotency-Key` and an `If-Match`, the write may be buffered
    offline (§ below);
  - without them, the sub-node returns `503 cluster.write_relay_failed` with
    `params.outcome = "unknown"` and does **not** buffer. The caller must
    re-read state before retrying.
- The sub-node never applies the write locally.

### Offline fallback (master unreachable)

Offline buffering is opt-in (`cluster.offline_writes.enabled = true`) and only
for **config-mutating** writes that carry both an `Idempotency-Key` and an
`If-Match` referring to the sub-node's last applied `config_version`.

- Accepted: return `202 Accepted` with
  `{"data":{"queued":true,"request_id":"...","state":"pending","queued_at":"...","expires_at":"..."}}`.
  The write is **not applied yet**; 202 is not a success.
- Rejected: missing `Idempotency-Key` or `If-Match` →
  `400 cluster.offline_write_requires_idempotency`; queue cap reached →
  `503 cluster.offline_write_queue_full`.
- Durability: the queue is a SQLite table in the node's data directory with one
  row per request (`request_id`, `idempotency_key`, `if_match`, method, path,
  body, actor, `enqueued_at`, `state`, `attempts`, `expires_at`, `result_status`).
  `expires_at` is the deadline returned in the 202; `result_status` is the HTTP
  status of the master's answer on replay. The enqueue commits before the 202 is
  returned, so a crash after 202 does not lose the write. The queue survives
  restarts.
- Replay on reconnect, strict FIFO:
  - each request is sent with its original `Idempotency-Key` and `If-Match`;
  - 2xx → mark `applied`, ack, continue;
  - `409` → mark `conflict`, do **not** apply, and **stop replay** (head-of-line
    blocking): later queued writes were built on the conflicted version and are
    marked `blocked`; the caller must re-read and resubmit;
  - other 4xx → mark `failed`; 5xx/transport → retry with backoff until
    `max_age`;
  - rows older than `max_age` (default 24 h) or above `queue_max_entries` are
    dropped with `cluster.offline_write_expired`.
- The master deduplicates by `Idempotency-Key`, so a replay after an ambiguous
  ack is safe; the queue is effectively exactly-once for keyed requests.
- Conflict/expiry reporting: `GET /api/v1/cluster/writes/{request_id}` returns the
  state, deadline and replay status (SPEC-control-api.md § Cluster contract); the
  node status also carries the queue counters.

### Runtime-only and non-repeatable writes

- **Pause/resume and temporary allows** are not versioned and do not survive a
  restart (SPEC-control-api.md § MCP-managed filter rules). A sub-node forwards
  them to the master; the master applies them and broadcasts
  `RuntimeCommand { kind, filter_set_id, payload, issued_at }` to every node,
  which applies it to its local `FilterEngine`. Last command wins; commands are
  not persisted and are not buffered offline — when the master is down,
  `503 cluster.master_unavailable`.
- **Token creation/revocation, local account changes and join-token issuance**
  produce secret material or revoke credentials. They are master-only, never
  buffered offline, and return `503 cluster.master_unavailable` when relayed
  while the master is unreachable.
- Read requests are never relayed: the sub-node serves them locally.

## Keep serving without the master

DNS answering is fully independent of the master: resolver cache, filtering,
policy, clients data and listeners operate from the last applied snapshot.

| Operation | Master unreachable (sub-node) |
|---|---|
| DNS over all listeners (Do53/DoT/DoH/DoQ) | **Available** from last applied config; cache is whatever is warm locally |
| `GET /healthz`, `GET /readyz`, `GET /api/v1/status` | Available; status reports `cluster_master_reachable=false` |
| Local config / policy / clients / filter-set reads | Available from last applied snapshot |
| Local query-log reads and local statistics | Available (local data only; see § Log and statistics aggregation) |
| Query-log writes | Available; buffered locally for later streaming |
| Config-mutating writes | `202` queued (fully keyed) or `503`; never applied locally |
| Runtime pause/resume / temporary allow | `503 cluster.master_unavailable` |
| Token/account management, join/revoke | `503 cluster.master_unavailable` (master-only) |
| Cluster-wide query-log/stats view | Unavailable; local view remains |
| ACME renewal | Suspended (master-only); last certificate kept until expiry |
| DynDNS for the public entry node | Suspended if that node needs the master's data; per-node updates are local |
| Audit reads | Local audit only; master is authoritative |

Readiness must not flap merely because the master is gone: `readyz` stays ready
as long as the local modules are ready; the cluster loss is reported as a
degraded status warning, not as not-ready. A sub-node that has never received a
config is not ready.

## Log and statistics aggregation

Hub-and-spoke exactly as recorded in [CAPABILITY-MAP.md](CAPABILITY-MAP.md):
logs are aggregated on the master only; sub-nodes keep a short local buffer
(default 24 h), stream to the master, and backfill after an outage.

### Local buffer and outbox

- Every loggable query is written to the sub-node's local query-log store. In
  the **same SQLite transaction** an outbox row is written with a per-node
  monotonically increasing `seq` (per-node counter, not a UUID ordering) and the
  record `id`. Either both exist or neither does; a crash cannot silently drop a
  loggable query.
- The buffer keeps `cluster.log.buffer_retention` (default 24 h, range 1 h–7 d).
  Unacknowledged rows older than that are detached from the outbox (the query rows
  stay local), at most once a minute, also while the master is unreachable, and
  counted in `cluster.log_buffer_dropped`. The master then records the range as a
  gap on backfill. A row-count cap is not configured in v1. The buffer must not
  exceed the master's `control_api.query_log.retention_days`.
- `seq` is allocated on insert, so local ordering equals query order.

### Streaming

- A sender task batches contiguous unacked rows (`batch_max_records` default
  500 or `batch_interval` default 1 s, whichever fires first;
  `max_batch_bytes` 1 MiB) and `POST`s them to `/cluster/v1/logs` over the mTLS
  connection. No compression in v1.
- Batches carry `{ node_id, protocol, first_seq, last_seq, records[] }`.
  **`node_id` is taken from the authenticated connection, never from the
  payload**; a payload `node_id` mismatch is rejected with
  `cluster.log_stream.invalid`.
- At most `max_inflight_batches` (default 4) are in flight. The master
  acknowledges the highest **contiguous** `seq`; on a gap it returns the expected
  `seq` and the sub-node resends from there. This gives strict per-node
  ordering.
- Records are inserted into the master's query-log store preserving the
  originating `time` and `node_id`. Cross-node ordering is by timestamp only and
  is not guaranteed to be causal; per-node order is.

### Deduplication

- The master enforces unique `(node_id, record_id)` **and** `(node_id, seq)`.
  Replayed batches after a lost ack are inserted with
  `ON CONFLICT DO NOTHING`, so delivery is idempotent.
- Duplicate records are counted, not treated as errors. A repeated `seq` with a
  different `record_id` is `cluster.log_stream.invalid`.

### Backfill after an outage

1. On reconnect the sub-node sends `last_acked_log_seq` in `Hello` (persisted).
2. The master replies with the highest `seq` it has stored for that node.
3. The sub-node sends from `master_acked_seq + 1`. If the oldest buffered row
   is already newer than that (buffer overrun), it logs `cluster.log_gap`,
   sends what it has, and the master records the missing range as a gap. The
   loss is bounded by `buffer_retention` (default 24 h).
4. Backfill uses the same ordered, deduplicated path; there is no separate
   backfill protocol. The sub-node resumes live streaming after the backlog is
   acknowledged.

### Statistics

- The master computes the hourly/daily rollups from ingested rows and serves
  cluster-wide `/api/v1/stats/*` (default when cluster is enabled), including a
  per-node breakdown.
- A sub-node computes local statistics from its own buffer/store and serves
  them when the master is unreachable; when online it may serve the last
  master-pushed aggregate or its local view. The exact read model is an Open
  question; no new stats envelope is invented here.
- Rollups gain a `node_id` dimension (SPEC-control-api.md § Cluster contract), because
  the current rollup key (`hour/day, profile, protocol, answer_source`) would
  merge nodes indistinguishably.
- Master retention stays `control_api.query_log.retention_days` (default 30 d);
  rollups stay 365 d. The sub-node buffer is only a transport buffer, not a
  second long-term archive.

## Security considerations

### Threat model

- A malicious or compromised sub-node, a stolen user credential, a replayed
  cluster message, a MITM on the cluster path, and untrusted query-log content.
- The public DNS surface is unchanged; the cluster listener is never exposed
  publicly.

### Channel

- Connection caps: the master accepts at most 128 concurrent cluster connections
  and allows 10 s for each mTLS handshake; excess connections wait in the kernel
  backlog. An authenticated node may hold at most 8 connections (its stream plus
  short uploads); a ninth is dropped after the handshake. Heartbeats are limited
  per node to 1 per second with a burst of 10. Enroll attempts are limited
  listener-wide to 1 per second with a burst of 10 (enrollment is unauthenticated,
  so it cannot be keyed by node). Refusals use `cluster.quota.exceeded` (429).
- mTLS with a dedicated cluster CA; TLS 1.3, ring-only. The CA private key exists
  only on the master, mode `0600`, and is never in the config export, audit log,
  backups, or error messages.
- The master validates the node certificate chain **and** the registered,
  non-revoked fingerprint on every connection and stream resumption. Revoking a
  node (`DELETE /api/v1/cluster/nodes/{id}`) closes its sessions and rejects its
  next connection with `cluster.node.revoked`.
- Join tokens are one-time, bound to a `node_id`, short-lived and stored hashed.
- Cluster messages are not independently signed on top of mTLS; TLS provides
  transport authentication and integrity. Idempotency keys handle replay at the
  application layer.

### No cross-node privilege escalation

- Node identity is transport identity only. Authorization always uses the
  authenticated **actor**; a sub-node cannot mint or elevate an actor.
- The master re-checks the actor's role/scope against the operation, so a
  sub-node relaying a `viewer` write gets `403 control_api.auth.insufficient_scope`
  exactly as a direct call would.
- Token/account/join management is master-only and is never queued offline; a
  sub-node cannot issue itself credentials or add nodes.
- Node-local administrators are not cluster administrators by virtue of running
  the sub-node; cluster administration requires an authenticated admin actor and
  is executed on the master.
- A compromised sub-node remains trusted infrastructure for its own relayed
  writes (it already possesses the credentials and serves DNS). Node compromise
  is contained by revocation, not by assuming the node is honest; the master
  still enforces actor RBAC and audits every write with the originating
  `node_id`.

### Audit integrity

- Every forwarded config write produces one master-side audit entry with
  `node_id` = originating sub-node, `actor_id`, `actor_type`, `action`,
  `object_type`, `object_id`, `config_version`, `before_digest`, `after_digest`,
  redacted `before`/`after`, `result` and `error_code`.
- The sub-node keeps a local mirror of the same `request_id`; the master is
  authoritative. Audit remains append-only; master config writes and rollbacks
  are audited as today.
- Log ingestion is data, not an administrative action: no audit entry per batch.
  `node_id` is derived from the mTLS identity; payload-supplied node ids,
  actors or timestamps are never trusted for authority.

### Data handling

- Query-log content is attacker-influenced; batches are schema-validated and
  length-capped on the master and inserted only with bound parameters.
- Private keys, token hashes, local account hashes and the auth snapshot travel
  only over mTLS and are never logged, exported, or written to the query log.
- Per-node quotas (`cluster.quota.*` in § Configuration excerpt) bound log
  bandwidth, relay rate and queue growth so one faulty node cannot exhaust the
  master.

## Testing strategy

No internet, no real ACME, no real Cloudflare/Authentik. Use the injectable
clock (ADR-0005) and loopback listeners only.

1. **Unit tests**
   - `node_id`/role validation, role↔config consistency (standalone forbids
     `master_url`/listener; sub-node requires both; master forbids `master_url`).
   - Join token: one-time use, expiry, wrong `node_id`, unknown token, revoked `node_id` re-join (old fingerprint rejected), replayed
     token.
   - Config snapshot digest/version handling; apply failure rolls back and keeps
     the previous version.
   - Offline queue: FIFO order, `Idempotency-Key`/`If-Match` requirement,
     capacity, expiry, and head-of-line blocking on 409.
   - Log batch: seq ordering, gap detection, dedupe, payload `node_id` mismatch,
     size caps.
   - Error-code uniqueness across `cluster.*`, `control_api.*` and module codes.
2. **Transport tests (loopback)**
   - In-process master plus 1–3 sub-nodes on `127.0.0.1:0`; a test CA generated
     with `rcgen`; TLS 1.3 mTLS.
   - Wrong CA, missing client cert, unregistered fingerprint, revoked node and
     expired node cert are all rejected with the documented codes.
   - Cluster listener refuses a non-loopback/non-private bind (config
     validation).
   - Protocol-version mismatch fails the session without stopping DNS.
3. **Fault injection**
   - A controllable transport wrapper between harness nodes: drop, delay,
     reorder, duplicate, truncate and partition messages; restart the master
     process against the same SQLite database; restart a sub-node.
   - Assert: config push eventually converges; forwarded writes are
     exactly-once under retries; ambiguous ack does not double-apply; backfill
     resumes from `last_acked_seq`; queue survives restart.
4. **Integration flows**
   - Join → config write on master → all sub-nodes apply and ack; write on a
     sub-node → master applies, audit `node_id` is the sub-node; `409` relayed
     unchanged.
   - Master down → sub-node keeps answering DNS (query success against a
     pre-seeded config), local reads work, writes queue (202) or fail (503) as
     specified; master returns → queue replays, conflicts surface.
   - Log outage longer than the buffer produces a recorded gap and no panic;
     outage shorter than the buffer backfills with zero duplicates.
   - Runtime command broadcast: pause on the master reaches every node; a
     command issued offline is rejected.
   - TLS cert push installs on sub-nodes (validated, persisted, hot-reloaded;
     mismatching key/names or an older certificate are rejected); a sub-node
     never starts an ACME order, even with `acme.enabled = true` at bootstrap.
5. **No wall-clock waits** for heartbeats, timeouts, retention or token expiry:
   advance `ManualClock`/`SystemClock` test doubles. A test that needs
   "eventually" uses the existing `wait_until` helper.
6. **No real network**: all addresses are `127.0.0.1`, `::1`, or documentation
   ranges in fixtures. No outbound request is made by any test.

## Error codes

Stable `cluster.<area>.<reason>` codes, locale-neutral, in the same envelope as
control-api. Codes owned by other modules are forwarded unchanged (for example
`control_api.config.version`, `policy.config.invalid`,
`control_api.auth.insufficient_scope`).

| Code | When / HTTP |
|---|---|
| `cluster.internal` | Backend failure (filesystem, rcgen, SQLite) with no more specific code |
| `cluster.quota.exceeded` | A node exceeded one of its `[cluster.quota]` rate limits; `429` |
| `cluster.role.invalid` | Role/config mismatch (e.g. sub-node without `master_url`) at startup; `500`/startup error |
| `cluster.master_unavailable` | Sub-node cannot reach the master for an operation that cannot be buffered (runtime/token/admin write); `503` |
| `cluster.master_conflict` | A node reports an applied version the master never published (heartbeat warning). Master-wins still applies on its next `Hello`; the connection is not refused. A second master is not detectable in v1 (no master-to-master protocol) |
| `cluster.node.unknown` | `node_id`/certificate fingerprint not registered on the master |
| `cluster.node.revoked` | Revoked node identity; connection refused (`403` for API calls) |
| `cluster.node.already_joined` | `node_id` is registered and not revoked. A revoked `node_id` may be re-issued a join token; the join replaces the old entry and drops its superseded certificates |
| `cluster.join.token_invalid` | Join token unknown, already used, or bound to another `node_id` |
| `cluster.join.token_expired` | Join token past its TTL |
| `cluster.transport.tls` | mTLS handshake or certificate validation failure |
| `cluster.protocol.version` | Unsupported cluster protocol version |
| `cluster.config.apply` | Sub-node failed to apply a pushed snapshot; stays on the previous version |
| `cluster.config.stale` | A connected node has not acknowledged a pushed snapshot within `config_apply_timeout` (heartbeat warning; the master also counts it in `cluster.degraded_nodes`) |
| `cluster.write_relay_failed` | Forwarded write transport failed before a master response (`params.outcome = "unknown"`); `503` |
| `cluster.offline_write_requires_idempotency` | Offline buffering requested without `Idempotency-Key` or `If-Match`; `400` |
| `cluster.offline_write_queue_full` | Offline queue cap reached; `503` |
| `cluster.offline_write_conflict` | Buffered write returned `409` on replay and was not applied |
| `cluster.offline_write_expired` | Buffered write exceeded `max_age` and was dropped |
| `cluster.log_stream.invalid` | Malformed, oversized, out-of-order or `node_id`-mismatched log batch |
| `cluster.log_buffer_dropped` | Sub-node dropped buffered log rows (informational/status count) |
| `cluster.log_gap` | Master received a batch after a sequence gap (informational/status count) |
| `cluster.runtime_command.failed` | Node failed to apply a broadcast runtime command |
| `cluster.cert_push.failed` | Sub-node failed to install the certificate it requested (chain with its local key) |
| `cluster.clock_skew` | Node clock skew above the threshold (status warning) |

When cluster is disabled (`role = "standalone"`), cluster routes do not exist
and return `404 control_api.not_found`; there is no separate "cluster disabled"
code (same rule as the disabled MCP listener).

## Configuration excerpt (TOML)

Node-local bootstrap only. These keys are **never** part of the replicated
snapshot. Secrets come from the environment / `*_FILE`, never from this file.
The assembler reads the enrollment material from the environment, used only
when a sub-node has no identity yet: `DNSCRAFT_CLUSTER_JOIN_TOKEN` or
`DNSCRAFT_CLUSTER_JOIN_TOKEN_FILE` (one of the two), and
`DNSCRAFT_CLUSTER_MASTER_CERT_FILE`, the PEM of the master's certificate, pinned
for first enrollment. Relative `cluster.tls` paths resolve under `data_dir`.

```toml
[cluster]
role = "standalone"                  # standalone | master | sub_node
node_id = ""                         # required for master/sub_node: 1-63 chars, [a-z0-9-]
# master_url = "https://master.dns.example.com:8443"   # required for sub_node; forbidden for master/standalone

[cluster.listen]                     # master only
bind = "192.0.2.10"                  # loopback or private/ULA only; never 0.0.0.0/:: 
port = 8443
# TLS is always on (mTLS); there is no plaintext mode.

[cluster.join]                       # master only
token_ttl = "15m"                    # one-time join-token lifetime
node_cert_ttl = "90d"                # issued node certificate lifetime
# The CA cert/key live in the data directory; the key is mode 0600.

[cluster.timing]
heartbeat_interval = "10s"
master_timeout = "5s"
config_apply_timeout = "30s"
reconnect_backoff = "1s"
reconnect_backoff_max = "60s"

[cluster.offline_writes]
enabled = true
queue_max_entries = 100              # 1-10000
max_age = "24h"                      # 1h-7d; requires Idempotency-Key + If-Match

[cluster.log]
buffer_retention = "24h"             # 1h-7d; must not exceed control_api.query_log.retention_days
batch_max_records = 500              # 50-5000
batch_interval = "1s"                # 100ms-10s
max_batch_bytes = "1MiB"             # 64KiB-16MiB
max_inflight_batches = 4             # 1-16

[cluster.quota]                      # per-node limits enforced on the master
max_relay_requests_per_second = 50   # 1-1000
max_log_bytes_per_second = "2MiB"    # 64KiB/s-64MiB/s
max_queued_offline_writes = 100      # must be <= offline_writes.queue_max_entries
clock_skew_warning = "5m"            # 30s-1h

[cluster.tls]
ca_cert = "data/cluster/ca.pem"
node_cert = "data/cluster/node.pem"
node_key = "data/cluster/node.key"   # prefer env / *_FILE in deployed configurations
```

| Setting | Default | Validation |
|---|---|---|
| `role` | `standalone` | `standalone` \| `master` \| `sub_node` |
| `node_id` | – | required for master/sub_node; DNS label 1–63 |
| `master_url` | – | required for sub_node; `https://` only; must use the cluster port |
| `cluster.listen.bind` | – | loopback/private/ULA; `0.0.0.0`/`::` rejected |
| `token_ttl` | 15m | 5m–24h |
| `node_cert_ttl` | 90d | 1d–365d |
| `heartbeat_interval` | 10s | 5s–60s |
| `master_timeout` | 5s | 1s–30s |
| `config_apply_timeout` | 30s | 5s–120s |
| `queue_max_entries` | 100 | 1–10000 |
| `max_age` | 24h | 1h–7d |
| `buffer_retention` | 24h | 1h–7d and ≤ master query-log retention |
| `batch_max_records` | 500 | 50–5000 |
| `batch_interval` | 1s | 100ms–10s |
| `max_batch_bytes` | 1 MiB | 64 KiB–16 MiB |
| `max_inflight_batches` | 4 | 1–16 |
| `clock_skew_warning` | 5m | 30s–1h |

## Success Criteria

1. Role/config validation at startup: standalone rejects cluster listener and
   `master_url`; sub-node requires `master_url` plus `node_id`; master requires
   the listener plus `node_id`; a non-private cluster bind is rejected.
2. A sub-node joins with a one-time token, receives the cluster CA and a
   per-node certificate, and connects with mTLS. Wrong CA, unregistered
   fingerprint, revoked node and expired certificate are rejected with the
   documented `cluster.*` code; certificate identity is bound to `node_id`.
3. The master never initiates a TCP connection to a sub-node; every cluster
   session and upload originates at the sub-node.
4. A config write on the master creates a new `config_version` and every
   connected sub-node applies the full snapshot through the control-api atomic
   apply path within `config_apply_timeout`, acks the version, and reports zero
   lag. `mcp_rules` in the snapshot replicate.
5. A failed sub-node apply rolls back to the previous snapshot, keeps answering
   DNS on it, reports `cluster.config.apply`, and the master retries with
   backoff; no partial config is ever active.
6. A config write sent to a sub-node is relayed to the master, applied there,
   and returned with the master's status/envelope; the audit entry carries
   `node_id` = the originating sub-node, the actor, `config_version` and
   before/after digests.
7. `If-Match` mismatch on a live relay returns `409 control_api.config.version`
   unchanged; no write is applied by the sub-node.
8. Master unreachable: a sub-node with an applied snapshot keeps answering DNS
   on all listeners and serving local config reads; `readyz` stays ready with a
   degraded cluster warning; a never-synced sub-node reports not-ready.
9. Config writes while the master is unreachable: with `Idempotency-Key` +
   `If-Match` and the queue enabled, return `202` with `queued: true` and
   survive a process restart; without them return
   `cluster.offline_write_requires_idempotency`; a full queue returns
   `cluster.offline_write_queue_full`. Runtime-only, token and admin writes
   return `cluster.master_unavailable` and are never queued.
10. On reconnect the queue replays in FIFO order with the original keys. A
    `409` marks the write `conflict`, is not applied, and blocks later queued
    writes; expired entries produce `cluster.offline_write_expired`. No queued
    write is applied twice (verified by config-version count and audit count).
11. Query logs stream from each sub-node to the master in per-node `seq` order;
    replays after a lost ack produce zero duplicate rows in the master's query
    log; the master acks the highest contiguous `seq`.
12. Backfill after a master outage resumes from the persisted
    `last_acked_log_seq`; an outage shorter than `buffer_retention` backfills
    completely, a longer outage records `cluster.log_gap` and drops the oldest
    rows with `cluster.log_buffer_dropped` (no panic, no silent loss of the
    newest rows).
13. Master statistics reflect all nodes; rollups distinguish `node_id`. A
    sub-node offline serves its local log/stats view and never claims it is
    cluster-wide.
14. Runtime pause/resume and temporary allows issued on any node reach every
    node via the master broadcast; when the master is unreachable they return
    `cluster.master_unavailable` and are not applied locally.
15. Privilege checks are not bypassed: a `viewer` write relayed from a sub-node
    returns `403 control_api.auth.insufficient_scope`; a joined node cannot
    assert a role higher than its actor's; token/account/join management is
    impossible from a sub-node while the master is unreachable.
16. The master pushes renewed TLS certificates to sub-nodes; sub-nodes install
    them without restart and never start an ACME order while a master is known.
17. Audit is append-only and coherent: each forwarded write yields exactly one
    master audit entry with the correct `node_id`, actor, `config_version` and
    digests; no secret material appears in audit, query log or config export.
18. All `cluster.*` codes are unique and stable; `cargo fmt`,
    `clippy -D warnings`, `cargo test --workspace`, `cargo deny check` and the
    ring-only `cargo tree` gates are green.
19. Every test runs on loopback with an injectable clock; no test contacts the
    internet, a real ACME server, Cloudflare or Authentik.

## Decisions

Resolved 2026-10-27. The concrete control-api contract (transport routes, admin
endpoints, internal hooks, status/stats extensions) is defined in
[SPEC-control-api.md](SPEC-control-api.md) § Cluster contract; it supersedes the
provisional "Required control-api additions" list that stood here.

1. **Node discovery & bootstrap trust** — static `master_url` + a one-time,
   `node_id`-bound join token. Bootstrap trust pins the master's certificate
   before enrollment: the operator supplies the master leaf PEM via
   `DNSCRAFT_CLUSTER_MASTER_CERT_FILE` (or `_FILE`); the sub-node derives the
   SHA-256 fingerprint from that PEM and accepts only that leaf on the enroll
   connection (equivalent to a fingerprint pin). After enrollment the sub-node
   switches to the cluster CA. No automatic discovery in v1.
2. **Transport authentication** — per-node mTLS certificates under a dedicated
   cluster CA (not a shared secret).
3. **Master failover** — no election/quorum/auto-promotion in v1 (single master,
   documented SPOF for writes and aggregation). Manual promotion =
   `role = "master"` with the same data directory/CA + revoke the old master.
4. **Offline-write conflict** — reject-and-retry: a stale `If-Match` is **not**
   applied, marked `conflict`, and head-of-line-blocks the queue.
5. **Offline-write durability** — SQLite in the node data directory, default
   24 h / 100 entries, `202` on enqueue, FIFO replay with `Idempotency-Key`;
   read via `GET /api/v1/cluster/writes/{request_id}`.
6. **Auth-state replication** — replicate a separate encrypted `AuthSnapshot`
   (token hashes, local-account hashes, OIDC settings, session-invalidation
   epoch) so sub-nodes authenticate bearer tokens offline. **Owner: YES.**
7. **Runtime-only state** — cluster-wide via a master broadcast (pause/resume,
   temporary allows); volatile, never queued offline.
8. **Config-conflict code** — `409 control_api.config.version` (matches the
   shipped control-api); the former `412 control_api.config.conflict` wording
   is removed everywhere.
9. **Sub-node read model** — serve the local view offline; use the master's API
   for cluster-wide views in v1 (no read relay).
10. **Isolated-sub-node cert expiry** — keep serving the expired cert on private
    listeners + loud status warning; never silently fall back to self-signed for
    public listeners.
11. **Clock skew** — warn above 5 min (`cluster.clock_skew`); accept records
    either way; display originating `time` and master `received_at`.
12. **Multi-entry / geo** — not in v1; revisit only with a concrete multi-site
    requirement.
