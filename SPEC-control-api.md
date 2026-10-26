# Spec: control-api

> Module id `control-api` · crate `crates/dnscraft-api` · depends on: `policy`, `clients`
> (reads `resolver`, `listeners`, `tls` state only through narrow read traits / status handles)
> Project-wide decisions: [SPEC.md](SPEC.md)
> Consumers later: `web-ui`, `mcp`, `cluster`
> Status: APPROVED 2026-10-26 (owner approved the plan and dependency table); decisions resolved — see "Decisions"

## Objective

Own the HTTP API that configures DNScraft, exposes the query log, statistics,
health/readiness, audit log and authentication. It is the primary configuration
boundary for the web UI and for the later `mcp` module. The API must be
locale-neutral, versioned, auditable, and safe to run on an internal-only
listener.

This module owns SQLite persistence for configuration, query log, statistics,
audit records, sessions/tokens and configuration versions. It does **not** decide
which DNS answers are produced; it calls `policy`, `clients`, `listeners` and
`tls` apply/status functions and stores user-provided configuration as typed
values.

### Scope

- REST API under `/api/v1/`.
- Configuration CRUD for policy views/profiles, client manual entries, UniFi
  settings, filter list URLs, schedules, SafeSearch, rebind, pause state,
  listener configuration, TLS-related settings and API/auth settings.
- Query log storage, filtering, pagination, export and “why blocked?” data.
- Read-only statistics endpoints for dashboard.
- Health/readiness endpoints for Docker and cluster.
- Auth/OIDC for human UI users, local break-glass login, and API tokens that
  `mcp` will reuse.
- Audit log for every mutating action.
- Internal-only binding; this module is never reached from a public DNS listener.

### Non-goals

- Not a DNS protocol implementation.
- Not a general-purpose database API.
- Not doing DNS filtering/rewrite decisions itself.
- Not serving the web UI files; `web-ui` is embedded in the binary later.
- Not implementing the actual multi-node replication protocol; it only provides
  versioned config and stable endpoint shapes that `cluster` can reuse.
- Not creating localized messages; only stable `area.reason` codes and structured
  parameters.

## Assumptions

1. `control-api` runs in the same process as `policy`, `clients`, `listeners`
   and `tls`; hot-reload is done by calling each module’s existing `apply_config`
   or status accessors, not by spawning separate binaries.
2. Configuration is stored in SQLite. Bootstrap values from environment / TOML
   are only for initial seed data; after first startup SQLite owns the current
   editable config.
3. The API listener is private/internal only (SPEC.md). It may be bound to
   loopback or a ULA/RFC 1918 address. Public DoH/DoT listeners are owned by
   `listeners` and never route API paths.
4. Human browser sessions use HttpOnly cookies with SameSite and CSRF
   protection. `mcp` uses revocable static bearer tokens, not cookies.
5. The `mcp` module later reuses the same token, roles and audit endpoints
   without breaking changes; API paths remain stable after v1.
6. Query-log records are attacker-influenced and treated as untrusted data.

## Interfaces to neighbouring modules

This section lists the boundary types control-api will use. Where a type is not
yet finalised in the adjacent module, the spec gives the required shape and the
implementer must create a narrow adapter/facade in that module or in
control-api itself. No module may expose `rusqlite` or internal mutable state
through these APIs.

### `policy`

Control-api depends on the re-exported policy types from
`crates/dnscraft-policy`:

- `Arc<PolicyEngine>`
- `PolicyEngine::new(config: PolicyConfig, filter: Arc<FilterEngine>,
  resolver: Arc<Resolver>, clients: Arc<dyn ClientDirectory>,
  clock: Arc<dyn Clock>) -> Result<Self, PolicyError>`
- `async PolicyEngine::apply_config(&self, config: PolicyConfig) -> Result<(), PolicyError>`
- `PolicyEngine::pause(&self, scope: PauseScope, until: PauseUntil) -> Result<(), PolicyError>`
- `PolicyEngine::resume(&self, scope: PauseScope)` (infallible, returns `()`)
- `PolicyEngine::handle(...)` is not used by control-api directly; control-api
  only configures and reads status.
- `PolicyEngine::is_client_id_registered(&self, id: &str) -> bool` is available
  and is used by `listeners::PolicyClientIds`.

Types control-api stores/exposes from `policy`:

- `PolicyConfig`, `ProfileConfig`, `ViewConfig`, `SafeSearchConfig`,
  `ScheduleConfig`, `YoutubeMode`, `DnsProtocol`, `ClientFlags`,
  `RequestContext`
- `ViewId`, `ProfileId`, `ListenerId`, `ClientId`
- `Selection`, `SelectionCause`
- `DecisionRecord`, `DecisionStep`, `DecisionTimings`, `FilterHit`,
  `AnswerOrigin`, `ProtectionPauseScope`, `RebindSkipReason`
- `PauseScope`, `PauseUntil`
- `PolicyStatus`, `PolicyStats`, `ProfileStats`, `ViewStats`,
  `ProfileScheduleStatus`
- `PolicyError`

Control-api should use the same DTO names as these public Rust types where the
API is a direct representation. It must not invent parallel `view`/`profile`
string types.

### `clients`

Control-api depends on:

- `Arc<ClientEngine>` from `crates/dnscraft-clients`
- `ClientEngine::new(config: ClientsConfig, data_dir: PathBuf, clock: Arc<dyn Clock>) -> Result<Arc<Self>, ClientsError>`
- `async ClientEngine::apply_config(&self, config: ClientsConfig) -> Result<(), ClientsError>`
- `async ClientEngine::sync_now(&self) -> Result<SyncReport, ClientsError>`
- `ClientEngine::status(&self) -> ClientsStatus`
- `ClientEngine::lookup(&self) -> Arc<ClientLookup>`

Types control-api stores/exposes from `clients`:

- `ClientsConfig`, `ManualEntry`, `LocalDomainMode`, `UnifiConfig`
- `SyncReport`, `ClientsStatus`
- `ClientLookup` and `ClientInfo`, `ClientSource`, `ClientId`, `VlanInfo`,
  `MacAddr`
- `ClientLookup::by_ip(&self, ip: IpAddr) -> Option<Arc<ClientInfo>>`
- `ClientLookup::by_name(&self, name: &str) -> Option<Arc<ClientInfo>>`
- `ClientLookup::reverse(&self, ip: IpAddr) -> Option<String>`
- `ClientLookup::local_domains(&self) -> Arc<[String]>`
- `ClientLookup::clients(&self) -> &[Arc<ClientInfo>]`

Control-api adapts `Arc<ClientLookup>` to `Arc<dyn policy::ClientDirectory>`
for `PolicyEngine::new`. The adapter maps `by_name` to `addresses()`; `by_ip`
stays a control-api-only enrichment API.

### `resolver`

Control-api reads resolver status and stats through the existing public methods
on `crates/dnscraft-resolver::Resolver`. The exact return types are already
public; no new facade is required, unless the resolver owner chooses to add one
for an even smaller API.

- `Resolver::stats(&self) -> ResolverStats`
- `Resolver::forward_zone_ids(&self) -> Vec<ForwardZoneId>`
- `Resolver::forward_zone_for(&self, name: &Name, allow: Option<&[ForwardZoneId]>) -> Option<ForwardZoneId>`
- `Resolver::priming_status(&self) -> PrimingStatus`
- `Resolver::cached_bytes(&self) -> usize` is `#[doc(hidden)]` and test-only;
  control-api should use only the public status/stats surface.

The API DTO for resolver status is a read-only snapshot of these values, not a
mutable handle into the resolver.

### `listeners`

Control-api owns the persisted `ListenersConfig` and calls the real listener
runtime. The public API from `crates/dnscraft-listeners` includes:

- `ListenerSet`
- `ListenerSetParams`
- `async ListenerSet::start_with(params: ListenerSetParams<H>) -> Result<Self, ListenersError>`
  (`H: QueryHandler`, default `PolicyEngine`)
- `async ListenerSet::apply_config(&self, cfg: ListenersConfig) -> Result<(), ListenersError>`
- `ListenerSet::status(&self) -> ListenersStatus`
- `async ListenerSet::shutdown(self, grace: Duration)`
- `QueryEventSink`, `QueryEvent`
- `ChannelSink`, `NullSink`
- `ListenerConfig`, `ListenersConfig`, `ListenerStatus`, `ListenersStatus`,
  `Protocol`, `Exposure`
- `Clock`, `ManualClock`, `SystemClock`

`ListenerSetParams` currently contains at least `config`, `handler`, `certs`,
`sink`, `clock`, `public_domain`, and `client_ids`. Control-api therefore wires
the policy engine, TLS cert resolver, event sink and a
`PolicyClientIds`/`EmptyClientIds` registry into the listener set.

Control-api implements `QueryEventSink` and persists the emitted `QueryEvent`
values. The listener sink must stay non-blocking and drop events when full;
the API only consumes what the bounded channel can deliver.

### `tls`

Control-api reads TLS status and configures TLS through the public
`crates/dnscraft-tls::TlsEngine` API:

- `TlsEngine::open(config: TlsConfig, data_dir: &Path, clock: Arc<dyn Clock>) -> Result<Self, TlsError>`
- `TlsEngine::resolver(&self) -> Arc<CertResolver>`
- `TlsEngine::status(&self) -> TlsStatus`
- `async TlsEngine::apply_config(&self, config: TlsConfig) -> Result<(), TlsError>`
- `async TlsEngine::renew_now(&self) -> Result<(), TlsError>`
- `async TlsEngine::dyndns_now(&self) -> Result<DynDnsResult, TlsError>`

The API may expose `TlsStatus` fields but must never expose private key PEMs
or secret token material. The `CertResolver` is passed to listeners as
`Option<Arc<CertResolver>>`.

## API surface

### General rules

- All routes are under `/api/v1`.
- Responses are `application/json` unless otherwise stated.
- Success envelope:

  ```json
  { "data": { ... } }
  ```

- Error envelope:

  ```json
  {
    "error": {
      "code": "area.reason",
      "params": { ... }
    }
  }
  ```

- IDs are strings; UUIDs use canonical RFC 4122 formatting.
- Timestamps are UTC RFC 3339 (`2026-10-26T08:15:30Z`).
- Pagination uses `limit` (default 50, max 500) and `offset` (default 0), plus
  a stable `next_offset`/`has_more` response or a `Link` header.
- Mutating endpoints that cannot be safely repeated require `Idempotency-Key`
  headers for cluster relay. The server stores successful responses for at
  least 24 hours.
- Rate limits: internal API per source IP and per authenticated principal:
  - read endpoints: `100/s` burst `200`
  - write endpoints: `20/s` burst `40`
  - auth endpoints: `10/s` burst `20`
  - exceeded: `429` with `control_api.rate_limited`.
- `/mcp/v1` is mounted on the same listener and shares these buckets. Requests
  rejected with `401` (missing or invalid bearer token) are counted against the
  **auth** bucket, so unauthenticated probing cannot use the MCP path to avoid
  the auth limit. Authenticated MCP requests count against the read or write
  bucket according to the tool they call.

### Endpoint table

| Method | Path | Role | Request / response summary | Errors |
|---|---|---|---|---|
| GET | `/healthz` | public | liveness only | – |
| GET | `/readyz` | public | readiness aggregates resolver/listener/config states | `control_api.not_ready` |
| GET | `/api/v1/status` | public | node status, module status, build version | `control_api.internal` |
| GET | `/api/v1/config` | admin | full current config export (secrets excluded) | `control_api.config.read` |
| PUT | `/api/v1/config` | admin | atomic config replace, except `mcp_rules` (carried over when omitted; see § MCP-managed filter rules); returns new version | `control_api.config.invalid`, `control_api.config.apply` |
| GET | `/api/v1/config/versions` | admin | list previous config versions | `control_api.config.version` |
| POST | `/api/v1/config/versions/{version}/rollback` | admin | restore version | `control_api.config.unknown_version` |
| GET | `/api/v1/policy/views` | admin | list views | – |
| GET | `/api/v1/policy/views/{id}` | admin | single view | `control_api.not_found` |
| PUT/POST | `/api/v1/policy/views/{id}` | admin | create/update view | `policy.config.invalid` etc. |
| DELETE | `/api/v1/policy/views/{id}` | admin | delete view | `control_api.not_found` |
| GET/POST/PUT/DELETE | `/api/v1/policy/profiles/{id}` | admin | profile CRUD | `policy.config.unknown_filter_set` |
| GET/POST/PUT/DELETE | `/api/v1/policy/pause` | admin | global/per-profile pause state | `policy.config.invalid` |
| GET/POST/PUT/DELETE | `/api/v1/clients/manual` | admin | manual IP/CIDR entries | `clients.config.invalid` |
| GET | `/api/v1/clients` | admin | client directory/list | – |
| POST | `/api/v1/clients/sync` | admin | trigger UniFi sync | `clients.sync.*` |
| GET/POST/PUT/DELETE | `/api/v1/filter-sets` | admin | filter set configuration | `filtering.config.*` |
| GET/POST/PUT/DELETE | `/api/v1/filter-lists` | admin | URL list management | `filtering.*` |
| GET/POST/PUT/DELETE | `/api/v1/listeners` | admin | listener CRUD | `listeners.config.*` |
| GET/POST/PUT/DELETE | `/api/v1/tls` | admin | TLS config | `tls.config.*` |
| GET | `/api/v1/query-log` | viewer/admin | query-log search / paginate | `control_api.query_log.*` |
| GET | `/api/v1/query-log/{id}` | viewer/admin | single query-log record | `control_api.not_found` |
| GET | `/api/v1/query-log/export.csv` | viewer/admin | CSV export of current filter | `control_api.query_log.export` |
| GET | `/api/v1/query-log/export.ndjson` | viewer/admin | NDJSON stream of current filter | `control_api.query_log.export` |
| GET | `/api/v1/stats/overview` | viewer/admin | aggregated dashboard stats | – |
| GET | `/api/v1/stats/top_clients` | viewer/admin | top N by queries / blocked | – |
| GET | `/api/v1/stats/top_domains` | viewer/admin | top N domains | – |
| GET | `/api/v1/stats/cache` | viewer/admin | cache hit ratio | – |
| GET | `/api/v1/auth/oidc/authorize-url` | public | PKCE authorization URL | `control_api.auth.oidc` |
| GET | `/api/v1/auth/oidc/callback` | public | code exchange, session | `control_api.auth.oidc` |
| POST | `/api/v1/auth/local/login` | public | break-glass login | `control_api.auth.locked` |
| POST | `/api/v1/auth/logout` | viewer/admin | delete session | – |
| GET | `/api/v1/auth/me` | viewer/admin | current principal | – |
| GET/POST | `/api/v1/auth/tokens` | admin | list/create bearer tokens (`viewer`, `admin`, `mcp:read`, `mcp:write`; plaintext shown once) | – |
| DELETE | `/api/v1/auth/tokens/{id}` | admin | revoke token | `control_api.auth.unknown_token` |
| GET | `/api/v1/audit` | viewer/admin | audit log | – |

All paths are stable for v1. Future additions will use `/api/v2` and keep v1
available for at least one full major release.

### MCP-phase endpoints (MCP phase, after v1 core)

These endpoints are required by the `mcp` module (SPEC-mcp.md § Required
control-api additions). They are **not part of the v1 core**: they are built
after Checkpoint F in the MCP phase, and each needs an owner-approved plan (see
tasks/plan-control-api.md § Phase M). They use the same `{data}`/`{error}`
envelopes, auth middleware, audit path and config-apply path as the endpoints
above. `viewer`/`admin` tokens may call the read endpoints; `mcp:read` and
`mcp:write` tokens may **not** call any `/api/v1` endpoint (see § Auth).

`duration` values are the fixed `PT5M`/`PT15M`/`PT1H` set; the configured
maxima can only lower that set (SPEC-mcp.md § Limits and defaults).

| Method | Path | Role | Request | Response | Errors |
|---|---|---|---|---|---|
| POST | `/api/v1/filtering/explain-block` | viewer/admin | `{ "domain": "ads.example.com", "profile_id": "default", "qtype": "A" }` | `{ "data": { "domain": "...", "profile_id": "default", "filter_set_id": "default", "verdict": "blocked" \| "allowed", "reason": { "rule_text": "\|\|ads.example^", "source": "list:adguard-dns:line 1234", "important": false, "block_mode": "refused" } \| null } }` | `policy.config.unknown_filter_set`, `filter_name.*` |
| POST | `/api/v1/policy/test-query` | viewer/admin | `{ "domain": "...", "qtype": "A", "client_id": "...", "source_ip": "192.0.2.10", "protocol": "udp53" }` (`client_id` optional) | `{ "data": { ...DecisionRecord..., "answer": { "rcode": "NXDOMAIN", "records": [] } } }` | `policy.selection.no_view`, `filter_name.*` |
| POST | `/api/v1/filtering/temporary-allows` | admin | `{ "domain": "example.com", "include_subdomains": true, "duration": "PT5M\|PT15M\|PT1H", "filter_set_id": "default", "reason": "..." }` | `{ "data": { "domain": "example.com", "include_subdomains": true, "created_at": "...", "expires_at": "...", "filter_set_id": "default" } }` | `filter_build.invalid_domain`, `filter_build.pattern_not_allowed`, `mcp.domain_too_broad`, `mcp.protected_domain`, `mcp.invalid_input`, `mcp.duration_exceeds_maximum` |
| POST | `/api/v1/filtering/custom-rules` | admin | `{ "domain": "example.com", "include_subdomains": true, "filter_set_id": "default", "reason": "...", "expires_at": "2026-11-25T10:30:00Z" }` (`expires_at` optional; earlier only) | `{ "data": { "rule_text": "\|\|example.com^", "filter_set_id": "default", "domain": "example.com", "include_subdomains": true, "created_at": "...", "expires_at": "..." } }` | `filter_build.*`, `mcp.domain_too_broad`, `mcp.protected_domain`, `mcp.rule_limit_exceeded`, `control_api.config.apply` |
| DELETE | `/api/v1/filtering/custom-rules` | admin | `{ "domain": "example.com", "filter_set_id": "default" }` | `{ "data": { "removed": true, "domain": "example.com", "filter_set_id": "default" } }` | `filter_build.*`, `mcp.protected_domain`, `control_api.config.apply` |
| GET | `/api/v1/filtering/mcp-rules` | viewer/admin | query: `filter_set_id?`, `kind=rules\|temporary_allows\|pauses` (default `rules`), `limit` (default 100, max 500), `offset` | `{ "data": { "filter_set_id": "default", "kind": "rules", "rules": [ { "id": "...", "domain": "example.com", "include_subdomains": true, "rule_text": "\|\|example.com^", "created_at": "...", "expires_at": "...", "filter_set_id": "default" } ], "has_more": false, "next_offset": null } }` (`temporary_allows` and `pauses` use the fields from SPEC-mcp.md) | `policy.config.unknown_filter_set`, `control_api.pagination.invalid` |
| POST | `/api/v1/filtering/pause` | admin | `{ "filter_set_id": "default", "duration": "PT5M\|PT15M\|PT1H" }` | `{ "data": { "filter_set_id": "default", "paused_until": "..." } }` | `policy.config.unknown_filter_set`, `mcp.invalid_input`, `mcp.duration_exceeds_maximum` |
| POST | `/api/v1/filtering/resume` | admin | `{ "filter_set_id": "default" }` | `{ "data": { "filter_set_id": "default", "resumed": true } }` | `policy.config.unknown_filter_set` |

`temporary-allows` and `pause`/`resume` change runtime filtering state;
`custom-rules` add/remove are config mutations (new config version plus audit
entry; see § MCP-managed filter rules). The `mcp.*` codes in the table are
defined by SPEC-mcp.md and are returned unchanged, so direct API callers and the
MCP backend share one contract. `POST /policy/test-query` requires the resolver
to expose a `no_cache_write` flag; the current resolver public API has no such
flag (verified 2026-10-26), so it is a prerequisite of the MCP phase, not an
existing capability.

## Query log

### Record schema

One persisted record per answered DNS query that policy decided was
`loggable == true`. The record is enriched with `clients` data for the source
IP, but never blocks DNS answering.

```json
{
  "id": "uuid",
  "node_id": "node1",
  "listener_id": "lan-udp",
  "protocol": "udp53",
  "source_ip": "192.0.2.10",
  "source_ip_truncated": false,
  "client_id": "iphone-k7q2x9",
  "client": {
    "id": "uuid",
    "display_name": "iPhone",
    "source": "unifi",
    "macs": ["aa:bb:cc:dd:ee:ff"],
    "vlan_id": 40,
    "vlan_name": "IoT",
    "local_domain": "iot.example.com"
  },
  "query": {
    "name": "www.example.com",
    "type": "A",
    "class": "IN"
  },
  "view_id": "lan",
  "profile_id": "default",
  "selection": {
    "cause": "subnet",
    "prefix": "192.0.2.0/24"
  },
  "answer_source": "resolver",
  "filter": null,
  "dnssec": "secure",
  "forward_zone": null,
  "rcode": "NOERROR",
  "answer_size": 184,
  "timings": {
    "select_us": 2,
    "filter_us": 8,
    "resolve_us": 840,
    "total_us": 950
  },
  "time": "2026-10-26T08:15:30.123456Z"
}
```

For a blocked query the `filter` field contains:

```json
{
  "reason": "adblock",
  "block_mode": "nxdomain",
  "rule_text": "||example.com^",
  "list_id": "adguard-dns-filter",
  "important": false
}
```

### Retention and privacy

- Default retention: **30 days** (`query_log_retention_days`).
- `source_ip` can be truncated with `query_log_ip_truncate`:
  - `none` = full IP,
  - `last_octet` = IPv4 `x.x.x.0`,
  - `last_group` = IPv6 first 48 bits.
- Privacy implications: full IPs allow per-device log filtering but increase
  identifiability. The UI explains this during setup. Default for new installs
  is `last_octet`, but the owner may choose `none`.
- Query-log records are written through a bounded channel and dropped with
  `query_log.dropped` counter when the sink is full; DNS answering is never
  blocked.

### Filter/query syntax

The public API uses explicit query parameters, not a free-text DSL:

- `from`, `to` — RFC 3339 UTC timestamps.
- `client_id`, `client_name_substr`
- `domain` — exact normalized owner name, or `domain_substr`
- `protocol` — `udp53|tcp53|dot|doh|doq`
- `view_id`, `profile_id`
- `status` — `allowed|blocked|dnssec_bogus|servfail|...`
- `only_blocked` — boolean
- `only_with_clients` — boolean
- `order_by` — `time`, `client`, `domain`, `rcode`
- `order` — `asc|desc`
- `limit`, `offset`

Limits: no query may return more than `max_query_log_rows_per_request` (default
10 000). CSV export uses streaming from SQLite and obeys the same retention
rules.

### “Why blocked?” data for `mcp`

The `GET /api/v1/query-log/{id}` and `/api/v1/query-log/test-query` endpoints
return the full `policy::DecisionRecord` stored for the query, including:

- ordered `steps` from the policy pipeline,
- `filter` object if blocked,
- `answer_source`,
- `dnssec_status`,
- `forward_zone`,
- `selection_cause`,
- `timings`.

`mcp` can therefore answer questions like “Which rule blocked this for device
X?” without re-running the query and without needing access to policy internals.

## Statistics

### Counters exposed

From `policy`, `resolver`, `listeners` and `clients`:

- total queries
- queries by `protocol`, `view`, `profile`, `answer_source`, `rcode`
- allowed/blocked ratio
- filter hit counts by `list_id`, `rule_text_hash`
- DNSSEC outcomes: `secure`, `insecure`, `bogus`
- cache hit ratio
- query-log drops due to full sink (`query_log.dropped`)
- active clients count from `ClientLookup`

### Aggregation windows

Keep a raw query-log table for ad-hoc filtering (retention default 30 days), plus
two rollup storage levels:

- hourly rollup: `hour`, `profile_id`, `protocol`, `answer_source`, counts
- daily rollup: `day`, `profile_id`, `protocol`, `answer_source`, counts

Rollups retain 365 days by default and allow dashboard periods up to a year.

### Cardinality limits

- `top_clients`: max **1000** entries per window.
- `top_domains`: max **10 000** entries per window.
- `top_rules`: max **10 000** entries per window.
- No cardinality limit on raw query-log rows aside from retention, but queries
  must use `LIMIT` and the API enforces the global row cap.

## Auth

### OIDC flow

- Authorization Code flow with PKCE S256 (RFC 7636).
- State: random 128-bit value, stored in session and matched on callback.
- Nonce: random 128-bit value, sent in authentication request, validated in the
  ID token.
- Token validation:
  - verify ID token signature using OIDC provider JWKS,
  - `iss` exactly matches configured issuer,
  - `aud` matches configured client ID,
  - `nonce` matches session,
  - `exp` not expired,
  - `iat` within allowed skew,
  - `at_hash` when present.
- Role mapping:
  - `viewer` if no configured admin group claim is present,
  - `admin` if the `groups` claim contains the configured admin group name.
  - The groups claim name is configurable; default `groups`.
- Token endpoints use OIDC Discovery where configured.

For tests and to support non-public providers, the OIDC provider must not be
contacted over the internet from CI; tests use an in-process mock provider.

### Break-glass local login

- Separate source of truth from OIDC; only used when OIDC is unreachable or
  intentionally disabled.
- Password hashing: **Argon2id** via the `argon2` crate. Alternative if
  dependency review rejects new crate: `ring::pbkdf2` with HMAC-SHA256 and a
  high iteration count, but Argon2id is preferred.
- Lockout after `local_login_max_attempts` (default 5) within
  `local_login_lock_window` (default 15 min): HTTP 423 with
  `control_api.auth.locked`.
- Every local login success/failure is written to the audit log.
- Local accounts are scoped to `admin` or `viewer` and cannot have more
  privileges than OIDC-mapped roles.

### Sessions vs. tokens

- Browser sessions: random opaque session id, stored hashed in SQLite.
  HttpOnly; Secure when TLS is enabled; SameSite=Lax; CSRF token required for
  all mutating cookie-session requests. Lifetime: 12 h absolute, 60 min idle
  (configurable); no refresh, re-login afterwards. Cookie sessions carry a
  `viewer` or `admin` role and are valid on `/api/v1` only; they never
  authorize `/mcp/v1`.
- Bearer tokens: random opaque token, stored as SHA-256 hash only, shown once
  in the creation response/UI. Optional expiry; no refresh tokens in v1.
  Revocation takes effect immediately by deleting the hash.

**Scopes (four, fixed):**

| Scope | Valid on | Grants |
|---|---|---|
| `viewer` | `/api/v1` only | operational reads (query-log, stats) — configuration-family reads are admin-only |
| `admin` | `/api/v1` only | read and write endpoints |
| `mcp:read` | `/mcp/v1` only | the 8 MCP read tools |
| `mcp:write` | `/mcp/v1` only | all 13 MCP tools (read and write) |

- **Endpoint-family validity is enforced on every request.** A token whose
  scope does not belong to the endpoint family is rejected with HTTP 403
  `control_api.auth.invalid_scope` (for example `viewer` on `/mcp/v1`, or
  `mcp:read` on `/api/v1`). No token is valid on both families. A missing,
  malformed, unknown, revoked or expired bearer token is rejected with HTTP 401
  `control_api.auth.unauthenticated`; `control_api.auth.unknown_token` is
  reserved for token-management calls that address a token id
  (`DELETE /api/v1/auth/tokens/{id}`).
- **Creation:** `POST /api/v1/auth/tokens`, admin only (an admin OIDC/local
  session or an `admin` bearer token). The body selects the scope; the response
  contains the plaintext token exactly once. All four scopes exist from the
  start. The web UI offers `mcp:read` and `mcp:write` with the explanation
  "MCP tokens are for AI assistants and work only on the MCP endpoint, not the
  regular API."
- **Self-signed warning:** while `tls_mode = self_signed`, the token-create
  response (and the web UI) carries the `control_api.tls.self_signed` warning;
  the owner must confirm before an MCP token is issued, because the MCP client
  pins the bootstrap certificate.
- **Tool-level scope denial:** an authenticated `mcp:read` token calling a
  write tool is not an HTTP error; the MCP layer returns a tool result with
  `isError: true` and `control_api.auth.insufficient_scope` (SPEC-mcp.md). The
  same code remains the HTTP 403 code for an authenticated principal that lacks
  a permission on `/api/v1`.
- Token material (plaintext or hash) never appears in config exports, audit
  snapshots or logs.

### CSRF

- Synchronizer token pattern for cookie-authenticated browser sessions.
- API tokens use `Authorization: Bearer <token>` and do not require CSRF
  tokens; same-site browser sessions are the only cookie-authenticated flow.

## Configuration model

### Editable at runtime

- Policy views, profiles, local records, schedules, SafeSearch, rebind,
  pause state.
- Client manual entries, UniFi settings, local domain mode.
- Filter set/lists.
- Listener definitions and limits.
- TLS settings, OIDC settings, local accounts, API tokens.
- Query-log retention and statistics rollup settings.

Bootstrap values from TOML/environment are only used to initialise the first
config generation if SQLite is empty. After that, the API and SQLite are the
source of truth.

### Validation

Every write validates the typed config against the module’s own validation
(`PolicyConfig`, `ClientsConfig`, `ListenersConfig`, filtering config, TLS
config) before storing. For cross-module validation (e.g. profile references a
view, forward-zone id exists), control-api performs an additional pass before
any module `apply_config` call.

### Atomic apply

A config save is an all-or-nothing operation:

1. Validate full configuration and calculate a new generation/version.
2. Persist the new version in a SQLite transaction.
3. Apply to modules sequentially, starting with leaf dependencies:
   - `filtering`
   - `clients`
   - `policy`
   - `listeners`
   - `tls` if needed
4. If any module `apply_config` returns an error, roll back previously applied
   modules by re-applying the previous snapshot, mark the version as failed,
   and return an error with the stable module error code.
5. On success, expose the new config version.

`PolicyEngine`, `ClientEngine`, `ListenerSet` and TLS already use `Arc`
snapshots, so hot reload happens without blocking DNS queries.

### MCP-managed filter rules

`FilterSetConfig` gains `mcp_rules: Vec<McpRule>` (SPEC-mcp.md § Required
changes in other modules): structured block rules created through the MCP
tools, with `id`, `domain`, `include_subdomains`, `created_at`, a mandatory
`expires_at` and the creating `token_id`. They are part of the versioned
configuration, not runtime state.

- **Every `mcp_rules` change is a config mutation.** `POST` and `DELETE` on
  `/api/v1/filtering/custom-rules` validate, persist a new `config_version`,
  apply the filtering snapshot and write an audit entry. They take the same
  serialized config-apply lock as `PUT /api/v1/config`.
- **Cap check inside the lock.** `max_custom_rules_per_set` is checked while
  holding the apply lock, so concurrent `add_rule` calls cannot exceed the cap.
- **Merge rule on `PUT /api/v1/config`.** A config replace carries the existing
  `mcp_rules` of each filter set over unchanged when the request does not
  include that field. Only an explicit `"mcp_rules": []` for a set deletes
  them. An unknown field in the request body is rejected with
  `control_api.config.invalid`; it is never silently dropped.
- **Expiry.** The server sets `expires_at = created_at +
  max_block_rule_lifetime` when the request omits it; a request may supply an
  earlier expiry, never a later one. Expired rules are dropped when the
  filtering snapshot is built.
- **Rollback restores them.** A rollback loads the target snapshot including
  `mcp_rules` and applies it; the audit entry records that MCP-managed rules
  were part of the restored snapshot.
- **Runtime, not config:** temporary allows and filter-set pauses are held in
  `FilterEngine` memory and are not versioned; `PUT /api/v1/config` never
  contains them. The current recommendation (open question in SPEC-mcp.md
  § Persistence and versioning) is that they do not survive a restart.
- **Cluster:** because the rules live in the config snapshot, config
  replication carries them; no separate replication path.

The filtering crate currently has neither `McpRule` nor
`FilterSetConfig::mcp_rules` (verified 2026-10-26); both are prerequisites of
the MCP phase (tasks/plan-control-api.md § Phase M).

### Rollback

Every successful config save creates a `config_versions` row with a complete
snapshot. `POST /api/v1/config/versions/{version}/rollback` restores that
snapshot using the same atomic apply path. Rollback is itself audited.

### Cluster hooks

- Each config object carries a monotonically increasing `version` field
  (`config_version`) for optimistic concurrency.
- Write requests may include `If-Match` header with the last observed version.
  Conflict returns `412 control_api.config.conflict`.
- The cluster module can reuse `/api/v1/config` and `/api/v1/config/versions`
  as the canonical write interface.
- Audit entries include `node_id`, `actor`, `config_version`, and
  `before/after` digests.

## Configuration excerpt (TOML bootstrap)

```toml
[control_api]
bind = "127.0.0.1"
port = 8080
# public flag is denied; API is always internal-only
# Default: TLS with the certificate of the `tls` module (ACME, hot reload). The API is served under the
# node hostname (e.g. node1.dns.example.com), which the wildcard cert *.dns.<public_domain> already covers.
tls = true
# Optional reverse-proxy mode: tls = false plus the proxy addresses allowed to set X-Forwarded-Proto/-For.
# trusted_proxies = ["192.0.2.10"]

[control_api.auth]
oidc_enabled = true
oidc_issuer = "https://auth.example.net/application/o/dnscraft"
oidc_client_id = "dnscraft"
oidc_client_secret = ""          # must come from env DNSCRAFT_OIDC_CLIENT_SECRET / *_FILE
oidc_admin_group = "dnscraft-admin"
# local_secret = ...             # env only
local_login_enabled = true

[control_api.query_log]
retention_days = 30
ip_truncate = "last_octet"       # none | last_octet | last_group
max_rows_per_request = 10000

[control_api.rate_limit]
read_per_second = 100
write_per_second = 20
auth_per_second = 10
burst_factor = 2

[control_api.mcp]
enabled = false                  # off by default; /mcp/v1 returns 404 control_api.not_found while false
write_tools_enabled = false      # independent gate for the 5 MCP write tools
legacy_session_mode = false      # stateless 2026-07-28 only; client compatibility is unverified
max_concurrent_requests_per_token = 5
request_timeout = "60s"
max_request_body_size = "1MiB"
max_temporary_allow_duration = "1h"   # <= 1h; can only lower the fixed PT5M/PT15M/PT1H set
max_pause_duration = "1h"             # <= 1h; can only lower the fixed PT5M/PT15M/PT1H set
max_custom_rules_per_set = 100
max_block_rule_lifetime = "30d"
protected_domains = []           # additional domains beyond the auto-derived protected list
```

The MCP limits and the derivation of `protected_domains` are specified in
SPEC-mcp.md § Limits and defaults and § Protected domains.

Limits/defaults:

| Setting | Default | Limit |
|---|---|---|
| `retention_days` | 30 | 1–3650 |
| `ip_truncate` | `last_octet` | enum |
| `max_rows_per_request` | 10000 | 100–100000 |
| `local_login_max_attempts` | 5 | 1–20 |
| `local_login_lock_window` | 15m | 1m–24h |
| `oidc_token_skew` | 30s | 5–300 |
| `api_token_max_ttl` | 365d | 1–3650d |
| `session_idle_timeout` | 30m | 5m–24h |
| `session_absolute_timeout` | 24h | 1h–7d |

### MCP mount

`/mcp/v1` is mounted by control-api on the same internal listener via
`axum::Router::nest_service("/mcp/v1", service)`. The service and the
`McpBackend` trait are defined in the `mcp` crate; control-api depends on `mcp`
(not the reverse) and supplies the backend implementation. MCP is off by
default: while `control_api.mcp.enabled = false`, every request to `/mcp/v1`
returns HTTP 404 with `control_api.not_found`. The token scopes and the
`/api/v1` ↔ `/mcp/v1` separation are in § Auth; the protocol surface is in
SPEC-mcp.md. Mounting is part of the MCP phase (tasks/plan-control-api.md
§ Phase M), not the v1 core.

## Error codes

Every error has stable `code()` (`control_api.<area>.<reason>`), uniqueness
tested. Codes are forwarded from module errors where applicable.

| Code | When |
|---|---|
| `control_api.config.invalid` | malformed request body, missing required field |
| `control_api.config.read` | unable to read current config snapshot |
| `control_api.config.apply` | one or more module apply operations failed |
| `control_api.config.version` | version conflict / invalid If-Match |
| `control_api.config.unknown_version` | rollback target does not exist |
| `control_api.not_found` | route or identifiable object missing |
| `control_api.internal` | invariant violation / unexpected panic boundary |
| `control_api.method_not_allowed` | route exists but the HTTP method is not allowed (HTTP 405) |
| `control_api.payload_too_large` | request body exceeds the configured cap (HTTP 413) |
| `control_api.rate_limited` | request exceeds API rate limit |
| `control_api.query_log.read` | SQLite/other query-log read error |
| `control_api.query_log.export` | CSV export failed |
| `control_api.query_log.dropped` | sink dropped query events (informational) |
| `control_api.query_log.invalid` | malformed query-log filter parameter (HTTP 400) |
| `control_api.auth.oidc` | OIDC provider/configuration error |
| `control_api.auth.local` | local login credential failure |
| `control_api.auth.locked` | local account temporarily locked |
| `control_api.tls.self_signed` | warning (status, not an HTTP error): serving the self-signed bootstrap certificate |
| `control_api.auth.unknown_token` | token id not found or not owned by actor (token-management calls only) |
| `control_api.auth.unauthenticated` | missing, malformed, unknown, revoked or expired bearer token (HTTP 401) |
| `control_api.auth.invalid_scope` | token scope is not valid for this endpoint family (HTTP 403) |
| `control_api.auth.invalid_origin` | `Origin` header present and invalid (HTTP 403; MCP) |
| `control_api.auth.insufficient_scope` | authenticated principal lacks the permission (HTTP 403); also the MCP tool-level code when an `mcp:read` token calls a write tool |
| `control_api.auth.session_expired` | cookie session expired |
| `control_api.auth.csrf` | missing/invalid CSRF token |
| `control_api.audit.read` | audit log read failure |
| `control_api.not_ready` | one or more modules not ready |

When a module error is propagated, the original code (e.g.
`policy.config.unknown_filter_set`) is used, not replaced with a generic
control-api code. The API wrapper may add context parameters. MCP tool-level
errors reuse `control_api.auth.insufficient_scope` and may also carry `mcp.*`
codes defined in SPEC-mcp.md; uniqueness is enforced workspace-wide.

**Implementation reality check (2026-10-26):** `control_api.method_not_allowed`,
`control_api.payload_too_large`, `control_api.auth.insufficient_scope` and
`control_api.auth.unknown_token` already exist as variants in
`crates/dnscraft-api/src/error.rs`. The variants still to add are
`control_api.auth.unauthenticated`, `control_api.auth.invalid_scope` and
`control_api.auth.invalid_origin`; A0's error-code uniqueness test must cover
them once A7 adds them.

## Security considerations

### Threat model

- All API paths are internal-only. Reverse proxies may be used, but the API
  itself must bind only to loopback or private/ULA addresses.
- Attackers submitting DNS queries cannot reach the API through public DoH/DoT
  listeners; `listeners` routes only `/dns-query/...` on public listeners.
- Query log data is attacker-influenced. Treat it as untrusted; never use it to
  build SQL without bind parameters.
- Token/session IDs are random and stored only as hashes.
- Secret material (OIDC client secret, TLS private keys, UniFi API key) is never
  returned by any config endpoint. It comes from environment / `*_FILE` and is
  not persisted by control-api.

### Audit log

- Every mutating request records `time`, `node_id`, `actor_id`, `actor_type`
  (`user`, `token`), `action`, `object_type`, `object_id`,
  `config_version`, `before_digest`, `after_digest`, `before` / `after` (redacted JSON
  snapshots, secrets masked), `result`, `error_code`.
- Audit log is append-only; delete/rollback actions are themselves audited.
- `viewer` users cannot access the audit log unless granted admin role.

### API TLS

Direct TLS is the default (`control_api.tls = true`): `rustls` with the
project's ring-only policy and the `CertResolver` of the `tls` module, so ACME
renewal and hot reload apply to the API automatically. The API is addressed by
its node hostname (`<node>.dns.<public_domain>`, covered by the wildcard
certificate). That name must resolve to the node's internal address for
internal clients (split-horizon / local name); it is never exposed publicly.
Bootstrap certificate: while the `tls` module has no certificate (first start,
ACME not configured or not yet issued), control-api serves a **self-signed**
certificate so the API and web UI are reachable over TLS from the start. It is
generated once with `rcgen` (already a workspace dependency, ring backend;
ECDSA P-256, SANs = configured node hostname + `localhost`, validity 1 year),
persisted in the data directory (private key mode 0600) and reused across
restarts. The listener's resolver picks the ACME certificate as soon as
`CertResolver::has_cert()` is true and falls back to the self-signed one
otherwise; no restart needed. Rules: the self-signed certificate is never
served for a hostname that has a valid ACME certificate; the status endpoint
reports `tls_mode` (`acme` | `self_signed`) plus the SHA-256 fingerprint so the
owner can pin it on first use; a `control_api.tls.self_signed` warning appears
in status and log while it is active; bearer tokens for `mcp` should not be
issued while `tls_mode = self_signed` unless the owner confirms (warning in
the token-create response). Regenerated automatically when expired or when the
node hostname changes.
Reverse-proxy mode is optional: `tls = false` plus `trusted_proxies`;
forwarded headers are honoured only from those addresses, and `Secure` cookies
follow `X-Forwarded-Proto`. Never self-signed in production.

### Rate limits and lockouts

All auth and write endpoints have stricter limits than read endpoints. Failed
local login attempts are tracked per principal IP and per user. OIDC callback
uses state/nonce/PKCE to prevent CSRF/login CSRF.

## Testing strategy

No internet and no real Authentik/Cloudflare in CI.

- **Unit tests:** config validation, RBAC checks, error mapping, query-log
  filter parsing, pagination edge cases, retention calculation, audit hashing,
  token/session hash generation, Argon2id verify.
- **Integration with mock OIDC provider:** in-process HTTP server implementing
  discovery, authorization, token and JWKS endpoints. Verifies callback flow,
  state/nonce/PKCE, role mapping from groups claim, invalid signature, expired
  token, wrong audience.
- **Integration with in-memory/temporary SQLite:** CRUD endpoints, atomic apply
  rollback, config version conflict, query log filtering/export, stats rollups.
- **Module adapters:** fake implementations of `PolicyEngine`, `ClientEngine`,
  `ListenerSet`, `Resolver` status, TLS status. Verify apply order and rollback
  on failures.
- **API protocol tests:** axum/hyper test server on `127.0.0.1`; no real
  network cards.
- **MCP readiness tests:** ensure token-based read/write roles match future
  `mcp` expectations; endpoints expose stable, documented JSON.
- **Fuzz:** request parse, query-log filter arguments, auth callback inputs.
- **Coverage:** control-api has no hard coverage threshold in SPEC.md, but aim
  for ≥ 80 % of non-HTTP glue logic.

## Success Criteria

1. All documented `/api/v1` endpoints exist and return the documented status
   codes and error envelope.
2. A config PUT validates, persists, applies to all modules, and increments
   `config_version`; any module failure rolls back the previous snapshot.
3. Query-log endpoints return records enriched with `clients` fields when a
   matching client exists; filter/order/pagination works with at least 10 000
   inserted test rows.
4. “Why blocked?” response contains the full `policy::DecisionRecord` data
   needed to identify the reason, rule, list and profile.
5. OIDC flow works against a mock provider with PKCE and nonce; an invalid or
   expired ID token is rejected.
6. Local break-glass login works, locks after 5 failed attempts for 15 minutes,
   writes audit events, and verifies passwords with Argon2id.
7. Viewer cannot call admin endpoints; admin can. Every bearer token carries
   exactly one of the four scopes (`viewer`, `admin`, `mcp:read`, `mcp:write`);
   a token from the wrong endpoint family is rejected with
   `control_api.auth.invalid_scope`, and no token is valid on both `/api/v1`
   and `/mcp/v1`.
8. Audit log contains coherent before/after digests for config changes and at
   least one entry for every local/OIDC login failure.
9. Internal-only binding is enforced: API does not bind to `0.0.0.0`/`::` and
   does not answer on public listener ports.
10. No real Authentik/Cloudflare/OIDC provider is contacted in tests. `cargo
    fmt`, `clippy -D warnings`, `cargo test --workspace` and `cargo deny check`
    are green.
11. The TLS bootstrap self-signed certificate is served only while no ACME
    certificate exists, reports `tls_mode` and fingerprint, and switches to the
    ACME certificate automatically without a restart.
12. NDJSON export is the primary streaming query-log export format and obeys
    the current filters and retention; CSV export remains available as a
    convenience.
13. Audit before/after snapshots are stored as redacted JSON with secret
    material masked; no plaintext secret from config/environment appears in the
    audit log or in any query-log record.

## Candidate dependencies

Workspace crates already pinned in the root `Cargo.toml` are reused with their
workspace versions and features (`tokio`, `serde`, `serde_json`, `time`,
`base64`, `ring`, `http`, `hyper`, `hyper-util`, `http-body-util`, `bytes`,
`reqwest` 0.13 with `rustls-no-provider`, `rustls`, `tokio-rustls`). Anything
below is new and needs one-time owner approval. Versions were **not**
checked against crates.io for this draft (unverified); the P1 plan must run
`cargo search` and cite docs.rs for each.

| Crate | Candidate | Features | Licence | Why / alternatives |
|---|---|---|---|---|
| `axum` | latest 0.8.x | `json`, `query`, `http1` (no default TLS) | MIT | Router/extractors on the existing `hyper`/`tokio` stack; alternative: hand-rolled on `hyper` (more code, no new dep) |
| `tower-http` | latest 0.6.x | `trace` only | MIT | Tracing middleware; skip if `tracing` spans in handlers suffice |
| `rusqlite` | latest | `bundled` | MIT | SQLite persistence, fixed by SPEC.md stack; `bundled` compiles C SQLite (no system lib) |
| `argon2` | latest 0.5.x | `std` | MIT/Apache-2.0 | Argon2id for break-glass; pure Rust. Alternative without new dep: `ring::pbkdf2` (PBKDF2-HMAC-SHA256) |
| `uuid` | latest 1.x | `v4` | MIT/Apache-2.0 | Entity IDs; alternative: `ring::rand` + hex, no new dep |
| `openidconnect` | latest | custom HTTP client, **no** `reqwest` default features | MIT/Apache-2.0 | Discovery, JWKS and ID-token validation; alternative: hand-rolled validation on `ring::signature` + `reqwest` (more code, more risk). It must not pull `aws-lc-rs`, `openssl-sys` or `native-tls`: verify with `cargo tree` before approval |

Not needed: `sha2` (use `ring::digest` for token/session hashing), a separate
`reqwest` entry (use the workspace one, `rustls-no-provider`, with the ring
provider installed as in `dnscraft-tls`), `base64` and `time` (workspace).

Ring-only enforcement: before merging control-api, run `cargo tree -i
aws-lc-rs`, `cargo tree -i aws-lc-sys`, `cargo tree -i openssl-sys` and
`cargo deny check`; all must stay empty/green. If `openidconnect` cannot be
made ring-only, fall back to the hand-rolled variant and record it in an ADR.

References (to be re-checked in P1): OIDC Core
<https://openid.net/specs/openid-connect-core-1_0.html>, PKCE RFC 7636
<https://www.rfc-editor.org/rfc/rfc7636>, OAuth 2.0 RFC 6749
<https://www.rfc-editor.org/rfc/rfc6749>, Argon2 RFC 9106
<https://www.rfc-editor.org/rfc/rfc9106>.

## Decisions (owner delegated, 2026-10-26)

The owner delegated these to Claude ("whatever is most sensible"). They are
binding for the plan unless the owner overrides them.

| # | Question | Decision | Reason |
|---|---|---|---|
| 1 | Direct TLS on the API listener? | **Default on**, using the `tls` module's `CertResolver` (ACME, hot reload) under the node hostname; until a real certificate exists a persisted **self-signed bootstrap certificate** (`rcgen`) is served and replaced automatically. Internal-only bind. A reverse proxy is **optional** (`tls = false` + `trusted_proxies`). *(Revised after owner feedback.)* | No extra component needed; the wildcard cert already covers node hostnames. |
| 2 | `argon2` vs `ring::pbkdf2` | **`argon2` (Argon2id)**, new dependency subject to the P1 dependency approval. | Memory-hard, RFC 9106; the ring-only rule is about the TLS/crypto backend and `argon2` is pure Rust. PBKDF2 stays the documented fallback. |
| 3 | Missing / empty groups claim | Role **`viewer`** only. `admin` only when the configured admin group is present. One configurable admin group; **no** multi-role mapping in v1. | Safe default (least privilege), simple to explain. |
| 4 | Session refresh | **No refresh.** Absolute session lifetime 12 h plus idle timeout 60 min (both configurable), then re-login. | No refresh-token storage, smaller attack surface. |
| 5 | Query-log export | **NDJSON streaming** (`/api/v1/query-log/export.ndjson`) is the primary format; CSV (`export.csv`) stays as a convenience for humans. Both obey the same filters and retention. | `mcp` and scripts consume NDJSON easily; CSV is cheap once streaming exists. |
| 6 | Resolver stats type | Use the existing public `ResolverStats` / `PrimingStatus`; control-api maps them to a read-only DTO. **No** facade in the resolver crate for now. | Avoids touching a finished module; revisit if the type changes. |
| 7 | Rate limits | One set of defaults for all deployments, **configurable in the TOML**; no separate cluster profile in v1. | Cluster is a later module; premature to split. |
| 8 | Audit before/after | Store **redacted JSON** before/after snapshots (secrets masked) plus the digest and `config_version`. | Makes "who changed what" answerable; the digest alone is not useful for humans. |

Consequences for the body of this spec: API TLS defaults on with a self-signed bootstrap
certificate (status warning `control_api.tls.self_signed`, see Error codes);  the endpoint table gains
`GET /api/v1/query-log/export.ndjson` (error code
`control_api.query_log.export`); the audit-log section stores redacted
snapshots; session defaults are 12 h absolute / 60 min idle.
