# Spec: control-api

> Module id `control-api` · crate `crates/dnscraft-api` · depends on: `policy`, `clients`
> (reads `resolver`, `listeners`, `tls` state only through narrow read traits / status handles)
> Project-wide decisions: [SPEC.md](SPEC.md)
> Consumers later: `web-ui`, `mcp`, `cluster`
> Status: DRAFT, owner questions decided 2026-10-26 (see "Decisions"); awaiting final approval

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

### Endpoint table

| Method | Path | Role | Request / response summary | Errors |
|---|---|---|---|---|
| GET | `/healthz` | public | liveness only | – |
| GET | `/readyz` | public | readiness aggregates resolver/listener/config states | `control_api.not_ready` |
| GET | `/api/v1/status` | viewer/admin | node status, module status, build version | `control_api.internal` |
| GET | `/api/v1/config` | viewer/admin | full current config export (secrets excluded) | `control_api.config.read` |
| PUT | `/api/v1/config` | admin | atomic config replace; returns new version | `control_api.config.invalid`, `control_api.config.apply` |
| GET | `/api/v1/config/versions` | viewer/admin | list previous config versions | `control_api.config.version` |
| POST | `/api/v1/config/versions/{version}/rollback` | admin | restore version | `control_api.config.unknown_version` |
| GET | `/api/v1/policy/views` | viewer/admin | list views | – |
| GET | `/api/v1/policy/views/{id}` | viewer/admin | single view | `control_api.not_found` |
| PUT/POST | `/api/v1/policy/views/{id}` | admin | create/update view | `policy.config.invalid` etc. |
| DELETE | `/api/v1/policy/views/{id}` | admin | delete view | `control_api.not_found` |
| GET/POST/PUT/DELETE | `/api/v1/policy/profiles/{id}` | admin | profile CRUD | `policy.config.unknown_filter_set` |
| GET/POST/PUT/DELETE | `/api/v1/policy/pause` | admin | global/per-profile pause state | `policy.config.invalid` |
| GET/POST/PUT/DELETE | `/api/v1/clients/manual` | admin | manual IP/CIDR entries | `clients.config.invalid` |
| GET | `/api/v1/clients` | viewer/admin | client directory/list | – |
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
| GET/POST | `/api/v1/auth/tokens` | admin | create list of API tokens | – |
| DELETE | `/api/v1/auth/tokens/{id}` | admin | revoke token | `control_api.auth.unknown_token` |
| GET | `/api/v1/audit` | viewer/admin | audit log | – |

All paths are stable for v1. Future additions will use `/api/v2` and keep v1
available for at least one full major release.

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
  (configurable); no refresh, re-login afterwards.
- `mcp`/API tokens: random opaque bearer token, stored as SHA-256 hash only.
  Token has `scope` (`viewer`/`admin`) and optional expiry. No refresh tokens
  in v1.
- Tokens are shown once in the API response/UI. Revocation takes effect
  immediately by deleting the hash.

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
tls = false
# if tls is true, cert paths are required and managed by the 'tls' module
# cert_file = "..."
# key_file = "..."

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
```

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
| `control_api.rate_limited` | request exceeds API rate limit |
| `control_api.query_log.read` | SQLite/other query-log read error |
| `control_api.query_log.export` | CSV export failed |
| `control_api.query_log.dropped` | sink dropped query events (informational) |
| `control_api.auth.oidc` | OIDC provider/configuration error |
| `control_api.auth.local` | local login credential failure |
| `control_api.auth.locked` | local account temporarily locked |
| `control_api.auth.unknown_token` | token id not found or not owned by actor |
| `control_api.auth.insufficient_scope` | role lacks permission |
| `control_api.auth.session_expired` | cookie session expired |
| `control_api.auth.csrf` | missing/invalid CSRF token |
| `control_api.audit.read` | audit log read failure |
| `control_api.not_ready` | one or more modules not ready |

When a module error is propagated, the original code (e.g.
`policy.config.unknown_filter_set`) is used, not replaced with a generic
control-api code. The API wrapper may add context parameters.

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

When direct TLS is enabled (`control_api.tls = true`), use `rustls` with the
project’s ring-only policy. Certificates for the API listener are managed by
the `tls` module or provided as local files; never self-signed in production.

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
7. Viewer cannot call admin endpoints; admin can; MCP viewer/admin token scopes
   map cleanly to existing role checks.
8. Audit log contains coherent before/after digests for config changes and at
   least one entry for every local/OIDC login failure.
9. Internal-only binding is enforced: API does not bind to `0.0.0.0`/`::` and
   does not answer on public listener ports.
10. No real Authentik/Cloudflare/OIDC provider is contacted in tests. `cargo
    fmt`, `clippy -D warnings`, `cargo test --workspace` and `cargo deny check`
    are green.

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
| 1 | Direct TLS on the API listener? | Optional, **default off**. Bind to loopback / internal address; a reverse proxy is the documented default. `control_api.tls = true` uses the `tls` module's `CertResolver`. | Most homelab setups already have a proxy; the option costs little since `tls` exists. |
| 2 | `argon2` vs `ring::pbkdf2` | **`argon2` (Argon2id)**, new dependency subject to the P1 dependency approval. | Memory-hard, RFC 9106; the ring-only rule is about the TLS/crypto backend and `argon2` is pure Rust. PBKDF2 stays the documented fallback. |
| 3 | Missing / empty groups claim | Role **`viewer`** only. `admin` only when the configured admin group is present. One configurable admin group; **no** multi-role mapping in v1. | Safe default (least privilege), simple to explain. |
| 4 | Session refresh | **No refresh.** Absolute session lifetime 12 h plus idle timeout 60 min (both configurable), then re-login. | No refresh-token storage, smaller attack surface. |
| 5 | Query-log export | **NDJSON streaming** (`/api/v1/query-log/export.ndjson`) is the primary format; CSV (`export.csv`) stays as a convenience for humans. Both obey the same filters and retention. | `mcp` and scripts consume NDJSON easily; CSV is cheap once streaming exists. |
| 6 | Resolver stats type | Use the existing public `ResolverStats` / `PrimingStatus`; control-api maps them to a read-only DTO. **No** facade in the resolver crate for now. | Avoids touching a finished module; revisit if the type changes. |
| 7 | Rate limits | One set of defaults for all deployments, **configurable in the TOML**; no separate cluster profile in v1. | Cluster is a later module; premature to split. |
| 8 | Audit before/after | Store **redacted JSON** before/after snapshots (secrets masked) plus the digest and `config_version`. | Makes "who changed what" answerable; the digest alone is not useful for humans. |

Consequences for the body of this spec: the endpoint table gains
`GET /api/v1/query-log/export.ndjson` (error code
`control_api.query_log.export`); the audit-log section stores redacted
snapshots; session defaults are 12 h absolute / 60 min idle.
