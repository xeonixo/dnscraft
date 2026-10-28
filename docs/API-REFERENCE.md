# API Reference (Explorer)

Every API function DNScraft exposes, in one place. Covers the two surfaces the
control plane offers: the **REST control API** (`/api/v1`, implemented in
`crates/dnscraft-api`) and the **MCP tool API** (13 tools implemented in
`crates/dnscraft-mcp`, to be mounted under `/mcp/v1`).

Source of truth is the code, not this file: route assembly lives in
[`crates/dnscraft-api/src/api/router.rs`](../crates/dnscraft-api/src/api/router.rs)
and RBAC in
[`crates/dnscraft-api/src/api/auth/roles.rs`](../crates/dnscraft-api/src/api/auth/roles.rs);
MCP tools are registered in
[`crates/dnscraft-mcp/src/tools/`](../crates/dnscraft-mcp/src/tools/). The formal
specs are [`SPEC-control-api.md`](../SPEC-control-api.md) and
[`SPEC-mcp.md`](../SPEC-mcp.md).

## Conventions

- All REST routes are under `/api/v1`; `/healthz` and `/readyz` sit at the root.
- Responses are JSON. Success envelope `{ "data": … }`, error envelope
  `{ "error": { "code": "area.reason", "params": … } }`. Error codes are
  locale-neutral.
- Timestamps are UTC RFC 3339. IDs are strings (UUIDs canonical RFC 4122).
- Pagination: `limit` (default 50, max 500) + `offset`, with `next_offset` /
  `has_more` in the response.
- Concurrency control on mutating config: optional `If-Match: <version>` header;
  mismatch returns `409 control_api.config.version`.
- Body limit: 1 MiB (`413 control_api.payload_too_large`).
- Rate limits (per source IP and per principal): reads `100/s` burst `200`,
  writes `20/s` burst `40`, auth `10/s` burst `20`; exceeded →
  `429 control_api.rate_limited`.

## Roles

Bearer tokens carry one of four fixed scopes; cookie sessions map to
`viewer`/`admin`.

| Scope | Family | Grants |
|---|---|---|
| `viewer` | `/api/v1` | operational reads only (query-log, stats) |
| `admin` | `/api/v1` | all reads + writes |
| `mcp:read` | `/mcp/v1` | read tools |
| `mcp:write` | `/mcp/v1` | read + write tools |

A scope used on the wrong family → `403 control_api.auth.invalid_scope`; a role
missing the permission → `403 control_api.auth.insufficient_scope`; missing /
invalid credential → `401 control_api.auth.unauthenticated`.

**Configuration-family reads are admin-only.** `/config`, `/policy`, `/clients`,
`/filter-sets`, `/filter-lists`, `/listeners` and `/tls` require `admin` even for
`GET`, because they expose network topology, filter rules and TLS settings.

## REST endpoints — implemented

### Liveness / readiness (public)

| Method | Path | Summary |
|---|---|---|
| GET | `/healthz` | Liveness only. `{ "ok": true }` |
| GET | `/readyz` | Readiness aggregates module state. `503 control_api.not_ready` with the failing `modules` when not ready. |

### Status (public)

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/status` | Build `version`, `ready` and `modules_not_ready` (names), TLS mode (`self_signed`/`acme`/`manual`), leaf fingerprint, and `warnings` (`control_api.tls.self_signed` while self-signed). TLS fields omitted in reverse-proxy mode. |

### Config (admin)

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/config` | Current `version` + stored snapshot (secrets redacted). |
| PUT | `/api/v1/config` | Validate + atomic replace of the whole config. `mcp_rules` are carried over when omitted, `[]` deletes them, an unknown field is `control_api.config.invalid`. Returns the new `version`. |
| POST | `/api/v1/config/validate` | Dry run of `PUT /config`: returns `valid`, `errors`, `diff`; HTTP 200 even when invalid. No version bump, no audit row. |
| GET | `/api/v1/config/versions` | Previous versions, newest first, paginated (`created_at` is RFC 3339). |
| POST | `/api/v1/config/versions/{version}/rollback` | Restore a stored version. `control_api.config.unknown_version` if absent. |

### Policy (admin)

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/policy/views` | List views. |
| GET / PUT / POST / DELETE | `/api/v1/policy/views/{id}` | Read / create-or-replace / delete one view. A view carries `subnets`, `nodes` (empty = every node; the default view must be empty) and `profile`. |
| GET | `/api/v1/policy/records` | Local records: one global name space. Each entry has `name`, `type` (A, AAAA, CNAME, TXT, SRV, MX, PTR), `ttl`, `rdata` and per-view `overrides` (presentation text, e.g. `192.0.2.10`, `10 mx.example.com.`). |
| PUT / POST | `/api/v1/policy/records` | Create or replace the record `{ "name", "type", "ttl"?, "rdata", "overrides"? }`. One entry per name and type through this API; `policy.config.invalid` on bad type or value. |
| DELETE | `/api/v1/policy/records` | Remove the record with body `{ "name", "type" }`. `control_api.not_found` if absent. |
| GET | `/api/v1/policy/client-ids` | DoH/DoT Client-ID registry (`client_ids`). Admission only; never a selection key. |
| POST | `/api/v1/policy/client-ids` | Register `{ "id" }` (`[a-z0-9-]{1,63}`). Duplicates are `policy.config.invalid`. |
| DELETE | `/api/v1/policy/client-ids/{id}` | Revoke a Client ID. `control_api.not_found` if absent. |
| GET / PUT / POST / DELETE | `/api/v1/policy/profiles/{id}` | Profile CRUD. `policy.config.unknown_filter_set` on bad references. |
| GET / PUT / POST / DELETE | `/api/v1/policy/pause` | Global/per-profile pause state (singleton). |

### Clients (admin)

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/clients/manual` | Manual IP/CIDR/domain entries. |
| POST / PUT / DELETE | `/api/v1/clients/manual` | Add / create-or-replace / delete (body `{ "name": … }`) a manual entry. |
| GET | `/api/v1/clients` | Manual entries + the synced directory (`id`, `name`, `dns_label`, `local_domain`, `source`, `ips`, `macs`, `vlan`, `online`, `last_seen`). The directory is empty until the binary wires a `ClientDirectory` adapter. |
| POST | `/api/v1/clients/sync` | Trigger a UniFi sync; returns `generation`, `rebuilt`, `client_count`, `ip_conflicts`. `clients.sync.not_configured` without an adapter. |

### Filtering (admin)

| Method | Path | Summary |
|---|---|---|
| GET / POST / PUT / DELETE | `/api/v1/filter-sets` | Filter-set CRUD (`id`, `name`, `lists`, `custom_rules`, `services`, `block_mode`, `mcp_rules`). Pauses are runtime state, not a field here. |
| GET / POST / PUT / DELETE | `/api/v1/filter-lists` | Filter-list CRUD (URL list sources). Local `file` sources are path-traversal-guarded (`filtering.list_source_path_not_safe`). |

### Listeners (admin)

| Method | Path | Summary |
|---|---|---|
| GET / POST / PUT / DELETE | `/api/v1/listeners` | Listener CRUD (`id`, `protocol`, `address`, `exposure`, `h3`). Forwards `listeners.config.*`. |

### TLS (admin)

| Method | Path | Summary |
|---|---|---|
| GET / PUT / POST / DELETE | `/api/v1/tls` | TLS config singleton (`public_domain`, `extra_sans`, `key_type`, `renew_before`, `expiry_warn`, `acme`, `cloudflare`, `dyndns`). Cloudflare API token is supplied out-of-band, never via this route. |

### Query log (viewer/admin)

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/query-log` | Filtered, ordered, paginated search. |
| GET | `/api/v1/query-log/{id}` | One record with the full decision record ("why blocked?"). |
| GET | `/api/v1/query-log/export.ndjson` | NDJSON stream of the current filter. |
| GET | `/api/v1/query-log/export.csv` | CSV export of the current filter. |

Query-log query parameters: `from`, `to`, `client_id`, `client_name_substr`,
`domain`, `domain_substr`, `protocol`, `view_id`, `profile_id`, `status`,
`only_blocked`, `only_with_clients`, `order_by`, `order`, `limit`, `offset`.
Malformed values → `control_api.query_log.invalid`.

### Stats (viewer/admin)

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/stats/overview` | Dashboard aggregate: totals, `by_*` breakdowns, `active_clients` (distinct attributed clients), `query_log_dropped` (sink drops since process start, node-local), `filter_hits` (`total`, `by_list`, `by_reason`, `top_rules` max 10). `source` is `raw`, or `rollup` when `from` lies before the raw retention horizon; rollup mode is day-granular, has no `by_view`, `by_rcode`, `dnssec`, `active_clients` or `filter_hits` (empty or `null`), and counts `blocked` from the `filter_block` answer origin. |
| GET | `/api/v1/stats/top_clients` | Top clients by queries/blocked. |
| GET | `/api/v1/stats/top_domains` | Top domains. |
| GET | `/api/v1/stats/cache` | Cache hit ratio. |
| GET | `/api/v1/stats/domains/{name}?days=7\|30` | One domain over the raw query log: `counts`, `first_seen`/`last_seen` (retention bounded), `daily`, `top_clients` (max 10), `last_decision`. `control_api.not_found` when unseen, `control_api.stats.invalid_domain` for a bad name or `days`. |

Stats query parameters: `from`, `to`, `node_id`, `profile_id` (exact filters, GM6; `overview`, `top_clients`, `top_domains`, `cache`), `limit`, `by`.

### Resolver (viewer/admin read, admin write)

| Method | Path | Role | Summary |
|---|---|---|---|
| GET | `/api/v1/resolver/upstreams` | viewer/admin | Passive upstream health (`up`/`degraded`/`down`/`unknown`) over a 5 min window. |
| POST | `/api/v1/resolver/cache/flush` | admin | Flush the whole cache (`{}`) or one domain and its subtree (`{"domain": "…"}`). Audited; returns `evicted`. |

### Alerts (viewer/admin)

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/alerts` | Active alerts: `active_count` and `items` (`id`, `severity`, `module`, `params`, `target_route`). Sources: TLS (revoked, expired, expiring, DynDNS stale), failed filter-list updates, sub-node without master. |

### Auth

| Method | Path | Role | Summary |
|---|---|---|---|
| POST | `/api/v1/auth/tokens` | admin | Create a bearer token (`viewer`/`admin`/`mcp:read`/`mcp:write`); plaintext shown once, hash stored. |
| GET | `/api/v1/auth/tokens` | admin | List tokens (`id`, `name`, `scope`, `actor_id`, RFC 3339 `created_at`/`expires_at`); never the plaintext. |
| DELETE | `/api/v1/auth/tokens/{id}` | admin | Revoke a token; `control_api.auth.unknown_token` (404) if absent. Audited. |
| POST | `/api/v1/auth/local/login` | public | Break-glass login with a provisioned local account. `control_api.auth.locked` on lockout, per account and per source IP. |
| POST | `/api/v1/auth/logout` | viewer/admin | Ends the cookie session. Audited. |
| GET | `/api/v1/auth/me` | viewer/admin | Current principal: `role`, `actor_id`, `actor_type`, `csrf_token` (cookie sessions). |
| GET | `/api/v1/auth/sessions` | viewer/admin | Live sessions: own by default, `scope=all` for admins. Rows carry `id` (not the cookie), `client_label`, truncated `ip`, `created_at`, `last_seen`, `expires_at`, `current`. |
| DELETE | `/api/v1/auth/sessions/{id}` | viewer/admin (own), admin (any) | Revoke a session. `control_api.auth.session_current` (409) for the current one, `control_api.auth.unknown_session` (404) for an unseen or foreign id. Audited. |
| GET | `/api/v1/auth/oidc/authorize-url` | public | PKCE S256 + nonce authorization URL. |
| GET | `/api/v1/auth/oidc/callback` | public | Code exchange → cookie session. `auth.oidc.login` audit row on success and failure. |

### Audit (admin)

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/audit` | Newest first, `limit`/`offset`; secrets masked; `time` is RFC 3339. |

## REST endpoints — planned, not yet mounted

These are in the spec but not in `router.rs` yet; do not call them.

| Method | Path | Role |
|---|---|---|
| GET | `/api/v1/update/check` | viewer/admin (WP2, not built) |
| GET / PUT | `/api/v1/backups`, `/api/v1/backups/settings` | admin (WP3, not built) |
| GET / PUT | `/api/v1/filtering/services` | viewer/admin, admin (WP5, needs the service catalog) |
| GET / PUT | `/api/v1/notifications`, POST `/api/v1/notifications/test` | viewer/admin, admin (WX7, owner decisions open) |
| GET | `/api/v1/query-log/stream` | viewer/admin, SSE (WX2, not built) |

The MCP-phase REST endpoints (`/api/v1/filtering/explain-block`,
`/api/v1/policy/test-query`, `/api/v1/filtering/temporary-allows`,
`/api/v1/filtering/custom-rules`, `/api/v1/filtering/mcp-rules`,
`/api/v1/filtering/pause`, `/api/v1/filtering/resume`) are also planned for
Phase M; their shapes are in `SPEC-control-api.md` § MCP-phase endpoints. They
are **not** part of the implemented surface.

## MCP tools

The `dnscraft-mcp` crate implements all 13 tools and exposes a stateless
`service()` meant to be mounted by `control-api` under `/mcp/v1`. The mount is
not wired yet (`dnscraft-api` has no `dnscraft-mcp` dependency); it lands in
Phase 3 (M20–M27). Tools use the same tokens/roles/audit as the REST API;
write tools are additionally gated by `write_tools_enabled` (default off).

### Read tools (`mcp:read` or `mcp:write`)

| Tool | Summary |
|---|---|
| `get_status` | Node status: resolver health, listener bindings, TLS certificate status, filter-list update times, uptime. |
| `search_query_log` | Search the query log with filters (client, domain, verdict, time range). |
| `get_query` | One query-log entry by ID with the full decision record (why blocked, which rule, DNSSEC status, timings). |
| `explain_block` | Why a domain is currently blocked for a profile — the matching rule, its source list and priority. No live query. |
| `test_query` | Dry-run a DNS query through the policy engine as a specific client; returns what the answer would be, without polluting the log or cache. |
| `get_stats` | Aggregated statistics for a period. |
| `list_clients` | Known clients with names, IPs, VLANs and source (UniFi/manual). |
| `list_mcp_rules` | MCP-managed rules, active temporary allows, or active pauses for a filter set. |

### Write tools (`mcp:write` + `write_tools_enabled`)

| Tool | Summary |
|---|---|
| `allow_temporarily` | Temporarily allow a blocked domain (`PT5M`/`PT15M`/`PT1H`); expires automatically. |
| `add_rule` | Add a custom block rule built from structured input (no raw AdGuard syntax). |
| `remove_rule` | Remove an MCP-created rule (exact domain match). |
| `pause_filter_set` | Pause filtering for a set for a fixed duration. |
| `resume_filter_set` | Resume a paused set (no-op if not paused). |

All write tools are destructive and require client confirmation; every call is
audited. Input domains are validated (no wildcards, IPs, or single-label names)
and protected domains are never blockable/allowable.
