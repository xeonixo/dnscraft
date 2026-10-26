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
| GET | `/api/v1/status` | TLS mode (`self_signed`/`acme`), leaf fingerprint, and `warnings` (`control_api.tls.self_signed` while self-signed). TLS fields omitted in reverse-proxy mode. |

### Config (admin)

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/config` | Current `version` + stored snapshot (secrets redacted). |
| PUT | `/api/v1/config` | Validate + atomic replace of the whole config. `mcp_rules` are carried over when omitted, `[]` deletes them, an unknown field is `control_api.config.invalid`. Returns the new `version`. |
| GET | `/api/v1/config/versions` | Previous versions, newest first, paginated. |
| POST | `/api/v1/config/versions/{version}/rollback` | Restore a stored version. `control_api.config.unknown_version` if absent. |

### Policy (admin)

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/policy/views` | List views. |
| GET / PUT / POST / DELETE | `/api/v1/policy/views/{id}` | Read / create-or-replace / delete one view. |
| GET / PUT / POST / DELETE | `/api/v1/policy/profiles/{id}` | Profile CRUD. `policy.config.unknown_filter_set` on bad references. |
| GET / PUT / POST / DELETE | `/api/v1/policy/pause` | Global/per-profile pause state (singleton). |

### Clients (admin)

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/clients/manual` | Manual IP/CIDR/domain entries. |
| POST / PUT / DELETE | `/api/v1/clients/manual` | Add / create-or-replace / delete (body `{ "name": … }`) a manual entry. |
| GET | `/api/v1/clients` | Manual entries + the synced directory (empty until a `ClientEngine` adapter is wired). |
| POST | `/api/v1/clients/sync` | Trigger a UniFi sync. `clients.sync.*` on failure. |

### Filtering (admin)

| Method | Path | Summary |
|---|---|---|
| GET / POST / PUT / DELETE | `/api/v1/filter-sets` | Filter-set CRUD (`id`, `name`, `lists`, `custom_rules`, `services`, `block_mode`, `paused_until`, `mcp_rules`). |
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
| GET | `/api/v1/stats/overview` | Dashboard aggregate. |
| GET | `/api/v1/stats/top_clients` | Top clients by queries/blocked. |
| GET | `/api/v1/stats/top_domains` | Top domains. |
| GET | `/api/v1/stats/cache` | Cache hit ratio. |

Stats query parameters: `from`, `to`, `limit`, `by`.

### Auth

| Method | Path | Role | Summary |
|---|---|---|---|
| POST | `/api/v1/auth/tokens` | admin | Create a bearer token (`viewer`/`admin`/`mcp:read`/`mcp:write`); plaintext shown once, hash stored. |
| POST | `/api/v1/auth/local/login` | public | Break-glass login with a provisioned local account. `control_api.auth.locked` on lockout. |
| GET | `/api/v1/auth/oidc/authorize-url` | public | PKCE S256 + nonce authorization URL. |
| GET | `/api/v1/auth/oidc/callback` | public | Code exchange → cookie session. |

## REST endpoints — planned, not yet mounted

These are in the spec but not in `router.rs` yet; do not call them.

| Method | Path | Role |
|---|---|---|
| GET / POST | `/api/v1/auth/tokens` | admin (list; POST is implemented) |
| DELETE | `/api/v1/auth/tokens/{id}` | admin (revoke) |
| POST | `/api/v1/auth/logout` | viewer/admin |
| GET | `/api/v1/auth/me` | viewer/admin |
| GET | `/api/v1/audit` | viewer/admin |

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
