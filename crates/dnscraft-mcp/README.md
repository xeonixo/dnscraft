# dnscraft-mcp

Stateless Model Context Protocol (MCP) server for DNScraft, implementing protocol
revision 2026-07-28 over Streamable HTTP under `POST /mcp/v1`.

The crate owns the protocol and tool layer only. The control API owns the HTTP
listener, the bearer tokens, the rate limits and the audit log, and mounts the
service returned by [`service`](src/lib.rs) at `/mcp/v1`.

See [SPEC-mcp.md](../../SPEC-mcp.md) for the authoritative protocol, tool and
security rules.

## Architecture

```text
control-api
   │  implements McpBackend (all I/O: log, policy, filtering, audit)
   ▼
dnscraft-mcp
   ├── tools/       13 tool definitions + handlers (read and write)
   ├── transport     pure request pre-checks + rmcp Streamable HTTP wrapper
   ├── auth         bearer-token extraction and scope checks
   ├── protected    protected-domain matching
   ├── sanitize     control-character neutralisation and length caps
   ├── config       config keys, defaults and startup validation
   ├── dto          every DTO that crosses the backend boundary
   └── error        stable `mcp.*` codes
```

The crate **depends on no other DNScraft crate**. `McpBackend` is the single
inbound port: `control-api` implements it and every type passed across that
boundary is defined in this crate's `dto` module. Tool handlers therefore never
link to the resolver, filtering, policy or query-log crates directly.

`rmcp` 3.7.0 provides the Streamable HTTP transport, SEP-2243 header validation,
protocol-version negotiation and disconnect cancellation. This crate adds the
DNScraft-specific behaviour around it: bearer authentication, scope checks,
the stable error envelope, per-token request caps, request deadline and the
write-tools gate. The dependency decision is recorded in
[ADR-0006](../../docs/adr/0006-mcp-rmcp-stateless.md).

## Tools

All 13 tools are listed when `write_tools_enabled = true`; with the gate off,
`tools/list` returns only the eight read tools and every write tool call fails
with `mcp.write_tools_disabled`. Rows are in the order returned by `tools/list`
(alphabetical).

| Tool | Scope | Description |
|---|---|---|
| `add_rule` | `mcp:write` | Add a structured custom block rule to a filter set (no raw syntax, no wildcards). |
| `allow_temporarily` | `mcp:write` | Temporarily allow a blocked domain for a fixed short duration; the allow expires automatically. |
| `explain_block` | `mcp:read` | Explain why a domain is currently blocked for a profile, without a live DNS query. |
| `get_query` | `mcp:read` | Retrieve one query-log entry with its full decision record. |
| `get_stats` | `mcp:read` | Retrieve DNS statistics for a time range. |
| `get_status` | `mcp:read` | Get node status: resolver health, listeners, TLS, list updates and uptime. |
| `list_clients` | `mcp:read` | List known clients with names, addresses, VLANs and source. |
| `list_mcp_rules` | `mcp:read` | List MCP-created rules, active temporary allows or active pauses for a filter set. |
| `pause_filter_set` | `mcp:write` | Pause filtering for a filter set for a fixed short duration. |
| `remove_rule` | `mcp:write` | Remove a custom block rule that was previously created via MCP. |
| `resume_filter_set` | `mcp:write` | Resume filtering for a paused filter set. |
| `search_query_log` | `mcp:read` | Search the query log by time, client, domain, protocol, view or outcome. |
| `test_query` | `mcp:read` | Dry-run a query through the policy engine without writing to the log or cache. |

Read tools carry `readOnlyHint: true`; write tools carry `destructiveHint: true`.
Tool descriptions are static and are never built from runtime data.

## Limits and defaults

| Setting | Default | Range | Enforced by |
|---|---|---|---|
| `max_concurrent_requests_per_token` | 5 | 1–50 | Per-token in-flight counter |
| `request_timeout` | 60 s | 10–300 s | Per-request deadline |
| `max_request_body_size` | 1 MiB | ≥ 1 byte | Transport (streamed, independent of `Content-Length`) |
| `max_temporary_allow_duration` | 1 h | 5 min–1 h | Lowers the fixed `PT5M`/`PT15M`/`PT1H` set |
| `max_pause_duration` | 1 h | 5 min–1 h | Lowers the fixed `PT5M`/`PT15M`/`PT1H` set |
| `max_custom_rules_per_set` | 100 | 10–1000 | `add_rule` (non-expired rules per filter set) |
| `max_block_rule_lifetime` | 30 d | 1–365 d | Server-set `expires_at` on every MCP-created rule |
| `legacy_session_mode` | `false` | `true`/`false` | Protocol negotiation (stateless only by default) |
| `write_tools_enabled` | `false` | `true`/`false` | Independent gate for the five write tools |

`enabled` defaults to `false` as well: the endpoint is opt-in. Result lists default
to 50 items (100 for `list_clients` and `list_mcp_rules`) and cap at 500 per
request. Per-token rate limits are the control-api limits for the token.

The duration maxima can only **lower** the fixed three-value duration set; they
cannot add `PT4H` or any other value. Out-of-range configuration is rejected at
startup with `mcp.config.invalid` (or `mcp.config.protected_domain` for a
malformed protected-domain entry).

## Error codes

Tool-level failures use one shape: `isError: true` plus
`structuredContent.error = {"code": "...", "params": {...}}`. They never become
an HTTP status or a JSON-RPC error.

| Code | When |
|---|---|
| `mcp.tool_not_found` | The `tools/call` name is not a registered tool |
| `mcp.invalid_input` | Input fails the schema, an enum value is not allowed, or a duration is outside the fixed set |
| `mcp.domain_too_broad` | The target is a single-label (TLD-wide) name such as `com` |
| `mcp.write_tools_disabled` | A write tool was called while `write_tools_enabled = false` |
| `mcp.duration_exceeds_maximum` | A duration in the fixed set is above the configured maximum |
| `mcp.rule_limit_exceeded` | The MCP-created rule cap was reached for the filter set |
| `mcp.protected_domain` | The target, an ancestor or a descendant is protected |
| `mcp.config.invalid` | A configuration value is out of range (startup only) |
| `mcp.config.protected_domain` | A `protected_domains` entry is malformed (startup only) |

Protocol-defined JSON-RPC errors, returned as JSON-RPC errors rather than tool
results: `-32601` (method not found, HTTP 404), `-32020` (header mismatch, HTTP
400) and `-32022` (unsupported protocol version, HTTP 400).

HTTP-level rejections use the control-api envelope with a stable code:
`control_api.auth.unauthenticated` (401), `control_api.auth.invalid_origin`
(403), `control_api.auth.invalid_scope` (403), `control_api.not_found` (404),
`control_api.method_not_allowed` (405), `control_api.payload_too_large` (413)
and `control_api.rate_limited` (429).

## Security model

- **Least privilege.** Tokens use dedicated MCP scopes: `mcp:read` for the eight
  read tools and `mcp:write` for the five write tools. Browser/API tokens
  (`viewer`, `admin`) are rejected on `/mcp/v1`, and MCP tokens are rejected on
  `/api/v1`. The write tools have a second, independent configuration gate
  (`write_tools_enabled`, default `false`).
- **Sanitizing.** Every string from DNS, clients, filter lists or the assistant
  is untrusted data. Output passes through `SafeText`, which replaces control
  characters with `U+FFFD` and truncates on a character boundary with known
  caps. Assistant-supplied reasons are sanitized before storage and audit.
- **Protected domains.** Control-plane and infrastructure names (the node's
  public domain, DynDNS names, OIDC issuer, ACME directory, list URLs, DNS
  forward zones and `api.cloudflare.com`) cannot be blocked, unblocked or
  allowed via MCP. Matching is bidirectional (target, ancestors and
  descendants), case-insensitive and IDNA-aware.
- **Block-only rules.** MCP can create block rules only. There is no `action`
  field and no permanent allow: allows exist only through `allow_temporarily`
  with a mandatory expiry.
- **Mandatory expiry.** Every MCP-created block rule gets a server-set
  `expires_at` from `max_block_rule_lifetime`. Temporary allows and pauses are
  volatile and capped at one hour; expired rules are dropped at snapshot build.
- **Audit.** Every write tool records an audit entry (`action: "mcp.<tool>"`
  with actor, object, redacted before/after, result and error code). Read tools
  increment telemetry counters instead of per-call audit entries.
- **Transport hardening.** Bearer authentication, body caps, Origin checks,
  SEP-2243 header/body matching, per-token in-flight caps and a per-request
  deadline apply before or around tool dispatch.

## Manual interop recipe

The endpoint is stateless: there is no `initialize` handshake, no session
header and no cookies. Every request declares the protocol version in both the
`MCP-Protocol-Version` header and the request `_meta`, and carries
`Mcp-Method` (plus `Mcp-Name` for `tools/call`). Examples use documentation
names only.

**Status: not run.** These steps need a running control-api with MCP enabled
and a token with `mcp:read`; they were not executed while writing this
document.

1. Start the server with `[control_api.mcp] enabled = true` and a test token.

2. List tools (not run):

   ```bash
   curl -sS https://dnscraft.example.net:8443/mcp/v1 \
     -H 'Authorization: Bearer <mcp-read-token>' \
     -H 'Content-Type: application/json' \
     -H 'Accept: application/json, text/event-stream' \
     -H 'MCP-Protocol-Version: 2026-07-28' \
     -H 'Mcp-Method: tools/list' \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}'
   ```

   Expect `200 OK` with `application/json` and a `result.tools` array of eight
   read tools (13 with the write gate on).

3. Call `get_status` (not run):

   ```bash
   curl -sS https://dnscraft.example.net:8443/mcp/v1 \
     -H 'Authorization: Bearer <mcp-read-token>' \
     -H 'Content-Type: application/json' \
     -H 'Accept: application/json, text/event-stream' \
     -H 'MCP-Protocol-Version: 2026-07-28' \
     -H 'Mcp-Method: tools/call' \
     -H 'Mcp-Name: get_status' \
     -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_status","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}'
   ```

   Expect a result whose `content[0].text` is a JSON document and whose
   `structuredContent` matches the node-status shape.

4. Call `add_rule` with a `mcp:write` token (not run):

   ```bash
   curl -sS https://dnscraft.example.net:8443/mcp/v1 \
     -H 'Authorization: Bearer <mcp-write-token>' \
     -H 'Content-Type: application/json' \
     -H 'Accept: application/json, text/event-stream' \
     -H 'MCP-Protocol-Version: 2026-07-28' \
     -H 'Mcp-Method: tools/call' \
     -H 'Mcp-Name: add_rule' \
     -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"add_rule","arguments":{"domain":"ads.example.com"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}'
   ```

   Expect a block rule with a server-set `expires_at`. Repeating with a
   `mcp:read` token returns `isError: true` and
   `control_api.auth.insufficient_scope`.

5. Negative check (not run): send `MCP-Protocol-Version: 2099-01-01` and expect
   `400` with JSON-RPC error `-32022`; send `GET /mcp/v1` and expect `405`.
