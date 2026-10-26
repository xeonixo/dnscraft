# ADR-0006: rmcp 3.7.0 for the stateless MCP server

- Status: Proposed
- Date: 2026-10-26
- Deciders: project owner (Checkpoint D0 — do not treat as approved until the owner logs it)
- Scope: `crates/dnscraft-mcp` transport layer (SPEC-mcp.md), new dependency `rmcp` 3.7.0

## Context

SPEC-mcp.md § Candidate dependencies proposes `rmcp` 3.7.0 (the official Rust MCP SDK) with
features `server`, `transport-streamable-http-server`, `macros` and default features off, to serve
MCP 2026-07-28 over stateless Streamable HTTP under `POST /mcp/v1`. The alternative is a
hand-rolled ~500-line JSON-RPC + Streamable HTTP layer on axum/hyper/serde_json.

The spec left six "Unverified details" to be answered before any Rust code is written. This ADR
records the dependency pack (Task M0) and the answers, read from the rmcp 3.7.0 source in the
cargo registry (`~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/rmcp-3.7.0`). No builds
were run in the repository; all commands ran in a throw-away crate under `/tmp/mcp-m0-scratch`.

## Decision

Use `rmcp` 3.7.0 (features `server`, `transport-streamable-http-server`, `macros`, default off)
as the transport/tool framework, and implement the DNScraft-specific behaviour (bearer
authentication, error envelope, per-token caps, deadline, config gating) in axum/tower layers and
in the `mcp` crate's `ServerHandler` wrapper around rmcp.

### Dependency pack (Task M0)

`cargo generate-lockfile` + `cargo fetch` in a throw-away crate resolved 91 external packages.
Compared with the workspace `Cargo.lock` (295 packages, HEAD `3ddcfbb`), **26 new crates** are
added; every shared crate reuses the same version already pinned in the workspace lock. All 26
licences are MIT / Apache-2.0 (or dual MIT OR Apache-2.0).

| Crate | Version | Licence |
|---|---|---|
| rmcp | 3.7.0 | Apache-2.0 |
| rmcp-macros | 3.7.0 | Apache-2.0 |
| pastey | 0.2.3 | MIT OR Apache-2.0 |
| schemars | 1.2.3 | MIT |
| schemars_derive | 1.2.3 | MIT |
| serde_derive_internals | 0.30.0 | MIT OR Apache-2.0 |
| uuid | 1.29.0 | Apache-2.0 OR MIT |
| sse-stream | 0.2.6 | MIT OR Apache-2.0 |
| tokio-stream | 0.1.19 | MIT |
| chrono | 0.4.45 | MIT OR Apache-2.0 |
| darling | 0.24.1 | MIT |
| darling_core | 0.24.1 | MIT |
| darling_macro | 0.24.1 | MIT |
| ident_case | 1.0.1 | MIT OR Apache-2.0 |
| strsim | 0.11.1 | MIT |
| ref-cast | 1.0.27 | MIT OR Apache-2.0 |
| ref-cast-impl | 1.0.27 | MIT OR Apache-2.0 |
| dyn-clone | 1.0.20 | MIT OR Apache-2.0 |
| iana-time-zone | 0.1.65 | MIT OR Apache-2.0 |
| iana-time-zone-haiku | 0.1.2 | MIT OR Apache-2.0 |
| android_system_properties | 0.1.6 | MIT OR Apache-2.0 |
| windows-core | 0.62.2 | MIT OR Apache-2.0 |
| windows-implement | 0.60.2 | MIT OR Apache-2.0 |
| windows-interface | 0.59.3 | MIT OR Apache-2.0 |
| windows-result | 0.4.1 | MIT OR Apache-2.0 |
| windows-strings | 0.5.1 | MIT OR Apache-2.0 |

Provenance: `chrono` (with its `now` feature) pulls `iana-time-zone`, which pulls the
platform-specific `windows-*` / `android_system_properties` / `iana-time-zone-haiku` crates and
`core-foundation` (already in the workspace lock). `schemars` pulls `dyn-clone` / `ref-cast`;
`rmcp-macros` pulls `darling*` / `ident_case` / `strsim`. `uuid` (feature `v4`) and `pastey` are
enabled by rmcp's `server` feature; `sse-stream`, `tokio-stream`, `tokio-util`, `rand`, `base64`,
`http`, `http-body`, `http-body-util`, `tower-service` are enabled by
`transport-streamable-http-server` (the latter group already in the workspace lock).

### Gates

- `cargo deny check` (copy of the repo `deny.toml`): **advisories ok, bans ok, licenses ok,
  sources ok**. Warnings only: 8 `license-not-encountered` (allow-list entries unused by this
  smaller tree) and 1 `duplicate` (`syn` 2.0.119 + 3.0.9, already duplicated in the workspace lock).
- `cargo tree -i` for `aws-lc-rs`, `aws-lc-sys`, `openssl-sys`, `native-tls`, `ring`, `reqwest`:
  all six "package ID specification did not match any packages" (empty). The ring-only rule
  (ADR-0002) is unaffected. (rmcp's `jsonwebtoken`/`oauth2`/`reqwest` dependencies exist only under
  the optional `auth*`/`reqwest*` features, which are not enabled.)
- rust-version: rmcp declares `rust-version = "1.88"` (matches the workspace MSRV).

## Answers to the six "Unverified details" (SPEC-mcp.md:1128-1134)

1. **`cargo deny` result + docs.rs URL.** Deny passes as above. docs.rs URL:
   `https://docs.rs/rmcp/3.7.0` (rmcp Cargo.toml `documentation = "https://docs.rs/rmcp"`).
2. **How a validated Bearer token reaches tool handlers.** The tower service consumes the body and
   injects the remaining `http::request::Parts` into the request's `rmcp::model::Extensions`
   (`src/transport/streamable_http_server/tower.rs:1538` and `:2275`), which are reachable through
   `RequestContext` (`src/service.rs:1194`, field `extensions` at `:1199`). A tool handler reads
   them either as an `Extension<http::request::Parts>` parameter or via
   `ctx.extensions.get::<http::request::Parts>()` (documented `tower.rs:1276-1330`); the extractor
   is `Extension<T>` in `src/handler/server/common.rs:180`, which does
   `context.as_request_context().extensions.get::<T>()` (`common.rs:187-199`). Therefore an axum
   layer validates the token once and inserts `TokenInfo` into `http::Extensions`
   (`req.extensions_mut().insert(...)`); the tool then reads it from `parts.extensions`, with **no
   re-validation inside the tool**. `Extensions::insert` requires `T: Clone + Send + Sync + 'static`
   (`src/model/extension.rs:68`), so `TokenInfo` must derive `Clone`.
3. **Annotations and static descriptions.** `ToolBase::description()` returns
   `Option<Cow<'static, str>>` and `ToolBase::annotations()` returns `Option<ToolAnnotations>`
   (`src/handler/server/router/tool/tool_traits.rs:44-84`); `tool_attribute::<T>()` assembles the
   `Tool` from these (`tool_traits.rs:98-112`). The `#[tool(...)]` macro accepts
   `name = "..."`, `title = "..."`, `description = "..."` (a static string literal) and
   `annotations(title = "...", read_only_hint = …, destructive_hint = …, idempotent_hint = …,
   open_world_hint = …)` (`rmcp-macros-3.7.0/src/tool.rs:65-74` and `:148-180`; annotation
   expression built at `tool.rs:219-245`; description also falls back to `///` doc comments).
   `ToolAnnotations` serialises exactly `readOnlyHint` / `destructiveHint` / `idempotentHint` /
   `openWorldHint` (`src/model/tool.rs:54-93`), matching SPEC-mcp.md.
4. **Stateless behaviour of `with_legacy_session_mode(false)`.** The flag only controls session
   routing (`tower.rs:90`, setter `:254`). With it `false`, `handle()` restricts the endpoint to
   POST only (`tower.rs:1818-1834`, GET/DELETE → 405) and `handle_post()` forces `use_session =
   false` (`tower.rs:2031-2032`), so every request takes the stateless path and no
   `Mcp-Session-Id` session or per-request state survives beyond the response. Accepted versions
   are `ProtocolVersion::KNOWN_VERSIONS` = 2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25,
   2026-07-28 (`src/model.rs:202-208`); an unknown `MCP-Protocol-Version` header is rejected 400
   (`tower.rs:293-320`). The 2026-07-28 revision has no `initialize` handshake
   (`ProtocolVersion::NO_INITIALIZE = V_2026_07_28`, `model.rs:181`); a request whose `_meta`
   carries all required 2026-07-28 keys is served per-request
   (`uses_legacy_lifecycle`, `src/service.rs:201-205`). **Caveat:** to make a legacy
   `initialize` client receive `UnsupportedProtocolVersionError` (and to advertise only
   2026-07-28 in `server/discover`), the mcp crate must override
   `ServerHandler::supported_protocol_versions()` — the default is `KNOWN_VERSIONS` (all five,
   `src/handler/server.rs:390-392`); the error is produced by `negotiate_protocol_version`
   (`src/service/server.rs:471-512`) when no handshake version remains.
5. **`with_json_response(true)` encoding.** When the handler's first message is a terminal
   `Response`/`Error` (the normal case for `tools/list`, `tools/call`), the server returns
   `200 OK` + `Content-Type: application/json` with the JSON-RPC message as the body
   (`tower.rs:2322-2337`). If the handler emits an intermediate notification/request first, it
   falls back to SSE (`Content-Type: text/event-stream`, `src/transport/common/server_side_http.rs:133-169`).
   So plain JSON-response tests need no SSE parser; only a test that forces a stream would.
6. **Config hooks for caps.** `StreamableHttpServerConfig` exposes **natively**:
   `max_request_body_bytes` (default 4 MiB, `tower.rs:55`; enforced while streaming, 413,
   `server_side_http.rs:207-255`), `allowed_origins` + `enforce_origin_validation` (Origin,
   RFC 6454, `tower.rs:111-131`, `:1199-1256`), and `allowed_hosts` (Host, default loopback-only,
   `tower.rs:110`). There is **no** per-token in-flight/concurrent-request cap and **no**
   per-request deadline — `max_concurrent_requests_per_token` and `request_timeout` must be tower
   layers in control-api. The per-token rate limiter is control-api's (already A5).

### Which SPEC-mcp.md transport checks rmcp already performs itself

| SPEC-mcp.md check | rmcp behaviour | file:line |
|---|---|---|
| GET/DELETE → 405 | `method_not_allowed_response()` with `Allow: POST`, plain-text body | `tower.rs:449-455`, `:1818-1834` |
| `MCP-Protocol-Version` unsupported → 400 | plain-text 400 `"Bad Request: Unsupported MCP-Protocol-Version: …"` | `tower.rs:293-320` |
| `Mcp-Method`/`Mcp-Name`/`Mcp-Param-*` vs body → 400 `-32020` HeaderMismatch | SEP-2243 validation, JSON-RPC error | `tower.rs:849-917`, `src/transport/common/mcp_headers.rs:326-386` |
| Unknown RPC method → 404 `-32601` | handler error mapped via `jsonrpc_http_status` | `tower.rs:648-656` |
| Notification POST → 202 empty body | `accepted_response()` = 202 | `server_side_http.rs:24-29`, `tower.rs:2340-2343` |
| Origin present and invalid → 403 | 403 (plain text) when `allowed_origins` non-empty or enforced | `tower.rs:1216-1256` |
| Body over cap → 413 | 413 while streaming, independent of `Content-Length` | `server_side_http.rs:207-255` |
| Cancellation on client disconnect | per-request `CancellationToken` cancels the in-flight handler | `tower.rs:2200-2211`, `:2330-2340` |

## Consequences

- The 26 new crates need one-time owner approval (Checkpoint D0); all permissive, deny-clean,
  ring-only.
- Several rmcp rejections are **plain-text bodies**, not the SPEC-mcp.md `{"error":{code,params}}`
  envelope. control-api must wrap/rewrite rmcp's 405/403/413/400 responses into the
  `control_api.*` envelope (the axum `map_response` that already rewrites 413 is a natural place).
- control-api must call `with_allowed_hosts([<node hostname>])` (rmcp defaults to loopback-only,
  which would 403 the API listener's own hostname), `with_allowed_origins([...])` or
  `enforce_origin_validation()`, and `with_max_request_body_bytes(1 MiB)` (default is 4 MiB).
- Per-token in-flight cap, per-request deadline and bearer-token validation are **not** rmcp's
  concern and are built as tower/axum layers; `TokenInfo` flows to tools via `Parts.extensions`.
- The mcp crate must override `supported_protocol_versions()` → `[V_2026_07_28]` and `get_info()`
  so `server/discover` and legacy-client rejection match the spec.

## Spec/plan contradictions to resolve at D0 (recorded, not silently changed)

1. **`server/discover` response shape.** SPEC-mcp.md:172-183 shows
   `{protocolVersion, serverInfo{name,version}, capabilities:{tools:{}}}`. rmcp 3.7.0's
   `DiscoverResult` (`src/model.rs:1474-1496`, `from_server_info` at `:1537-1560`) serialises
   `{resultType, supportedVersions[], capabilities, instructions, ttlMs, cacheScope, _meta{…
   serverInfo}}` — server info lives under `_meta["io.modelcontextprotocol/serverInfo"]` and the
   version list is `supportedVersions`, not a single `protocolVersion`. M8 must build its
   `server/discover` test against rmcp's actual shape (or the spec example is updated).
2. **Unsupported-version error.** SPEC-mcp.md:120,1228 say `UnsupportedProtocolVersionError`
   "listing the supported versions" (`data.supportedVersions`). rmcp emits code **`-32022`**
   (`src/model.rs:634`) with `data = {"requested": …, "supported": […]}` (`model.rs:690-705`) —
   key `supported`, not `supportedVersions` — and only on the JSON-RPC path; the
   `MCP-Protocol-Version`-header-level rejection is a plain-text 400 (`tower.rs:293-320`).
3. **Malformed JSON body → 415, not a JSON-RPC parse error.** `expect_json` returns HTTP 415 for
   an unparseable body (`server_side_http.rs:256-266`), whereas SPEC-mcp.md:206 puts "parse error"
   in the JSON-RPC bucket (`-32700`).

None of these blocks the transport (M8/M9 will implement what the spec requires around rmcp, e.g.
by re-wrapping the plain-text rejections into the control-api envelope); they are reported so the
owner can correct SPEC-mcp.md or the acceptance tests at D0.

## Alternatives considered

- **Hand-rolled Streamable HTTP (~500 lines).** Rejected: it would re-implement the SEP-2243
  header validation, SSE fallback, protocol-version negotiation, disconnect cancellation and
  2026-07-28 stateless routing that rmcp already provides and tests; the DNScraft-specific gaps
  (envelope, auth, caps, deadline) must be built as layers either way. The dry-check found no
  crypto/deny blocker.
- **Different SDK / older rmcp.** Not evaluated in detail; the official SDK at the version the
  spec names is preferred.

## Links

- [SPEC-mcp.md](../../SPEC-mcp.md) — § Candidate dependencies, § Protocol version and transport
- [tasks/plan-mcp.md](../../tasks/plan-mcp.md) — "Dependencies for owner approval"
- [tasks/todo-mcp.md](../../tasks/todo-mcp.md) — Task M0
- [ADR-0002](0002-ring-only-crypto.md) — ring-only rule; [`deny.toml`](../../deny.toml)
- rmcp 3.7.0 source: `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/rmcp-3.7.0`
