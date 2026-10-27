# Plan: Production assembler (G0)

> Owner decision required before any code. Authority: [todo-spec-gaps.md](todo-spec-gaps.md) G0.
> The binary `crates/dnscraft` is still the N14 minimal bootstrap: it serves listeners with a
> hardcoded empty policy/filtering and a stdout query log. Every "complete" module
> (control-api, mcp, clients, real filtering/policy/tls, query-log) is unreachable from `main.rs`.
> This plan turns the binary into the real assembler.

## Current state (verified 2026-10-27)

- `crates/dnscraft/src/config.rs`: `Config { public_domain, [[listeners]], allow_partial_bind, [log] }`,
  `deny_unknown_fields`. No `data_dir`, no `[resolver]`/`[filtering]`/`[clients]`/`[tls]`/`[policy]`/
  `[control_api]` sections.
- `crates/dnscraft/src/engine.rs`: `build_engine` hardcodes `empty_filter()`, `ResolverConfig::default()`
  (5 s), one default profile/view with empty subnets/records/client_ids, `Arc::new(NoClients)`.
- `crates/dnscraft/src/lib.rs::build`: env-PEM `CertResolver`, stdout JSON-lines `QueryEventSink`,
  `ListenerSet::start`. No control-api/mcp/clients/tls-engine.
- `crates/dnscraft-api`: `AppState` has all `with_*` builders; `serve(config, state, tls)`;
  `ConfigService` needs `ConfigStore` + `ModuleAppliers`; `ModuleAppliers` has 5 `Apply*` traits with
  **no production impl** (`modules.rs`); `McpBackendInner` is `pub(crate)`, `with_mcp_backend` is
  `#[allow(dead_code)]`; `ControlApiConfig` is `Serialize`-only; `allowed_origins` is an empty
  `ponytail:` block (`server.rs:358-364`).
- `crates/dnscraft-mcp`: `McpConfig` has no serde.
- `crates/dnscraft-clients`: `ClientEngine`/`ClientLookup` has no `ClientDirectory` adapter (policy
  takes `Arc<dyn ClientDirectory>`; the trait lives in `dnscraft-policy`).

## Target architecture

```
dnscraft.toml ──► binary Config (bootstrap) ──► build engines ──► seed SQLite ──► control-api serve
                                                        │
        resolver · filtering · clients · tls · policy ──┴──► Apply* traits (live apply on PUT /config)
```

- One process: resolver + filtering + policy + clients + tls engines, a `ListenerSet`, the
  control-api (`/api/v1`, `/mcp/v1`) on the internal bind, and a SQLite-backed query-log/audit/config
  store under `data_dir`.
- The binary is the only crate that depends on every module, so it owns the assembly and the
  `Apply*` impls.
- Config lives in SQLite (`config_versions`). The TOML file is the bootstrap: on first run it seeds
  SQLite; afterwards the control-api is the source of truth and applies changes live.

## Decisions (open — owner to confirm)

- **D1 — config (de)serialization.** The `Apply*` traits take `serde_json::Value`, and the config
  snapshot in SQLite is JSON. To get JSON↔module-config without hand-written parsers, the module
  config structs need `serde` (`ResolverConfig`, `FilterConfig`, `ClientsConfig`, `TlsConfig`,
  `PolicyConfig`, and the listeners config). Recommendation: add `serde` derives to those structs
  (workspace already depends on `serde`) and let the `Apply*` impls deserialize the JSON directly.
  This deviates from the "module crates take Rust values only" note in SPEC-tls Assumptions 1;
  alternative is a JSON-mirror layer in the binary (more code, drift risk).
- **D2 — where `Apply*` impls live.** Recommendation: `crates/dnscraft` (the binary). It is the only
  place with both `dnscraft-api` (traits) and the module crates; adding `dnscraft-api`, `dnscraft-mcp`,
  `dnscraft-clients` as binary dependencies is the whole point of the assembler.
- **D3 — MCP backend construction.** `McpBackendInner`/`with_mcp_backend` must become constructible
  from the binary (public constructor or a public `McpBackend` builder). Confirm the shape.
- **D4 — bootstrap vs SQLite ownership.** TOML seeds SQLite on first run; `PUT /config` afterwards is
  authoritative. A re-`--config` on a non-empty store must not silently overwrite (log a warning and
  ignore, or error — owner to pick).
- **D5 — `data_dir` layout.** `data_dir/dnscraft.db` (config/audit/query-log/rollups/tokens/sessions),
  `data_dir/tls/` (cert store + state.json + account.json), `data_dir/` (filter-list bodies). Confirm
  or propose a layout.
- **D6 — query-log default `ip_truncate`.** Binary default is `none`; control-api default is
  `last_octet`. Pick one (recommend `last_octet`) and keep the other explicit.

## Phases

- **Phase 0 — Config model.** `ControlApiConfig` + `McpConfig` gain `Deserialize`; module configs gain
  `serde` (per D1); extend the binary `Config` with `data_dir`, `[resolver]`, `[filtering]`,
  `[clients]`, `[tls]`, `[policy]`, `[listeners_public]`, `[listeners_limits]`, `[listeners_ddr]`,
  `[control_api]` (incl. `[control_api.mcp]`, `[control_api.auth]`, `[control_api.rate_limit]`,
  `[control_api.query_log]`). Keep the existing `[[listeners]]` and env-secret TLS bootstrap.
- **Phase 1 — Module assembly.** Build the real resolver, filtering (`ListStore` + lists/sets),
  clients (`ClientEngine` + `ClientDirectory` adapter), policy (views/profiles/records), and tls
  (`TlsEngine` ACME/DynDNS) engines from config, replacing the hardcoded `build_engine`.
- **Phase 2 — Apply + store.** Real `ApplyFiltering`/`ApplyClients`/`ApplyPolicy`/`ApplyListeners`/
  `ApplyTls` impls (D2); `Db`/`ConfigStore`/`ConfigService`; bootstrap seeding (D4).
- **Phase 3 — control-api + MCP.** Assemble `AppState` (auth, query-log, stats, TLS admin/status),
  construct the MCP backend (D3) and mount `/mcp/v1`, populate `allowed_origins`.
- **Phase 4 — Query-log pipeline + delivery.** Replace the stdout sink with `QueryLogSink` (SQLite);
  Dockerfile/compose/HEALTHCHECK/multi-arch/musl (delivery) as a separate, gated phase.

Checkpoints after every 2–3 tasks; the last one per phase is a review + owner approval.

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| `Apply*` impls hand-built JSON parsing | drift/bugs | D1: serde on module configs, one source of truth |
| TOML bootstrap overwrites a live SQLite store | config loss | D4: seed-once + warn/error |
| The binary becomes a god-crate | review burden | keep assembly in `crates/dnscraft` but per-module `assemble_*` fns; impls are thin adapters |
| MCP backend constructor exposes internal handles | API leak | D3: public, narrow builder, still no secret material |
| Delivery phase (Docker/musl) balloons scope | never ships | separate gated phase, do last |

## Open questions (owner)

1. **D1** — serde on module configs (recommended) vs binary JSON-mirror layer?
2. **D2** — `Apply*` impls in `crates/dnscraft` (recommended) vs a new `dnscraft-assemble` crate?
3. **D3** — MCP backend constructor shape (public `McpBackendInner` builder vs `McpBackend` trait factory)?
4. **D4** — bootstrap re-run on a non-empty store: warn-and-ignore vs error?
5. **D5** — `data_dir` layout as proposed?
6. **D6** — query-log default `ip_truncate`: `last_octet` (recommended) or `none`?
7. **Delivery** — is Docker/musl/multi-arch in scope for this plan, or a separate plan?

**STOP for owner approval before Phase 0 code.**
