# Todo: Spec-vs-Code Gaps (independent horde review, 2026-10-27)

> Source: 9 parallel read-only agents, each comparing one `SPEC-*.md` against its crate.
> Scope: everything **except** `cluster` and `web-ui`. Line numbers are from the review snapshot;
> concurrent cluster work has since landed (e.g. CL4/CL5) and may shift a few lines in `dnscraft-api`.
>
> Triage legend:
> - **[code]** — the spec is authoritative, fix the code to match.
> - **[spec]** — the code is a deliberate decision, update the spec to match instead.
> - **[owner]** — needs an owner decision before any change.
> - Severity: 🔴 Critical · 🟠 Important · 🟡 Suggestion.

---

## G0 — Production assembler (cross-cutting, blocks everything) 🔴 [owner]

The root finding behind roughly half the Criticals: `crates/dnscraft` is still the **N14 minimal
bootstrap**. `main.rs` builds only listeners + a hardcoded empty policy/filtering + stdout logging.
The "complete" modules are unreachable from the production process.

- `crates/dnscraft/Cargo.toml` has no `dnscraft-api`, `dnscraft-mcp`, or `dnscraft-clients` dependency.
- Bootstrap `Config` accepts only `public_domain`, `[[listeners]]`, `allow_partial_bind`, `[log]`
  (with `deny_unknown_fields`); a spec-shaped config fails `dnscraft.config.unknown_field`.
  (`crates/dnscraft/src/config.rs:154-170`)
- `ControlApiConfig` is `Serialize`-only (`dnscraft-api/src/config.rs:193-212`), `mcp` is
  `#[serde(skip)]` — neither can be deserialized from TOML without new code.
- `ApplyFiltering`/`ApplyClients`/`ApplyPolicy`/`ApplyListeners`/`ApplyTls` traits have **no
  production implementation** (`dnscraft-api/src/modules.rs:49-60`; only a test fake exists).
- `with_mcp_backend` is `#[allow(dead_code)]`, `McpBackendInner` is `pub(crate)` — the MCP service
  cannot be mounted outside tests (`dnscraft-api/src/server.rs:150`, `api/router.rs:180-185`).
- `ClientLookup` → `ClientDirectory` adapter does not exist anywhere; policy gets `NoClients`
  (`crates/dnscraft/src/engine.rs:90`).
- Query log/statistics pipeline not assembled: only a stdout JSON-lines writer
  (`crates/dnscraft/src/events.rs:18-45`); `dnscraft_api::QueryLogSink` unused by the binary.

**Needed before code:** a production-config design (which top-level TOML sections, who owns them,
how `ControlApiConfig` becomes `Deserialize`, how module appliers get wired into live engines, how
the MCP backend is constructed and mounted, how the client adapter feeds policy + query-log). This
is a plan/spec task, not a per-crate fix. Deferred until the owner signs off on scope.

→ **Plan + tasks written 2026-10-27:** [plan-assembler.md](plan-assembler.md) ·
[todo-assembler.md](todo-assembler.md) (phases AS0–AS13, owner decisions D1–D6). Awaiting owner
approval before Phase 0 code.

---

## Resolver (`SPEC-resolver.md` ↔ `crates/dnscraft-resolver`)

- [x] **GR1** 🔴 [owner] (closed: serde on `ResolverConfig` plus the assembler `[resolver]` mapping, AS1–AS3; forward-zone spec excerpt fixed) `[resolver]` config is not deserializable: `ResolverConfig` has no serde,
      and no TOML loader maps the spec keys (`cache_size_mb`, `ttl_min/max`, `serve_stale`,
      `prefetch`, `negative_trust_anchors`, `forward_zones`). *(config.rs:64-65, 181-195)*
      Note: the spec's forward-zone excerpt omits the `id` the code requires.
- [x] **GR2** 🟠 [code] `outgoing_ipv6` key has no counterpart; transport always follows the target
      address family. Add field + honour it. *(config.rs:66-155, transport.rs:83-87)*
- [x] **GR3** 🟠 [code] RFC 5011 rollover tracking not implemented (static ROOT_DS only). *(dnssec/anchors.rs:63-96)*
- [x] **GR4** 🟠 [code] Forward zones with `validate=true` never check NXDOMAIN/NODATA denial
      proofs and miss the "rcode is not signed" rule → a validating forwarder accepts forged
      negative answers. *(forward.rs:217-290)*
- [x] **GR5** 🟠 [code] 16-address referral cap enforced only for glue candidates; glueless host
      lookups can inject up to ~64 addresses. *(iterate.rs:71-72, 197-200, 928-931)*
- [x] **GR6** 🟡 [code] Root re-prime is query-driven, not time-driven — an idle resolver never
      refreshes the 24 h root set. *(lib.rs:530, 566-593)*
- [x] **GR7** 🟡 [code] `forward::scrub` keeps every NSEC/NSEC3 in the authority section
      regardless of owner. *(forward.rs:97-101)*

## Filtering (`SPEC-filtering.md` ↔ `crates/dnscraft-filtering`)

- [x] **GF1** 🟠 [code] `max_list_size_mb` key has no counterpart; the 64 MiB cap lives only in
      `StoreConfig.max_body_bytes`, unreachable via `FilterConfig`. Plumb it through. *(set.rs:92-99, store.rs:62)*
- [~] **GF2** 🟠 [code] `filter_list.fetch_failed` / `filter_list.too_large` error codes don't
      exist (only `filter_fetch.*` / `filter_store.*`); params differ from SPEC.md. Add codes +
      map in control-api. *(fetch.rs:116-128, store.rs:103-110)*
- [x] **GF3** 🟠 [code] `$client`/`$ctag` modifiers reject the whole rule instead of ignoring the
      modifier (rule still applies) with a warning. *(modifiers.rs:290-294)*
- [x] **GF4** 🟠 [code] `list_status()` omits last HTTP status and skip breakdown by reason.
      *(engine.rs:42-59, 925-961; store.rs:223; snapshot.rs:58-76)*
- [x] **GF5** 🟡 [code] No `tracing::warn` is emitted for any skipped rule (client modifier,
      invalid IDNA, record rewrite). *(parser.rs:440-456)*
- [x] **GF6** 🟡 [spec] `$badfilter` from a list/service cannot disable an identical custom rule;
      the spec says "everywhere in the set" without that exception. *(index.rs:66-70, 508-548)*
- [x] **GF7** 🟡 [spec] Record-form `$dnsrewrite` from a list drops the whole rule (loses the
      block); spec's hosts analogy suggests only the rewrite should be ignored. *(modifiers.rs:450-452)*
- [x] **GF8** 🟡 [code] No `tests/data/` golden fixtures; parser proptest only for the builder
      round-trip. *(tests/ has no data dir)*
- [x] **GF9** 🟡 [spec] Interface sketch drift: `new` returns `Arc<Self>`, `match_*` take `now`
      + return `Result`, `TempAllow` requires `created_at`. *(engine.rs:138-142 etc.)*
- [x] **GF10** 🟡 [spec] No backoff state for list/catalog update retries (fixed interval only). *(scheduler.rs:94-111)*
- [x] **GF11** 🟡 [spec] Match budget p99 ~18.9 µs > 10 µs for deep names; owner waived at
      Checkpoint B but spec not updated. *(README.md:209)*

## Clients (`SPEC-clients.md` ↔ `crates/dnscraft-clients`)

- [x] **GC1** 🔴 [owner] No `ClientLookup` → `ClientDirectory` adapter; policy/MCP/query-log never
      get clients. *(policy/src/directory.rs:12-27; api clients_routes.rs:3-5,130-137)* — belongs to G0.
      *Done 2026-10-28:* `EngineClients` (policy directory + query-log enricher) and `EngineDirectory`
      (control-api/MCP `ClientDirectory`) in `crates/dnscraft/src/engine.rs`; verified by `boots_every_engine_and_serves_the_control_api`.
- [x] **GC2** 🟠 [code] `UnifiConfig::default()` is `TlsMode::Insecure`; skip-verify must be
      opt-in, not the default. *(config.rs:101-113, 229-240)*
- [x] **GC3** 🟠 [code] With UniFi disabled, startup still merges cached observations/networks.
      *(engine.rs:165-199)*
- [x] **GC4** 🟠 [code] `apply_config { enabled:true }` does not load the API key from
      `DNSCRAFT_UNIFI_API_KEY`/`_FILE` (read only at construction). *(engine.rs:151-162, 323-333)*
- [x] **GC5** 🟠 [code] Change-detection hash omits `display_name`, `macs`, `last_seen`, VLAN,
      network name/prefixes → stale log/UI + stale cache survive restart. *(engine.rs:860-903, 664-683)*
- [x] **GC6** 🟠 [code] Manual client ids are `manual-{index}`, not a stable manual uuid → reorder
      shifts ids/labels/FQDNs. *(merge.rs:187-206, state.rs:14-16)*
- [x] **GC7** 🟠 [code] `[clients]`/`[clients.unifi]` keys (`enabled`, `base_url`, `site_id`,
      TLS mode, `local_domain_mode`, `offline_retain`, `ipv6_address_ttl`, `classic_clients`,
      `tls_pin_sha256`) are not mapped anywhere in the product. *(api config_routes.rs:60)*
- [x] **GC8** 🟡 [code] `local_domains()` always inserts the config fallback domain even when
      unused. *(merge.rs:183, 374-384)*
- [x] **GC9** 🟡 [code] Missing `vlanId` yields `VlanInfo { id: 0, … }` instead of unknown. *(merge.rs:447-455)*
- [x] **GC10** 🟡 [code] Memory cap counts rows, not indexed addresses. *(merge.rs:160-165)*
- [x] **GC11** 🟡 [code] `clients.ip.conflict` counter computed but not surfaced. *(merge.rs:60-66, engine.rs:36-53)*
- [x] **GC12** 🟡 [code] No sync success/failure counters exposed. *(status.rs:6-29)*
- [x] **GC13** 🟡 [code] Link-local `fe80::/10` exclusion applies only to UniFi observations, not
      manual entries. *(merge.rs:516-518 vs 208-222)*
- [x] **GC14** 🟡 [code] URL validation accepts malformed hosts/ports and paths. *(config.rs:305-331)*
- [x] **GC15** 🟡 [code] Manual CIDR lookup is O(n), not O(1). *(lookup.rs:109-121)*

## TLS (`SPEC-tls.md` ↔ `crates/dnscraft-tls`)

- [x] **GT1** 🟠 [code] Manual DNS-01 (`manual`) can never complete: single `manual_txt` vs two
      distinct challenge values, and no "published" signal. *(issue.rs:231-252, 185-194; config.rs:198-217)*
- [x] **GT2** 🟠 [code] `AcmeOrderStatus.next_attempt_at` never populated; early errors skip
      progress update so `order_status()` can report stale state. *(acme.rs:60-71, 422-506)*
- [x] **GT3** 🟠 [code] `apply_config` unconditionally re-uploads `config.manual` when present,
      reverting API uploads and clearing the `revoked` flag. *(engine.rs:306-309, 388-390)*
- [x] **GT4** 🟡 [code] `acme_account_status().deactivated` hardcoded `false`. *(acme.rs:755-777)*
- [x] **GT5** 🟡 [code] Account-key rollover not exposed through `TlsEngine`. *(acme.rs:173-177; engine.rs)*
- [x] **GT6** 🟡 [code] `tls.dns.provider.zone` defined but never emitted (`CloudflareZone` used). *(error.rs:216, cloudflare.rs:161-179)*
- [x] **GT7** 🟡 [code] `rate_limit_status()` goes stale when a later non-429 attempt fails. *(engine.rs:652-663)*
- [x] **GT8** 🟡 [code] Preflight omits ACME/DNS checks entirely when `acme.enabled=false`. *(engine.rs:492-537)*
- [x] **GT9** 🟡 [code] ACME-sourced revocation skips the CA when `acme.enabled==false`. *(engine.rs:411-421)*
- [x] **GT10** 🟡 [code] DynDNS echo transport failure treated as "no route"/success. *(dyndns.rs:90-96, 300-350)*
- [x] **GT11** 🟡 [code] Audit entries for successful writes dropped if a later write in the same
      pass fails. *(dyndns.rs:355-362, engine.rs:702-708)*
- [x] **GT12** 🟡 [code] No metrics (days-to-expiry gauge, renew counters) anywhere. *(not found)*

## Policy (`SPEC-policy.md` ↔ `crates/dnscraft-policy`)

- [x] **GP1** 🔴 [code] Client IDs are **not** selection keys per current spec, but the code still
      does `SelectionCause::ClientId` lookup (and listeners piggyback `is_client_id_registered` on it).
      *(select.rs:50-55, config.rs:173-174, snapshot.rs:105-106, engine.rs:100-109)* — spec was revised,
      crate never updated; also needs a separate listener-side ID source.
- [x] **GP2** 🔴 [code] Local records should be a global name space with per-view `overrides`;
      code has them per-view. *(config.rs:175-176, 217-230; snapshot.rs:241, 395-442; steps/local_records.rs:22-23)*
- [x] **GP3** 🟠 [code] `nodes` / node validity not implemented (no `node_id` in
      `RequestContext`/`PolicySnapshot::build`). *(grep node → 0 hits)*
      Owner decision made 2026-10-27 → implement the revised spec. Plan: `plan-policy-model.md` · `todo-policy-model.md`.
- [ ] **GP7** 🟡 [code] TOML bootstrap `[[policy.records]]` takes wire-form `rdata` (`{type, data:[bytes]}`) and map-of-wire `overrides`; SPEC-policy excerpt shows presentation text (`rdata = "192.0.2.10"`, `overrides = { "guests" = "192.0.2.50" }`). The API accepts presentation text. *(config.rs rdata_serde / override_map)* — owner: pick one form for TOML.
- [x] **GP4** 🟠 [code] `DecisionTimings.filter_us` declared but never assigned (=0). *(decision.rs:150, engine.rs:204-459)*
- [x] **GP5** 🟡 [code] RFC 6724 / ULA note exists only in specs, no operator/first-run docs. *(grep 6724 → specs only)*
- [x] **GP6** 🟡 [code] `home.arpa` via resolver local zone has no policy-crate test. *(grep home.arpa → 0 in crate)*

## Listeners (`SPEC-listeners.md` ↔ `crates/dnscraft-listeners`)

- [x] **GL1** 🔴 [code] DoH `h3=true` bind failure hangs startup/reload: the TCP+UDP wrapper
      `join!` waits forever on the surviving QUIC listener; reverse case ignores the h3 failure.
      *(set.rs:380-421, 462-484)*
- [x] **GL2** 🔴 [owner] `listeners_public.enabled` not expressible — assembler derives it from any
      `exposure="public"` entry. *(crates/dnscraft/src/config.rs:328-348)* — belongs to G0.
      *Done 2026-10-28:* `listeners_config` passes `[listeners_public]` through as written (AS2b); the listener
      config rejects a public listener while `enabled = false`; test `public_listener_requires_public_gate`.
- [x] **GL3** 🟠 [code] `max_inflight_per_listener` enforced only on Do53 UDP. *(only udp.rs:138)*
- [x] **GL4** 🟠 [code] Shutdown drains only UDP; TCP/DoT/DoH/DoQ abort in-flight queries. *(conn.rs:227-305, doh.rs:190-196, doq.rs:198-205)*
- [x] **GL5** 🟠 [code] Malformed DoH never records a ban strike. *(bans.rs:11-18; only doq.rs uses it)*
- [x] **GL6** 🟠 [code] Error replies (NOTIMP/FORMERR/REFUSED) drop EDNS OPT. *(core.rs:107-158)*
- [x] **GL7** 🟡 [code] Query events omitted for pre-policy/admission/timeout answers. *(core.rs:99-174, conn.rs:417-429)*
- [x] **GL8** 🟡 [code] DoQ/DoH diverge from the core's FORMERR/drop rules (QR=1, undecodable). *(doq.rs:518-588, doh.rs:531-537)*
- [x] **GL9** 🟡 [code] DoQ completes handshake before SNI Client-ID check (no handshake rejection). *(doq.rs:304-369)*
- [x] **GL10** 🟡 [code] Banned sources aggregated globally, not per listener. *(status.rs:12-37)*
- [x] **GL11** 🟡 [code] DDR endpoints built from config, not from successfully bound listeners. *(set.rs:600-613)*
- [x] **GL12** 🟡 [code] Listener default query timeout 10 s vs binary resolver 5 s. *(config.rs:14; engine.rs:49-52)*

## control-api (`SPEC-control-api.md` ↔ `crates/dnscraft-api`)

> ⚠️ dnscraft-api is under active cluster work right now; dispatch these only after cluster CL6–CL8 land.
> GA1–GA4/GA6 (the web-ui blockers) are planned in `plan-webui-api-gaps.md` ·
> `todo-webui-api-gaps.md`. The cluster-work caveat above is resolved (CL6–CL8 landed).

- [x] **GA1** 🔴 [code] `GET /api/v1/auth/me` route missing. *(router.rs:153-168; roles.rs:184 reserves it)*
- [x] **GA2** 🔴 [code] `GET /api/v1/auth/tokens` missing (only POST). *(router.rs:155; tokens.rs:263-287 unused)*
- [x] **GA3** 🔴 [code] `DELETE /api/v1/auth/tokens/{id}` missing; `revoke` lacks owner check. *(router.rs; tokens.rs:294-308)*
- [x] **GA4** 🔴 [code] `GET /api/v1/audit` missing (`Db::audit_list` + `AuditRead` exist but unwired). *(storage/audit.rs:118-125; error.rs:154-159)*
- [ ] **GA5** 🔴 [owner] `Apply*` traits have no production impl → `PUT /config` persists but applies nothing. *(modules.rs:49-60)* — belongs to G0.
- [x] **GA6** 🟠 [code] `GET /api/v1/clients` hardcodes `[]`; `POST /clients/sync` always `not_configured`. *(clients_routes.rs:129-138, 230-242)* — API side done: `ClientDirectory` trait + `AppState::with_clients`; **open for the assembler (GA6c, `crates/dnscraft`): implement the trait over `ClientEngine` and call `with_clients`.**
      *Done 2026-10-28 (GA6c):* `EngineDirectory` implements the trait over `ClientEngine`; `control_api.rs` calls `with_clients`. Open detail: `last_seen` is `null` (dnscraft-api's RFC 3339 helper is crate-private).
- [x] **GA7** 🟠 [code] Idempotency-Key not read or stored anywhere. *(grep Idempotency → 0)*
- [x] **GA8** 🟠 [code] Rate limit keyed only by source IP, not per principal. *(rate_limit.rs:1-9, 242-293)*
- [x] **GA9** 🟠 [code] `/mcp/v1` requests don't count against the auth bucket. *(rate_limit.rs:256-264)*
- [x] **GA10** 🟠 [code] `X-Forwarded-Proto` honoured unconditionally (spoofable); only `X-Forwarded-For` checks `trusted_proxies`. *(local.rs:346-351, oidc.rs:495-513)*
- [x] **GA11** 🟠 [code] Local-login lockout per account only, no per-IP counter. *(local.rs:181-276, migrations.rs:92-99)*
- [x] **GA12** 🟠 [code] OIDC `groups` claim name hardcoded (no config field). *(oidc.rs:74-81; config.rs:100-126)*
- [x] **GA13** 🟠 [code] OIDC login success/failure not audited; token create/revoke and logout not audited. *(oidc.rs:297-488, tokens.rs:326-367, auth/mod.rs:296-315)*
- [x] **GA14** 🟠 [code] `GET /status` returns only TLS fields (no node/module/version). *(router.rs:235-250)*
- [ ] **GA15** 🟠 [code] Runtime-editable keys (OIDC/accounts/retention/rollups) not exposed via `/config`. *(config_apply.rs:33-44)*
- [x] **GA16** 🟠 [code] `stats/overview` omits filter-hit by list/rule, `query_log.dropped`, active clients; stats read only raw log, not rollups (1-year dashboards → 30 days). *(stats.rs:113-140, stats_routes.rs:85-126)*
  *Done 2026-10-28 (commit fbf3200, docs 8ac9464):* `source` raw/rollup, `active_clients`, `query_log_dropped` (needs `QueryLog::with_sink` in the assembler, see report), `filter_hits`.
- [x] **GA17** 🟠 [code] SQLite query-log read errors map to `control_api.internal`, not `query_log.read`. *(query_log.rs:419-423, 467-494)*
- [x] **GA18** 🟠 [code] `paused_until` stored as versioned filter-set config (spec: runtime-only). *(config_apply.rs:47-56, filter_routes.rs:44-63)*
- [x] **GA19** 🟠 [code] `status.mode` can never report `manual` after upload. *(tls.rs:226-235, 272-326, 736-741)*
- [x] **GA20** 🟡 [code] Token/version timestamps as unix ints, not RFC 3339. *(tokens.rs:356-365, config_routes.rs:216-219)*
- [x] **GA21** 🟡 [spec] Config persisted-after-apply vs spec's persist-then-mark-failed. *(config_apply.rs:9-12, 462-473)*
- [x] **GA22** 🟡 [code] Dead codes: `config.apply`, `query_log.dropped`, `audit.read`, `auth.unknown_token`. *(error.rs, response.rs)* *Done 2026-10-28 (b76dc51): `audit.read` and `auth.unknown_token` are already wired; unmapped module apply failures now become `config.apply`; `query_log.dropped` variant removed (counter is `query_log_dropped` in the overview).*
- [x] **GA23** 🟡 [code] `protocol`/`status` filter values not validated as enums. *(query_log_routes.rs:59-76)*
- [x] **GA24** 🟡 [spec] `filter.reason` stores provenance, not the documented `"adblock"`-style reason. *(query_log.rs:824-838)*
- [x] **GA25** 🟡 [code] Manual cert upload accepts private-key material. *(tls_routes.rs:348-377)*
- [x] **GA26** 🟡 [code] UniFi settings / local-domain mode have no typed route. *(clients_routes.rs)*
- [ ] **GA27** 🟡 [code] No control-api fuzz target. *(fuzz/fuzz_targets/)*
- [x] **GA28** 🟡 [code] No bootstrap-to-SQLite config seeding path. *(config.rs:192-227; config_apply.rs:845-853)*
- [x] **GA29** 🟡 [code] `/readyz` reports ready with no module producers. *(server.rs:289-324)* — API side done: `Readiness::expect_module` keeps `/readyz` at 503 until each registered module calls `set_ready`; **open for the assembler (`crates/dnscraft`, G0): register and report each module.**
      *Done 2026-10-28:* `control_api.rs::report_readiness` registers resolver, filtering, clients, policy, listeners (and tls when configured) and reports each from the live engine; a listener bind failure reports `listeners` not ready.

## MCP (`SPEC-mcp.md` ↔ `crates/dnscraft-mcp` + `dnscraft-api` mcp files)

- [x] **GM1** 🔴 [owner] `[control_api.mcp]` never deserialized (`McpConfig` no serde; `#[serde(skip)]`).
      *(mcp/config.rs:59; api/config.rs:209-211)* — belongs to G0.
      *Done 2026-10-28:* Closed by AS0 (`McpConfig` Deserialize) — verified 2026-10-28.
- [x] **GM2** 🔴 [owner] MCP service not mountable in production (`with_mcp_backend` dead,
      `McpBackendInner` crate-private). *(api/server.rs:150-159, api/router.rs:180-185)* — belongs to G0.
      *Done 2026-10-28:* Closed by AS11 (`control_api.rs` attaches the backend and mounts `/mcp/v1`) — verified 2026-10-28.
- [x] **GM3** 🔴 [code] `list_clients` always returns empty in the real backend. *(api/mcp_backend.rs:1298-1307)*
      *Done 2026-10-28:* `mcp_backend_inner` takes the client directory; `list_clients` filters (source, name), pages (offset/limit, `has_more`). Smoke test `boots_every_engine_and_serves_the_control_api`.
- [x] **GM4** 🟠 [code] `get_status` returns empty listeners/filtering/TLS; `resolver.primed`
      approximated as `cache_size > 0`. *(api/mcp_backend.rs:1309-1344)*
      *Done 2026-10-28:* listeners come from a weak listener-set status closure, `resolver.primed` from `priming_status()` and `cache_size` from `stats().cache_entries` (`mcp_backend_inner` takes the resolver handle). Filtering and TLS were real already.
- [x] **GM5** 🟠 [code] `explain_block.block_mode` always empty. *(api/mcp_backend.rs:811-822)*
      *Done 2026-10-28:* Block mode read from the set snapshot (`mcp_backend.rs` explain).
- [ ] **GM6** 🟠 [code] `get_stats` ignores `profile_id`. *(api/mcp_backend.rs:1229-1298)*
  *API side done 2026-10-28 (445d840): `StatsScope` + `*_scoped` methods in `stats.rs`, REST `profile_id`. Still open in `mcp_backend.rs` (not owned by this agent): `get_stats` must call `stats_overview_scoped` / `top_clients_scoped` / `top_blocked_domains_scoped` / `cache_stats_scoped` with `StatsScope { profile_id: params.profile_id.as_deref(), .. }`.*
      *Open 2026-10-28:* needs a `profile_id` filter in `dnscraft-api/src/stats.rs` (overview, top clients, top blocked, cache, and rollups). Touches the shared stats module and `stats_routes.rs`, so not done in this MCP pass.
- [x] **GM7** 🟠 [code] `list_mcp_rules` lists expired pauses; pauses branch ignores pagination. *(api/mcp_backend.rs:870-877; filtering/engine.rs:480-495)*
      *Done 2026-10-28:* Pauses drop expired entries and paginate (`mcp_backend.rs` list_mcp_rules); test `list_mcp_pauses_omit_an_expired_pause`.
- [x] **GM8** 🟠 [code] Tool layer collapses domain errors to `mcp.invalid_input` (spec wants
      `filter_build.*`/`filter_name.*`/`mcp.domain_too_broad`). *(mcp/tools/write.rs:784-803, read.rs:519-547; api/mcp_backend.rs:470-475)*
      *Done 2026-10-28:* Domain failures forward `filter_build.*` / `filter_name.*` codes (`protected.rs` canonicalize, `write.rs` validate_domain, `read.rs` read_domain); tests `domain_rejections_forward_the_filtering_codes`.
- [x] **GM9** 🟠 [code] Read-tool telemetry counter `mcp.tool_calls{…}` missing. *(not found)*
      *Done 2026-10-28:* Implemented as a structured `tracing` event `counter="mcp.tool_calls"` (`tools/mod.rs`); no metrics exporter exists yet, so untested.
- [x] **GM10** 🟠 [code] `/mcp/v1` while disabled returns 401/403 (RBAC middleware) instead of
      404 `control_api.not_found`. *(api/auth/roles.rs:201-203, 270-306; api/router.rs:180-187)*
      *Done 2026-10-28:* RBAC middleware answers a disabled `/mcp/v1` with 404 before auth (`roles.rs`); test `disabled_mcp_endpoint_is_not_found_before_authentication`.
- [x] **GM11** 🟠 [code] `allowed_origins` never populated (empty `ponytail:` block). *(api/server.rs:358-363)*
      *Done 2026-10-28:* Closed by AS11 (`control_api.rs` fills `allowed_origins`); the dead empty block in `server.rs` serve() removed.
- [x] **GM12** 🟠 [code] `search_query_log`/`get_query` map read errors to `control_api.internal`,
      never `control_api.query_log.read`. *(api/mcp_backend.rs:1139-1165; mcp/tools/read.rs:414-427)*
      *Done 2026-10-28:* Query-log read failures keep `control_api.query_log.read` (`query_log_error`); unit test `query_log_read_failures_keep_their_code`.
- [x] **GM13** 🟡 [code] `test_query.filter.list_id` always null. *(api/mcp_backend.rs:1028-1036)*
      *Done 2026-10-28:* `test_query` reports the list id of a list-sourced block (`mcp_backend.rs`); no dedicated test yet.
- [x] **GM14** 🟡 [code] `test_query` TXT/SRV/SOA answers as `<TXT>`/`<SRV>`/`<SOA>` placeholders. *(api/mcp_backend.rs:358-376)*
      *Done 2026-10-28:* TXT, SOA and SRV render in presentation form (`mcp_backend.rs` rdata_str); test `test_query_answers_render_txt_soa_and_srv`.
- [x] **GM15** 🟡 [code] REST `temporary-allows`/`custom-rules` discard the request `reason`. *(api/mcp_endpoints.rs:321, 496)*
      *Done 2026-10-28:* REST temporary-allow and custom-rule keep the sanitized reason in the audit row; test `temporary_allow_keeps_its_reason_in_the_audit`.
- [x] **GM16** 🟡 [spec] MCP crate implements an independent rate limiter not in the spec's TOML. *(mcp/transport.rs:542, rate_limit.rs)*
      *Done 2026-10-28:* Resolved as [spec]: SPEC-mcp.md now documents the mcp-owned per-token buckets and their config keys.
- [x] **GM17** 🟡 [code] Canonicaliser rejects whitespace instead of trimming. *(mcp/protected.rs:92-110)*
      *Done 2026-10-28:* `canonicalize` trims surrounding whitespace; inner whitespace still rejected; test `canonicalize_trims_and_reports_filtering_codes`.

## Cluster follow-ups (wave 2, 2026-10-28) — `SPEC-cluster.md` ↔ `crates/dnscraft-cluster` + cluster wiring in `dnscraft-api`

Source: the open list left after Checkpoint F (`cluster-security-review-followups`, `cluster-offline-write-read-gap`).

- [x] **CF1** 🔴 [code] Node certificate renewal over the mTLS channel before expiry. *Done 2026-10-28:* `POST /cluster/v1/renew` (CSR for the current key, authenticated by the presented certificate); the master makes the new fingerprint current and keeps superseded certificates accepted until they expire (`cluster_superseded_certs`, migration v4), so a lost response cannot lock a node out; the sub-node renews at two thirds of the lifetime from its maintenance tick and rebuilds its client. SPEC-cluster § Node identity and join. Tests: `tests/join.rs` (`renewal_is_due_after_two_thirds_of_the_lifetime`, `renewal_replaces_the_certificate_and_keeps_the_previous_one_until_revoked`, `renewal_csr_for_another_node_is_rejected_and_nothing_changes`, `persisting_a_certificate_for_another_key_is_refused`).
- [x] **CF2** 🟠 [code] Wire `[cluster.timing]`. *Done 2026-10-28:* `heartbeat_interval` drives the sub-node maintenance pass (heartbeat + renewal check; the heartbeat was never sent before); `master_timeout` bounds connect and the relay retry window (`ClusterClient::new_with_timing`); `reconnect_backoff`/`reconnect_backoff_max` shape the reconnect and relay loops; `config_apply_timeout` drives degraded reporting (CF6). `ClusterServerConfig` gained `timing` (literal constructions updated). Offline-queue replay keeps its built-in backoff (open, 🟡 [code]).
- [x] **CF3** 🟠 [code] `GET /api/v1/cluster/writes/{request_id}` emits `expires_at` (RFC 3339) and `result` `{status}`. *Done 2026-10-28:* `api/cluster_endpoints.rs`; the crate already persisted both (commit `9f6d7ea`). Test: `write_with_a_queue_reports_its_state` asserts the exact deadline and `result: null` while pending.
- [x] **CF4** 🟠 [code] Durable relay idempotency cache. *Done 2026-10-28:* answers live in `cluster.db` (`relay_responses`, migration v5, 24 h); `ConfigWriteExecutor::with_store` is used by the master runtime. Test: `relayed_answer_survives_a_master_restart`. A storage failure after the apply is logged, not returned (best-effort for that one write).
- [~] **CF5** 🟠 [owner→decided] `push_cert` broadcast the shared wildcard private key to every node. *Owner decided option B (per-node CSR relay), 2026-10-28.* *Done (cluster side):* the master sends `tls_renewed` with names only; a node generates its own key, posts a CSR to `POST /cluster/v1/tls/certificate` and installs the chain with its local key (`request_tls_certificate`); `push_cert` and `CertPush` are removed. Tests: `tests/sync.rs` (`tls_renewal_notice_carries_names_and_no_key`, `node_requests_its_own_certificate_and_the_master_never_sees_its_key`, `tls_certificate_request_without_a_signer_is_refused`, `revoked_node_cannot_request_a_tls_certificate`, `failing_cert_install_is_reported_as_cert_push_failed`). **Open (🔴 for the feature):** `dnscraft-tls` needs an ACME finalize with an external CSR (`TlsCsrSigner` implementation in the assembler); until then the master answers `cluster.internal`. SPEC-cluster § TLS certificate distribution.
- [x] **CF6** 🟡 [code] `cluster.config.stale` and `cluster.master_conflict` are emitted. *Done 2026-10-28:* a node past `config_apply_timeout` without an ack gets `cluster.config.stale` in its heartbeat response and is counted as `cluster.degraded_nodes` in status; a node reporting a version the master never published gets `cluster.master_conflict` (a warning; master-wins still applies). SPEC row updated: a conflict is not a refused connection, and a second master is not detectable in v1. Tests: `quota.rs::unacked_push_past_the_apply_timeout_is_stale_in_heartbeat`, `quota.rs::node_ahead_of_the_master_is_a_master_conflict_warning`, `sync.rs::a_node_without_an_ack_is_degraded_after_the_apply_timeout`.
- [x] **CF7** 🟡 [code] Channel hardening. *Done 2026-10-28:* at most 8 concurrent connections per authenticated node (extra ones dropped after the handshake); heartbeats 1/s per node with burst 10; enroll attempts 1/s listener-wide with burst 10; refusals are `cluster.quota.exceeded`. Tests: `quota.rs` (`heartbeat_flood_is_rejected_per_node`, `enroll_attempts_are_rate_limited_listener_wide`, `one_node_cannot_hold_more_than_its_connection_cap`).
- [x] **CF8** 🟡 [code] Sub-node log `buffer_retention` pruning. *Done 2026-10-28:* `LogOutbox::prune` (default no-op) and `LogStreamer` prune at most once a minute, also while the master is down; `QueryLog::prune_outbox_before` detaches unacked rows older than the retention (query rows stay local); dropped rows are counted and the sub-node logs `cluster.log_buffer_dropped`. Test: `cluster_wiring.rs::expired_unacked_outbox_rows_are_pruned_and_the_gap_is_reported`. No row-count cap in v1 (not configured).
- [x] **CF9** 🟡 [code] Offline-queue replay backoff uses `[cluster.timing] reconnect_backoff`/`reconnect_backoff_max` (`OfflineWriteQueue::with_backoff`). *Done 2026-10-28:* wiring only; no dedicated test (the replay delay needs a clock-advancing helper task).
- [x] **CF10** 🔴 [code, owner-decided] `TlsCsrSigner` for the master: `dnscraft-tls` finalizes an ACME order with a node-supplied CSR (new path next to `finish_dns01_order`), and the assembler attaches it with `ClusterServer::attach_tls_signer`. The master must also check the CSR names against its configured names. Tracked here because the TLS module is outside the cluster-owned files. *Done 2026-10-28:* `dnscraft_tls::sign_csr` / `TlsEngine::sign_csr` (shared `order_dns01` with `issue`; CSR names checked against `default_identifiers`; order lock shared with renewal); `dnscraft_api::TlsEngineCsrSigner` implements `TlsCsrSigner`; `ClusterRuntime::attach_tls_engine` attaches it. Tests: `dnscraft-tls/tests/issue.rs` (`sign_csr_*`). **Not wired in production yet:** the assembler (`crates/dnscraft`) does not start `ClusterRuntime`, so the `attach_tls_engine(engine)` call goes in when it does. The cluster SPEC text and `dnscraft-cluster/README.md` still say "not yet available".
