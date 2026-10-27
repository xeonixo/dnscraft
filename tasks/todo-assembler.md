# Todo: production assembler (G0)

> Contract & ordering: [plan-assembler.md](plan-assembler.md). Gaps: [todo-spec-gaps.md](todo-spec-gaps.md) G0.
> One commit per task, `Co-Authored-By` line, Log entry in [progress.md](progress.md). Crate-scoped
> gates where possible; workspace gates at checkpoints. No new dependencies without owner approval.
> Tests never touch the internet or real UniFi/Cloudflare/ACME/OIDC endpoints.

## Phase 0 — Config model (gated on plan decisions D1/D5/D6)

- [x] **AS0** `ControlApiConfig` + `McpConfig` gain `Deserialize` (incl. nested `auth`/`rate_limit`/
      `query_log`/`mcp` blocks), keeping the existing `Serialize`. Uniqueness of `control_api.*`/
      `mcp.*` codes unchanged.
- [x] **AS1** Per D1: add `serde` to `ResolverConfig`, `FilterConfig`, `ClientsConfig`, `TlsConfig`,
      `PolicyConfig` and the listeners config structs (or, if D1 = mirror, add the JSON mirror layer).
      Round-trip tests (Rust → JSON → Rust) per config.
- [x] **AS2** Extend the binary `Config` with `data_dir` + `[resolver]`/`[filtering]`/`[clients]`/
      `[tls]`/`[policy]`/`[listeners_public]`/`[listeners_limits]`/`[listeners_ddr]`/`[control_api]`,
      mapping onto the module configs. Keep `deny_unknown_fields` and the env-secret TLS bootstrap.
      Resolve GL2 (public `enabled` key) and the D6 `ip_truncate` default here.

## Phase 1 — Module assembly

- [x] **AS3** Real resolver from `[resolver]` (replaces `ResolverConfig::default()` in `build_engine`).
- [x] **AS4** Real filtering: open `ListStore` under `data_dir`, build `FilterEngine` from
      `[filtering]` lists/sets (replaces `empty_filter`).
- [~] **AS5** Real clients: build `ClientEngine` from `[clients]`, add a `ClientDirectory` adapter,
      feed it to policy and to the query-log `ClientEnricher` (closes GC1).
- [x] **AS6** Real policy from `[policy]` (views/profiles/records) wired to filter + resolver + clients
      (replaces the hardcoded default view).
- [~] **AS7** Real TLS: build `TlsEngine` (ACME/DynDNS) from `[tls]`, hand its `CertResolver` to the
      listener set, and its `TlsStatusProvider`/`TlsAdmin` to control-api (replaces env-PEM install).

## Phase 2 — Apply + store

- [x] **AS8** `ApplyFiltering`/`ApplyClients`/`ApplyPolicy`/`ApplyListeners`/`ApplyTls` real impls
      (D2): deserialize the JSON section and call the module's `apply_config`/rebuild. Closes GA5.
- [x] **AS9** `Db` + `ConfigStore` + `ConfigService` under `data_dir`, with bootstrap seeding (D4):
      TOML → JSON snapshot → seed `config_versions` once. Closes GA28.

## Phase 3 — control-api + MCP

- [x] **AS10** Assemble `AppState` (auth/OIDC/local/tokens, `QueryLog`, stats, TLS admin/status,
      rate limiter) and call `serve`. Wire `Readiness` producers from the real engines. Closes GA29.
- [x] **AS11** Construct the MCP backend (D3) and mount `/mcp/v1`; populate `allowed_origins` from the
      TLS public domain. Closes GM1/GM2/GM11.

## Phase 4 — Query-log pipeline + delivery

- [x] **AS12** Replace the stdout sink with `QueryLogSink` (SQLite retention/rollups), keeping the
      JSON-lines stdout writer as an optional debug flag. Closes the query-log half of G0.
- [ ] **AS13** Delivery (gated on owner Q7): Dockerfile variants, compose, `HEALTHCHECK`, multi-arch
      `linux/amd64`/`linux/arm64`, musl static build. Closes the delivery findings.

## Checkpoints

- [ ] Phase 0: `cargo build --workspace --locked` + config round-trip tests green.
- [ ] Phase 1: `cargo test --workspace --locked` + a smoke `dnscraft --config` boots all engines.
- [ ] Phase 2: `PUT /config` round-trips through SQLite and applies to a live engine (e2e).
- [ ] Phase 3: `GET /healthz`/`/readyz` + `/mcp/v1` mount + `tools/list` respond.
- [ ] Phase 4: `cargo deny` + `cargo tree -i aws-lc-rs|openssl-sys` empty; docker build succeeds.
