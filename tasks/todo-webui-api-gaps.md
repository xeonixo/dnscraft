# Todo: web-ui blocking control-api gaps (GA1–GA4, GA6)

> Contract & ordering: `plan-webui-api-gaps.md`. Gaps: `todo-spec-gaps.md` § control-api.
> One commit per task, `Co-Authored-By` line, Log entry in `progress.md`. Crate-scoped
> gates (`cargo fmt --check`, `cargo clippy -p dnscraft-api --all-targets`,
> `cargo test -p dnscraft-api`) per task.

## Phase 0 — auth/me + CSRF (GA1)

- [x] **GA1** `GET /api/v1/auth/me`: `auth_me` handler returning
      `{ role, actor_id, actor_type, csrf_token }` (D1); register `get(auth_me)` beside
      the other auth routes. RBAC already maps it to `Requirement::Api`.
      Tests: authenticated viewer/admin gets their role + a stable CSRF token matching
      `csrf::csrf_token_for`; unauthenticated → `401`.

## Phase 1 — token list + revoke (GA2, GA3)

- [x] **GA2** `GET /api/v1/auth/tokens`: `list_tokens` handler over
      `TokenStore::snapshot_entries()` → array of
      `{id, name, scope, actor_id, created_at, expires_at}` (D2, never plaintext);
      register `get(list_tokens)`. Tests: admin lists; viewer `403`; response contains
      no plaintext token.
- [x] **GA3** `DELETE /api/v1/auth/tokens/{id}`: `delete_token` handler over
      `TokenStore::revoke(id)` (D3); register `delete(delete_token)`. Tests: admin
      revokes → `200` + token stops authenticating; unknown id → `404
      auth.unknown_token`; viewer → `403`.

## Phase 2 — audit list (GA4)

- [x] **GA4** `GET /api/v1/audit`: `list_audit` handler over `Db::audit_list(limit,
      offset)` with defaulted + capped `limit`/`offset` (D4); register `get(list_audit)`.
      Tests: admin lists newest-first; viewer `403` (D4); redacted rows (no secret
      material); read failure maps to `control_api.audit.read` (GA22).

## Phase 3 — clients directory + sync (GA6)

- [x] **GA6a** `AppState::with_clients(Arc<ClientEngine>)` + accessor; `list_clients`
      returns `engine.lookup().clients()` mapped to the D5 DTO (falls back to the
      current manual-only/empty shape when no engine is wired). Tests: empty
      directory, manual-only, mixed UniFi+manual.
- [x] **GA6b** `sync_clients` calls `engine.sync_now()` → `SyncReport`, mapping
      errors to `clients.*` codes; keeps `clients.sync.not_configured` when no engine.
      Tests: sync success + report, sync error mapping, no engine → `not_configured`.
- [ ] **GA6c** Binary wiring: the assembler hands the built `ClientEngine` to
      `AppState::with_clients` (reuses the `EngineClients` already built for the query
      log). Gate: `cargo test -p dnscraft` green; a smoke config boots with clients
      disabled.

## Checkpoints

- [ ] After GA1: `cargo test -p dnscraft-api` green; `auth/me` returns role + CSRF.
- [ ] After GA1–GA3: token CRUD e2e (create → list → revoke → 401).
- [ ] After GA1–GA4: auth + audit routes served; RBAC matrix green.
- [ ] After GA6: `GET /clients` returns the real directory; `POST /clients/sync`
      returns a report (or `not_configured` without UniFi); assembler boots.

## Found while building the SPA login (W4, 2026-10-28)

- [ ] **GA-W4a** OIDC callback (`api/auth/oidc.rs`) returns a JSON envelope; it must redirect back to the SPA
      (validated same-origin `return_to`), otherwise the browser login ends on a JSON page.
- [ ] **GA-W4b** `authorize-url` accepts no `return_to`; add it (same-origin path only, validated server-side).
- [ ] **GA-W4c** `auth_middleware` validates any cookie before public routes (`/auth/local/login`,
      `authorize-url`): an expired cookie yields 401 `session_expired` with no `Set-Cookie` to clear it, so the
      user cannot sign in again. Public routes must ignore/clear a stale cookie; logout must clear it too.
- [ ] **GA-W4d** CSRF token is delivered in the `auth/me`/login body only; the `dnscraft_csrf` cookie from the
      web-ui decision does not exist. Either add it or amend SPEC-web-ui to "body field only".
- [ ] **GA-W4e** `Retry-After` on 429 should be exposed as `params.retry_after` so the SPA can back off.

## Found while building the dashboard (W5, 2026-10-28)

- [ ] **GA-W5a** `stats/overview`: add response-time percentiles (p50/p95) and a time series so the dashboard can
      show latency tiles and sparklines (SPEC-web-ui Dashboard bullet).
- [ ] **GA-W5b** Route a blocked-domains ranking (`top_blocked_domains` exists in the library, not routed);
      the UI currently approximates it client-side from the top 100 domains.
- [ ] **GA-W5c** Expose the active pause state (read endpoint) so the UI can show/resume an active pause.
- [ ] **GA-W5d** Add `resolver.*` upstream error codes to the stable-code catalogue for translation.
- [ ] **GA-W5e** SPEC-web-ui: the pause path is `/filtering/pause`, not `/policy/pause`; no `/statistics` route
      exists (merged into the dashboard) — align the spec.
- [ ] **GA-W5f** No requests-over-time endpoint: `stats/*` returns totals, top lists and the cache ratio, but no
      time buckets (the rollup buckets in `stats.rs` are not routed). The dashboard therefore has no
      "Anfragen im Zeitverlauf" chart (blocked highlighted). Proposal: `GET /api/v1/stats/timeseries` with the same
      `from`/`to`/`node_id`/`profile_id` filters and a bucket size, returning `{bucket_start, total, blocked}` rows.
      Then add an inline-SVG chart beside Antwortquellen with a table fallback. Overlaps with the sparkline part of GA-W5a.

## Found while building the query log (W6, 2026-10-28)

- [ ] **GA-W6a** Query-log records carry no `status`; the UI derives it. Add an explicit status and a `cache` filter value.
- [ ] **GA-W6b** `query_log_dropped` is only available via `GET /stats/overview`; expose it on the query-log response.
- [ ] **GA-W6c** Add a total count (or a cheap estimate) and a qtype/IP filter to `GET /query-log`.
- [ ] **GA-W6d** `mcp.*` error codes (e.g. protected domain) need translations in the code catalogue.
- [ ] **OWNER** "Dauerhaft blockieren" from the log: custom rules expire at `max_block_rule_lifetime`; decide whether a
      permanent block belongs in the UI (not built).

## Found while building policy/clients/filter screens (W8, 2026-10-28)

- [ ] **GA-W8a** SPEC-web-ui says viewers can read policy/clients/filter screens "via config", but
      `roles.rs` marks `/policy/*`, `/clients/*`, `/filter-*` and `/config` reads as admin-only.
      Align SPEC and RBAC (viewer read via GET /config, or allow viewer on those GETs).
- [ ] **GA-W8b** No `GET /policy/profiles` list; UI loads profiles from `GET /config`. Add a list route
      or document config-only.
- [ ] **GA-W8c** Forward zones (`resolver.forward_zones`) lack reverse-zone and profile allow-list fields
      shown in the prototype; confirm whether those belong in the resolver model.
- [ ] **GA-W8d** No filter-list refresh/update endpoint; UI shows a footnote only.
- [ ] **GA-W8e** CNAME uncloaking is not a filter-set API field; add it or drop from the UI toggles.

## Found while building listeners/TLS/cluster/settings (W9, 2026-10-28)

- [ ] **GA-W9a** MCP enable/write_tools live in bootstrap `ControlApiConfig`, not the versioned `/config`
      snapshot. Either expose them via config snapshot or document bootstrap-only editing.
- [ ] **GA-W9b** Temporary allows have no DELETE endpoint — UI can list but not remove.
- [ ] **GA-W9c** Listeners lack a per-client rate-limit field in `listener_routes.rs` (SPEC/UI toggle deferred).
- [x] **GA-W9d** `query_log.ip_truncate` is bootstrap-only; not editable via `/config` (UI shows read-only note).
      Done: `control_api_settings.query_log.ip_truncate` (and `retention_days`) is in the versioned snapshot and applied live to `QueryLog` on boot, `PUT /config`, rollback and cluster sync; default is now `none`.
