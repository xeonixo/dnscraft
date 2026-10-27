# Plan: web-ui blocking control-api gaps (GA1–GA4, GA6)

> Source: `tasks/todo-spec-gaps.md` § control-api. These five gaps block the web-ui
> screens documented in `SPEC-web-ui.md` § Current-state alignment. Tracking IDs are
> stable. One commit per task, `Co-Authored-By` line, Log entry in `progress.md`.
> Crate-scoped gates (fmt/clippy/test on `dnscraft-api`) per task; workspace gates at
> the checkpoint.

## Goal

Close the five control-api gaps that block whole web-ui screens, so the frontend can
be built against a real API surface: `auth/me`, token list + revoke, the audit log,
and the real client directory + UniFi sync.

## Current state (verified 2026-10-27)

- RBAC already reserves the paths (`crates/dnscraft-api/src/api/auth/roles.rs`):
  `/api/v1/auth/me` → `Requirement::Api`; `/api/v1/auth/tokens` and
  `/api/v1/auth/tokens/*` → `Requirement::ApiAdmin`. No RBAC changes needed.
- `TokenStore` already implements `snapshot_entries()` (id_hash, name, scope,
  actor_id, created_at, expires_at — never plaintext) and `revoke(id)` (returns
  `AuthUnknownToken` for unknown ids). No storage work needed for GA2/GA3.
- `Db::audit_list(limit, offset)` and the `AuditRecord` (with redacted
  `before`/`after`) already exist; the `control_api.audit.read` error variant is
  declared but unused (GA22). Only the route + handler are missing for GA4.
- `ClientEngine` exposes `lookup()` → `Arc<ClientLookup>` with
  `clients() -> &[Arc<ClientInfo>]` (the full directory) and
  `sync_now() -> SyncReport`. `AppState` has no clients handle, so `list_clients`
  hardcodes `[]` and `sync_clients` returns `clients.sync.not_configured` (GA6).
- The assembler (`crates/dnscraft`) already builds `EngineClients` (a `ClientEnricher`
  for the query log); it does not yet hand a `ClientEngine` to `AppState`.

## Target

- `GET /api/v1/auth/me` returns the principal (role, actor_id, actor_type) plus the
  CSRF token the SPA echoes on mutations.
- `GET /api/v1/auth/tokens` lists token metadata; `DELETE /api/v1/auth/tokens/{id}`
  revokes; both admin-only.
- `GET /api/v1/audit` lists redacted audit rows, newest first, with limit/offset.
- `GET /api/v1/clients` returns the real merged directory (UniFi + manual);
  `POST /api/v1/clients/sync` triggers a real sync and returns its report.

## Decisions (settled 2026-10-27 — owner accepted the recommended defaults)

- **D1 — CSRF exposure.** `auth/me` returns the CSRF token in the response body
  (recommended; matches `SPEC-web-ui.md` Q2's first option). The token is already
  derivable from the session id (`csrf::csrf_token_for`); the handler must obtain the
  session id for the current request. Alternative: a separate non-HttpOnly
  `dnscraft_csrf` cookie.
- **D2 — token list shape.** v1 returns `id`, `name`, `scope`, `actor_id`,
  `created_at`, `expires_at` from `snapshot_entries`. `last_used` is not tracked and
  is omitted (adding a `last_used` column is out of scope). Timestamps stay unix ints
  unless the owner wants GA20 (RFC 3339) folded in here.
- **D3 — revoke authorization.** Tokens are admin-managed: RBAC `ApiAdmin` on the
  route is the only authorization; there is no per-token "owner" concept. A `viewer`
  gets `403 insufficient_scope`; an admin may revoke any token.
- **D4 — audit role and filters.** Admin-only (`SPEC-web-ui.md` Q6 assumes admin-only;
  confirm against `SPEC-control-api.md`). v1 supports `limit`/`offset` only (the
  storage query has no `WHERE`); actor/action/node/time filters are a follow-up.
- **D5 — clients DTO.** `GET /clients` maps `ClientInfo` to a stable public shape
  (name, source, ips, macs, vlan, local_domain). The exact field list is fixed in the
  task, matching `SPEC-clients.md` and what the query-log enricher already exposes.

## Phases

- Phase 0 — `auth/me` + CSRF (GA1)
- Phase 1 — token list + revoke (GA2, GA3)
- Phase 2 — audit list (GA4)
- Phase 3 — clients directory + sync (GA6)

## Risks

- **GA6 wiring touches the assembler.** Passing a `ClientEngine` into `AppState`
  changes the binary's bootstrap; keep it behind `with_clients` (None when clients
  are disabled) so `GET /clients` degrades to the current empty directory rather than
  failing.
- **CSRF token exposure is security-relevant.** The token must be returned only to an
  authenticated session (`Requirement::Api` already guarantees this) and never logged.

## Open questions

- Does `auth_me` include a `display_name`? The principal carries `actor_id`; a human
  name may need the local-account name or OIDC subject. v1 returns `actor_id` + role
  only unless the owner wants a name.
- Confirm D3/D4 against `SPEC-control-api.md` before implementing GA3/GA4.
