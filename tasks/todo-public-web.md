# Todo: Web-UI/API öffentlich erreichbar, im UI einstellbar, mit Fail2ban-Sperre (PW1–PW3)

> Nothing here is implemented. Today the UI/API is private-only: `route()` in
> `crates/dnscraft-listeners/src/doh.rs` hands non-DoH paths to the web handler only when
> `private_source()` holds; `ControlApiConfig::validate()` rejects non-private `bind`.
> Phase 0 (owner sign-off on the open decisions) comes before code. Owners: `dnscraft-listeners`
> (routing), `dnscraft-api` (ban + settings endpoint), `web` (settings page).

## Already there (reuse, don't rebuild)

- Per-source token-bucket limits: `crates/dnscraft-api/src/api/rate_limit.rs` (read/write/auth classes, LRU-bounded).
- Per-account and per-source login lockout (GA11): `api/auth/local.rs::authenticate_from`.
- Listener-side strike/ban for malformed DoH: `strike_malformed` in `doh.rs` (admission module).

## PW1 — Öffentlicher Web-Zugang (opt-in)

- [ ] Phase 0 decisions: (a) default off, enabled per setting; (b) UI/API reachable on the shared
      public DoH listener only, never an own wildcard socket (keeps `ensure_internal_socket`); (c) while
      public, `/api/v1/auth/local/login` and OIDC only, everything else needs a session as today;
      (d) TLS mandatory (shared listener already terminates TLS); (e) optional allowlist of CIDRs.
- [x] `route()` (done: `WebSlot::set_public`, `doh.rs::route`; not yet wired to a setting/UI → PW3): replace `private_source` with `private_source || web_public_enabled`; flag lives in
      `WebSlot`/shared state and is hot-swappable (no restart).
- [ ] Tests: `public_source_gets_web_handler_when_enabled`, `public_source_gets_404_when_disabled`,
      `public_toggle_applies_without_restart`; keep `public_listener_routes_the_web_handler_for_private_sources_only` for the default.
- [ ] Spec: update `SPEC-control-api.md` "Internal-only binding" + README security row 9 — the
      invariant becomes "no own public socket; public only via shared listener when opted in".

## PW2 — Fail2ban-Sperre für Web-Zugriffe

Built by reusing the listeners' shared `BanTable` (`bans.rs`; thresholds from `public.ban_strikes/window/duration`,
default 5 strikes / 60 s / 15 min). Deviations from the first draft: the ban is **shared** with DNS
(a banned IP also loses DoH/DoT), is **in-memory only** (lost on restart), has no escalation, and
the unban has no audit row (tracing only). Add when needed.

- [x] `StrikeReason::WebAuth`: strike on failed `POST /api/v1/auth/local/login` (401/423/429) and on any 403
      from the web handler, public sources only. Plain 401s are not counted (SPA probes `/auth/me`).
- [x] Banned public sources never reach the web handler (`web_allowed` in `doh.rs`).
- [x] `GET /api/v1/web-bans`, `DELETE /api/v1/web-bans/{ip}` (admin) over `ListenerSet::banned_sources/unban`.
- [x] Tests: `failed_web_logins_from_a_public_source_ban_it_and_close_the_web_path`,
      `plain_401s_on_public_web_paths_do_not_ban`, `web_bans_list_sorted_and_unban`.
- [ ] Open: persistence across restart, escalating duration, audit row on unban, strikes for 404 scans / bearer failures,
      editing ban thresholds in the UI (today: listeners `public` config).

## PW3 — Einstellungen im UI

- [x] `GET/PUT /api/v1/web-access` (admin), `public_enabled` only so far, stored in
      `control_api_settings.web_access`, applied live via `ModuleAppliers.web` (boot, replace, cluster sync).
      Still open: `allowed_cidrs`, `ban_*` (with PW2).
- [x] (toggle only: `web/src/lib/settings/WebAccessPanel.svelte`; ban list with unban done) Web: Seite unter Einstellungen — Schalter „Öffentlich erreichbar" mit Warnhinweis
      (nur HTTPS, Admin-Passwort/OIDC prüfen), Ban-Parameter, Tabelle gesperrter IPs mit „Entsperren".
      Lead with the toggle + current ban count; thresholds as secondary fields.
- [ ] Lock-out guard: refuse enabling public access while only the default/bootstrap admin password is set.
- [ ] Gates: `cargo fmt --check`, `cargo clippy`, `cargo test -p dnscraft-api -p dnscraft-listeners`, `pnpm check/lint/test`, Playwright toggle + unban flow; verify desktop/mobile/dark in browser.
