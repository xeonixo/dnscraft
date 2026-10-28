# Todo: web-ui prototype placeholders awaiting backend (WP1–WP5)

> Spec: `SPEC-web-ui.md` § "Required control-api additions" and § "Feature coverage
> beyond the core screens". Prototype: `docs/design/web-ui-prototype.html` (shows these
> as placeholders). Control-api gaps: `tasks/todo-webui-api-gaps.md`.
> Each task needs owner sign-off on the proposed route shape before implementation.
> One commit per task, `Co-Authored-By` line, Log entry in `tasks/progress.md`.

## Phase 0 — spec sign-off

- [ ] **WP1** Alerts (`/alerts`): owner decides between `GET /api/v1/alerts` (proposed
      in SPEC-web-ui) and client-side assembly from `/status`, TLS status and
      filter-list status. Record the decision in SPEC-web-ui § Open questions.
- [ ] **WP2** Update notice (`/settings` → Allgemein): confirm `GET /api/v1/update/check`,
      the opt-out config key name, and the cache interval (proposed ~24 h).
- [ ] **WP3** Automatic backups (`/settings` → Konfiguration): confirm `GET /api/v1/backups`
      and `PUT /api/v1/backups/settings`, or accept the documented-note fallback.
- [ ] **WP4** Blocked services catalog: confirm the runtime download of `services.json` +
      `services_i18n.json` (GPL-3.0, never bundled) and the `available: false` state.
- [ ] **WP5** Blocked services toggle: resolve per-profile (SPEC.md) versus per-filter-set
      (SPEC-filtering.md) before fixing the route in `GET`/`PUT /api/v1/filtering/services`.

## Phase 1 — backend

- [x] **WP1** Implement `GET /api/v1/alerts` in `control-api` (viewer/admin) aggregating
      TLS expiry, failed filter-list updates, cluster node offline and DynDNS failures,
      with `active_count` and `items[]` (`id`, `severity`, `module`, `params`, `target_route`).
      Tests: no alerts → empty list; cert within threshold → one item; viewer allowed.
- [ ] **WP2** Implement `GET /api/v1/update/check` in `control-api` (viewer/admin): binary
      fetches the GitHub latest release, caches it, returns `update_available` and
      `release_url`; disabled or unreachable → `latest: null`. Tests: opt-out returns no
      outbound request; unreachable GitHub returns a coded error, not a 500.
- [ ] **WP3** Implement `GET /api/v1/backups` and `PUT /api/v1/backups/settings` in
      `control-api` (admin): last run, next run, directory, retention count. Tests:
      admin read/write; viewer `403`; invalid retention rejected.
- [x] **WP4** (filtering crate part done 2026-10-28; the route is WP5) Filtering crate: download, cache and back off `services.json` and
      `services_i18n.json` like a filter list, with `available` and `catalog_updated_at`.
      Tests: catalog absent → `available: false`; cached catalog loads offline.
- [ ] **WP5** `control-api`: `GET /api/v1/filtering/services` (viewer/admin) and
      `PUT /api/v1/filtering/services/{service_id}` (admin, `filter_set_id`, `enabled`);
      icons sanitized before serving. Tests: unknown id → `filtering.service.unknown`;
      catalog absent → `filtering.catalog.unavailable`; viewer → `403`.

## Phase 2 — web UI wiring

- [ ] **WP1** Replace the `/alerts` placeholder with the grouped list, the Übersicht badge
      and the dashboard banner row; empty state when `active_count` is 0.
- [ ] **WP2** Replace the Allgemein update row with the "update available" row, the
      release-notes link and the opt-out switch; hide the row when disabled.
- [ ] **WP3** Replace the Konfiguration backup placeholder with status and retention
      controls (admin only); show the documented note when the endpoint is absent.
- [ ] **WP4** Show the `/blocked-services` catalog as unavailable when `available` is false.
- [ ] **WP5** Replace the `/blocked-services` placeholder with the grouped catalog, names
      in the viewer locale and per-set toggles (admin only).

## Checkpoints

- [ ] After WP1–WP3 (Phase 1): alerts, update check and backups endpoints served; RBAC matrix updated.
- [ ] After WP4–WP5: `/blocked-services` lists the real catalog, or shows "unavailable"
      without one; no third-party icon reaches the DOM unsanitized.
- [ ] After Phase 2: no placeholder text remains for the four features in
      `docs/design/web-ui-prototype.html` (the prototype itself is updated by its own owner).
