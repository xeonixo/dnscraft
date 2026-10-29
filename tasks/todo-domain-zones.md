# Task list: Namen-Modul — Split-DNS (öffentlich zuerst)

Plan and rationale: [plan-domain-zones.md](plan-domain-zones.md).
Branch: `feature/public-domain-zones`.
Verification commands: Rust `cargo fmt --all -- --check`,
`cargo clippy -p <crate> --all-targets --locked -- -D warnings`,
`cargo test -p <crate> --locked`; web (from `web/`)
`node_modules/.bin/svelte-check --tsconfig ./tsconfig.json`,
`node_modules/.bin/eslint .`, `node_modules/.bin/vitest run`,
`node --test mock/server.test.mjs mock/no-html.test.mjs`, then
`vite build && node scripts/gen-sw.mjs && node scripts/gen-csp-hashes.mjs`
and browser check (desktop, 375 px, dark).
Definition of Done: tests green, behaviour checked at runtime, docs updated.

## Phase 0: Decision gate (no code)

- [ ] **D1** Owner confirms (or amends) plan decisions and open questions in
      [plan-domain-zones.md](plan-domain-zones.md): **public first, deviate by
      Netzbereich**; shared CF token; one Namen-Modul; override UI; attach model;
      record types.

## Phase 1: Local overrides + CF read

- [ ] **T0** Netzbereich-Overrides-UI (ersetzt Freitext)
  - **Description:** Im Namen-Sheet: statt `zone=wert`-Textarea eine Liste
    „Abweichungen“ — Netzbereich wählen + Wert. Leer/fehlend = erbt öffentlich /
    lokalen Default. Views aus `GET /policy/views`.
  - **Acceptance criteria:**
    - [ ] Kein Freitext `id=wert`; Picker + Wertfeld; Speichern schreibt `overrides`.
    - [ ] Copy sagt Netzbereich, nicht Zone; Viewer read-only.
  - **Verification:** vitest page tests, svelte-check, eslint; browser check
  - **Dependencies:** D1
  - **Files likely touched:** `web/src/routes/names/+page.svelte`, messages, tests
  - **Estimated scope:** M

- [ ] **T1** CloudflareClient: zone inventory + list all records in a zone
  - **Description:** Extend `dnscraft-tls` Cloudflare client so control-api can list
    zones visible to the token and list (paginated) DNS records for one zone without
    requiring a name+type filter. Keep existing filtered helpers for ACME/DynDNS.
  - **Acceptance criteria:**
    - [ ] `list_zones()` returns zone id, apex name, status, name_servers (mocked).
    - [ ] `list_zone_records(zone_id, { page, per_page, name_substr? })` returns
          records with id, name, type, content, ttl, proxied; pages through CF API.
    - [ ] Existing ACME/DynDNS paths and write_lock behaviour unchanged.
  - **Verification:**
    - [ ] `cargo test -p dnscraft-tls --locked` (new mock CF tests + regression)
    - [ ] clippy/fmt clean for the crate
  - **Dependencies:** D1
  - **Files likely touched:** `crates/dnscraft-tls/src/cloudflare.rs`, tls tests/mocks
  - **Estimated scope:** M

- [ ] **T2** Control-API read routes for Domain-Zonen
  - **Description:** Expose admin/viewer GETs that proxy Cloudflare through the TLS
    engine’s client. Surface attached zones (public_domain + `dns_provider.zones`) and
    optionally discoverable zones. No secrets in responses; missing token → stable
    error code the UI can map to a CTA.
  - **Acceptance criteria:**
    - [ ] `GET /api/v1/domain-zones` returns attached zones (+ `has_cloudflare_token`,
          discoverable list or separate `?discover=1` for admin).
    - [ ] `GET /api/v1/domain-zones/{zone_id}/records` returns paginated records;
          unknown/unattached zone → `control_api.not_found` or documented CF error.
    - [ ] Viewer allowed to read; no real Cloudflare contacted in tests (loopback mock).
  - **Verification:**
    - [ ] `cargo test -p dnscraft-api --locked` (new http tests)
    - [ ] `docs/API-REFERENCE.md` + `SPEC-control-api.md` draft rows
  - **Dependencies:** T1
  - **Files likely touched:** `crates/dnscraft-api/src/api/router.rs`, new route module,
    `tls` engine access, tests, docs
  - **Estimated scope:** M

- [ ] **T3** Namen-Editor: Öffentlich zuerst (read) + Abweichungen
  - **Description:** Ein Modul `/names`. Sheet/Karte: oben **Öffentlich** (CF-Wert
    wenn Zone angebunden), darunter Netzbereich-Abweichungen (T0). Token fehlt → CTA
    zu TLS. Kein Lokal-vs-Cloudflare-Tab als zwei Welten.
  - **Acceptance criteria:**
    - [ ] Editor-Reihenfolge: Öffentlich → Abweichungen je Netzbereich.
    - [ ] Ohne Override sichtbar „wie öffentlich“ / erbt; nur-intern ohne CF-Zeile OK.
    - [ ] Viewer read-only; mock mit Split-Beispiel (gleicher Name, anderer LAN-Wert).
  - **Verification:** vitest, svelte-check, eslint, mock, browser
  - **Dependencies:** T0, T2
  - **Files likely touched:** `web/src/routes/names/`, api client, messages, mock
  - **Estimated scope:** M

### Checkpoint: After T0–T3

- [ ] Overrides ohne Freitext; öffentlicher Wert sichtbar wenn CF angebunden
- [ ] Owner review bevor Write-Path

## Phase 2: Write path

- [ ] **T4** Mutate records + attach/detach zones (API + client)
  - **Description:** Generic create/update/delete for v1 record types on an attached
    zone; attach/detach updates `dns_provider.zones` (and stays consistent with TLS).
    All mutations hold the Cloudflare write guard.
  - **Acceptance criteria:**
    - [ ] `POST/PUT/DELETE …/domain-zones/{zone_id}/records` for A/AAAA/CNAME/TXT/MX/SRV
          (content/ttl/proxied validation; CF errors mapped).
    - [ ] `POST /domain-zones/attach` / `DELETE …/attach/{apex}` updates config; does not
          delete the Cloudflare zone.
    - [ ] Concurrent ACME path still serialised via write_lock (test or documented guard).
  - **Verification:**
    - [ ] `cargo test -p dnscraft-tls -p dnscraft-api --locked`
    - [ ] API reference + control-api spec updated
  - **Dependencies:** T2, Checkpoint read path
  - **Files likely touched:** `cloudflare.rs`, domain-zones routes, `config_apply` /
    TLS put path, tests, docs
  - **Estimated scope:** M

- [ ] **T5** Namen-Editor schreibt Öffentlich + hält lokalen Default aligned
  - **Description:** Speichern von „Öffentlich“ → CF upsert + lokaler Default/`rdata`
    gleichziehen; Netzbereich-Zeilen nur `overrides`. Zone anbinden; proxied-Warnung
    für DoT-Namen; admin-only.
  - **Acceptance criteria:**
    - [ ] Öffentlich speichern aktualisiert CF und lokalen Default; Overrides bleiben.
    - [ ] Abweichung speichern/löschen nur `overrides`; Attach/Detach wie T4.
    - [ ] Proxied-Warnung auf inventory / `*.dns.<domain>`; Token-CTA zu `/tls`.
  - **Verification:** vitest (public save, override, attach, viewer), mock, browser
  - **Dependencies:** T3, T4
  - **Files likely touched:** `web/src/routes/names/`, api client, messages, mock
  - **Estimated scope:** M

### Checkpoint: After T4–T5

- [ ] Gleicher Name: öffentlich setzen, pro Netzbereich abweichen, Viewer read-only
- [ ] ACME/DynDNS regression green; Owner-Smoke gegen echte CF-Zone

## Phase 3: Polish

- [ ] **T6** Specs, cross-links, copy polish
  - **Description:** Document the feature; point DoH/TLS „public DNS“ notes at Domain-
    Zonen; keep SPEC non-goal clear (proxy ≠ authoritative hosting).
  - **Acceptance criteria:**
    - [ ] `SPEC.md` feature row + non-goal clarification; `SPEC-web-ui.md` screen row;
          `SPEC-control-api.md` / `SPEC-tls.md` as needed; API reference complete.
    - [ ] DoH/TLS UI strings that say „set in public DNS“ link or mention Domain-Zonen.
    - [ ] Optional low-effort: wire `GET /tls/records` in `web/src/lib/api/tls.ts` only if
          the TLS screen still needs the inventory panel; Domain-Zonen remains the editor.
    - [ ] de/en messages complete; no leftover placeholder copy. MCP tools explicitly deferred.
  - **Verification:**
    - [ ] Spec links resolve; grep for stale „DNScraft setzt sie nicht“ where superseded
    - [ ] Full web + relevant crate tests green
  - **Dependencies:** T5
  - **Files likely touched:** `SPEC*.md`, `docs/API-REFERENCE.md`, messages, DoH/TLS pages
  - **Estimated scope:** S

### Checkpoint: Complete

- [ ] All acceptance criteria above met
- [ ] Ready for code review / PR
