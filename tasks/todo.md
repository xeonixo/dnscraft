# Task list: Named Client IDs, device link, `.mobileconfig`

Plan and rationale: [plan.md](plan.md). Verification commands: Rust `cargo fmt --all -- --check`,
`cargo clippy -p <crate> --all-targets --locked -- -D warnings`, `cargo test -p <crate> --locked`;
web (from `web/`, pnpm is not installed here) `node_modules/.bin/svelte-check --tsconfig ./tsconfig.json`,
`node_modules/.bin/eslint .`, `node_modules/.bin/vitest run`, `node --test mock/server.test.mjs
mock/no-html.test.mjs`, then build with `vite build && node scripts/gen-sw.mjs && node
scripts/gen-csp-hashes.mjs` and look at the page in the browser (desktop, 375 px, dark).
Definition of Done: tests green, behaviour checked at runtime, docs updated.

## Phase 0: Decision gate (no code)

- [x] **D1** Owner answer (2026-10-28): rules stay with the device on the road, only some records
      differ → Phase 2 is in. Order: subnet → Client-ID pin → default. Still to confirm in T6 that a
      pin only replaces the default for unmatched IPs.
- [ ] **D2** Owner confirms label rules (optional, unique case-insensitive, max 64 chars), device link
      scope (all directory clients) and whether the Apple profile asks for a home-Wi-Fi SSID.

## Phase 1: Named Client IDs and `.mobileconfig` (no policy change)

- [x] **T1** Client ID entries carry a label and an optional device reference (API slice)
  - Acceptance:
    - [ ] `policy.client_ids` accepts string entries (unchanged) and `{id, label?, device?}` objects;
          `GET /policy/client-ids` returns objects (`id`, `label`, `device`); strings read as
          `{id}`.
    - [ ] `POST` accepts `label`/`device`; new `PUT /policy/client-ids/{id}` updates label/device
          without changing the id; unknown id → `control_api.not_found`; duplicate label →
          validation error; label length and charset capped.
    - [ ] Listener admission still sees plain ids; an old snapshot with strings round-trips and rolls
          back unchanged.
  - Verification: `cargo test -p dnscraft-api --locked` (new tests: object/string mix, PUT, duplicate
    label, rollback of an old snapshot), clippy/fmt clean; `docs/API-REFERENCE.md` and
    `SPEC-control-api.md` updated.
  - Dependencies: D2. Files: `crates/dnscraft-api/src/api/policy_routes.rs`, `api/router.rs`,
    config validation in `crates/dnscraft-api/src/config_apply.rs`, `crates/dnscraft-policy` registry
    accessor, `tests/policy_records_http.rs`, docs. Scope: M.

- [x] **T2** Query log shows the Client-ID label for public queries
  - Acceptance:
    - [ ] A query that carries a registered Client ID and has no directory match gets
          `client_name = label` in the log record and in `GET /query-log`.
    - [ ] A directory match by IP still wins; no label → unchanged behaviour.
    - [ ] Filtering `client_name_substr` finds the label.
  - Verification: `cargo test -p dnscraft-api -p dnscraft-policy --locked` with a test per precedence
    case; mock updated so the UI shows labels on DoH queries.
  - Dependencies: T1. Files: `crates/dnscraft-policy` (decision/registry), `crates/dnscraft-api/src/
    query_log.rs`, tests. Scope: M.

- [x] **T3** DoH-Clients page: named cards, device link, copy URL
  - Acceptance:
    - [ ] Header button "Client-ID registrieren" (label + optional device); cards show label, id
          (mono, secondary), DoH URL with a copy button, linked device (link to *Geräte*) or
          "Kein Gerät verknüpft".
    - [ ] Edit sheet (`centeredOnWide`, sticky footer) to change label/device; quiet "Löschen" with
          inline confirmation; viewers read-only; empty state explains what a Client ID is.
    - [ ] The jargon footnote about zones/Source-IP is replaced by one plain sentence that matches
          D1; hostile label/id strings use `displayText`.
    - [ ] Mock has 6+ Client IDs with labels, some linked to directory devices.
  - Verification: vitest (page tests: list, create, edit, delete confirm, viewer, empty), svelte-check,
    eslint, mock tests; browser check desktop/mobile/dark.
  - Dependencies: T1. Files: `web/src/routes/doh-clients/+page.svelte`, `web/src/lib/api/policy.ts`,
    `web/messages/{de,en}.json` (targeted edits), `web/mock/*`, tests. Scope: M.

- [x] **T4** Apple `.mobileconfig` download and Android hostname (client-side)
  - Acceptance:
    - [ ] Pure function builds a valid `com.apple.dnsSettings.managed` plist (DNS over HTTPS, `ServerURL
          = https://<public_domain>/dns-query/<id>`), deterministic payload UUIDs, XML-escaped and
          length-capped label, optional on-demand rule for a home-Wi-Fi SSID.
    - [ ] Card action "Apple-Profil laden" downloads `<label>.mobileconfig` (Blob, no server call);
          "Android: Privates DNS" shows/copies `<id>.dns.<public_domain>`.
    - [ ] Warning banner when `tls.mode` is `self_signed` or no public domain is set (iOS will refuse).
  - Verification: unit tests (golden plist, escaping of `<`, `&`, RTL, 150-char label, missing
    domain), page test for download action, browser check; manual install on a real iPhone (owner)
    at Checkpoint A.
  - Dependencies: T3. Files: `web/src/lib/doh/mobileconfig.ts` (+ test), `web/src/routes/doh-clients/
    +page.svelte`, messages, SPEC note. Scope: M.

- [x] **T4b** "DoH überall" setup check on the DoH-Clients page
  - Acceptance:
    - [ ] Checklist (read-only, from config/status): public domain set, certificate trusted (not
          self-signed), DoH listener reachable, and a `dns.<public_domain>` record with a home-range
          override exists (button "Datensatz anlegen" creates it via the existing records API, admin).
    - [ ] Per Client ID: "zuletzt gesehen" time, protocol and **how the last query was assigned**
          (Netzbereich name or "Standard"/"Client-ID") from the latest query-log record; warns when a
          home device was assigned to the default range (source IP not preserved).
    - [ ] SSID rule in T4 stays optional and off by default.
  - Verification: page tests with mock records (matched, unmatched, never seen), browser check;
    owner test on the real network at Checkpoint A. Dependencies: T3, T4 (T2 for labels).
    Files: `web/src/routes/doh-clients/+page.svelte`, `web/src/lib/api/policy.ts` (records), messages,
    mock. Scope: M.

- [x] **T5** Specs and docs
  - Acceptance:
    - [ ] `SPEC.md` (Client ID row), `SPEC-web-ui.md` (`/doh-clients` row, resolved open questions),
          `SPEC-control-api.md`, `SPEC-listeners.md` stale reference fixed, `tasks/todo-webui-*` items
          ticked.
  - Verification: grep for the old wording; links resolve. Dependencies: T1–T4. Scope: S.

### Checkpoint A: after T1–T5 (incl. T4b)
- [ ] All Rust and web tests pass, build and mock start clean
- [ ] On a real iPhone: install the profile, query resolves via DoH, the log shows the label
- [ ] Old snapshot/rollback and cluster write relay still work with string entries
- [ ] Owner reviews the pages (desktop, mobile, dark)

## Phase 2: Client ID is the fallback Netzbereich for unrecognised IPs

- [x] **T6** Spec change: selection order subnet → Client-ID pin → default
  - Acceptance: `SPEC-policy.md` selection section, review log entry (narrows #13: a pin never beats a matching subnet), `SPEC-listeners`
    and `SPEC-clients` cross references; node-validity rule for pins stated (pin to a view not valid
    on this node falls back to subnet/default).
  - Verification: owner approval recorded. Dependencies: D1. Scope: S.

- [x] **T7** Policy: an admitted Client ID with a pin replaces the default view
  - Acceptance:
    - [ ] `PolicyConfig` carries `client_pins` (Client ID → view id); snapshot validation rejects
          unknown views and pins to views not valid on every node where they matter as specified.
    - [ ] `select` returns the subnet match first, then `SelectionCause::ClientId` (pin), then the
          default; decision record and query log expose the cause.
    - [ ] Pinned id only applies when the request really carries an admitted Client ID.
  - Verification: `cargo test -p dnscraft-policy --locked` (precedence matrix incl. "subnet beats pin", node validity,
    unknown view), clippy/fmt. Dependencies: T6. Files: `crates/dnscraft-policy/src/{config,select,snapshot,
    decision}.rs`, tests. Scope: M.

- [x] **T8** API field `view` on a Client ID
  - Acceptance: `POST/PUT /policy/client-ids` accept `view` (existing view id), validation error for
    unknown/removed views, deleting a view with pins is rejected with a clear code, docs updated.
  - Verification: `cargo test -p dnscraft-api --locked`. Dependencies: T1, T7. Scope: S–M.

- [x] **T9** UI: choose the Netzbereich for a Client ID
  - Acceptance: editor select "Netzbereich (optional)"; card shows the pinned range; Netzbereiche
    cards list pinned Client IDs; query detail shows "Zugeordnet über: Client-ID"; mock data covers
    pinned and unpinned IDs; wording says "gilt, wenn die IP keinem Netzbereich zugeordnet ist";
    the Netzbereiche/Namen screens let the owner create an "Unterwegs" range with the home profile
    and override single records for it (verify the existing override UI is enough, else add it).
  - Verification: vitest, svelte-check, eslint, mock tests, browser check desktop/mobile/dark.
  - Dependencies: T3, T8. Files: `web/src/routes/doh-clients/+page.svelte`,
    `web/src/routes/zones/+page.svelte`, `web/src/routes/query-log/[id]/+page.svelte`, messages, mock.
    Scope: M.

### Checkpoint B: after T6–T9
- [ ] All tests pass; selection precedence covered end to end (mock + Rust)
- [ ] iPhone on mobile data gets its pinned Netzbereich (home profile, `nas.lan` override) and at
      home still the LAN range (real-device check by owner)
- [ ] Owner review before merge

## Deferred (not planned now)
- Signed `.mobileconfig`, QR code, Android intent links, rotating a Client ID while keeping its label.
