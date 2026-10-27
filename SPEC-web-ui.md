# Spec: web-ui

> Module id `web-ui` · directory `web/` · depends on: `control-api`
> Project-wide decisions: [SPEC.md](SPEC.md)
> Status: DRAFT

## Objective

Provide the human-facing surface of DNScraft: a fully internationalized TypeScript
single-page application that authenticates through the existing `control-api` OIDC or
break-glass login, renders the dashboard, configuration (including version diff and
rollback), the filterable query log with "why blocked?" details and exports,
statistics, clients, filter sets and lists, listeners, TLS status, MCP-managed rules,
API tokens and the audit log. The application is built once with `pnpm`, emitted as
static assets, embedded into the single Rust binary, and served from the internal
`control-api` listener. It owns all human-readable text; the API supplies only stable
locale-neutral codes and structured parameters.

### Scope

- One SvelteKit SPA (TypeScript `strict`) in `web/`, built with `pnpm` and
  `adapter-static`, embedded with `rust-embed`.
- Login via OIDC Authorization Code + PKCE (initiated through `control-api`) and the
  local break-glass login; cookie session; CSRF synchronization token on every
  mutating request.
- Viewer and admin role gating for every route, with the server as the authority and
  the UI degrading gracefully on `control_api.auth.insufficient_scope`.
- Screens: login, first-run wizard, dashboard/status, configuration (per-module and
  full-config editor, versions, rollback), query log (filters, pagination, single
  record "why blocked?", NDJSON/CSV export), statistics, clients, filter sets,
  filter lists, listeners, TLS, MCP rules/allows/pauses, API tokens, audit log, and
  settings (theme, locale).
- i18n through Paraglide JS with `en` and `de` shipped, zero missing keys, no raw
  literals.
- Static asset serving, security headers, and a documented self-signed-TLS bootstrap
  UX.

### Non-goals

- No new `/api/v1` endpoints. The UI consumes only the surface documented in
  [SPEC-control-api.md](SPEC-control-api.md). Missing capabilities are listed under
  Open questions / Required control-api additions, never invented.
- No server-side rendering and no Node.js runtime in production. `adapter-static`
  emits assets only; DNS resolution, configuration and auth stay in Rust.
- No separate web server, reverse proxy requirement, CDN or external font/analytics
  host.
- No browser-side OAuth tokens. The SPA never sees OIDC access/ID tokens or API
  bearer tokens (except the one-time plaintext display of a newly created token).
- Not an MCP client and not a general SQL/query console.
- Not implementing cluster write forwarding; the UI talks to whichever node it was
  loaded from and surfaces that node's API results.

## Architecture

### Build toolchain

- Framework: **SvelteKit** with `adapter-static` and `pnpm`, as fixed in
  [SPEC.md](SPEC.md) § Stack.
- `web/` layout: SvelteKit routes, `web/messages/{en,de}.json` message catalogs,
  shared API client and types under `web/src/lib/`.
- Commands (from [SPEC.md](SPEC.md) § Commands): `pnpm install --frozen-lockfile`,
  `pnpm check` (svelte-check + `tsc --noEmit`), `pnpm lint` (includes i18n checks),
  `pnpm test` (vitest), `pnpm build` → `web/build`.
- TypeScript `strict`; ESLint + Prettier; components PascalCase. API types are
  generated from the `control-api` OpenAPI schema, never hand-maintained
  ([SPEC.md](SPEC.md) § Code Style). The schema source is an open question (see
  Required control-api additions); until it exists, a checked-in generated types
  file is the only hand-off.
- Pin exact versions in `pnpm-lock.yaml`; exact versions are chosen at implementation
  start ([SPEC.md](SPEC.md) § Stack).

### SPA versus server-rendered

**Decision: client-side SPA.** The root layout disables SSR (`ssr = false`),
prerendering is off, and `adapter-static` uses `fallback: "index.html"`. Justification:

- The binary contains no JavaScript runtime; SSR would require a Node process and
  contradict the one-binary delivery model.
- Every screen is authenticated and data comes from `control-api`, so server-side
  rendering buys no SEO and adds a second rendering path to secure.
- A single `index.html` fallback makes deep links and refresh-safe routing trivial
  for a phone or bookmarked URL.

Consequences: the first paint is a small shell; the status dashboard loads its data
after `GET /api/v1/auth/me`. Loading, empty, permission and error states are explicit
component states, not server redirects.

### Embedding into the Rust binary

- **Mechanism: `rust-embed`** ([SPEC.md](SPEC.md) § Stack). The crate that owns the
  HTTP listener derives an asset table over `web/build`:

  ```rust
  #[derive(rust_embed::RustEmbed)]
  #[folder = "$CARGO_MANIFEST_DIR/../../web/build"]
  struct WebAssets;
  ```

- In release builds the assets are embedded and the binary is self-contained. In
  debug builds the same service may serve `web/build` from disk (or a
  `--web-dir` override) so frontend iteration does not require recompiling Rust.
- `cargo build` needs `web/build` to exist at compile time. CI and any release build
  must run `pnpm build` before `cargo build`, and a clean checkout must either
  provide an empty placeholder directory or make the frontend build a documented
  prerequisite. This ordering is a build-system requirement, not a runtime one.
- Build metadata: a short build hash/version is embedded into the bundle and shown in
  the footer; the authoritative version remains `GET /api/v1/status`.

### Serving the assets

The routing contract (owner of this layer is an open question; see below):

- `/api/v1/*`, `/mcp/v1`, `/healthz` and `/readyz` are handled by `control-api`
  exactly as specified. An unknown `/api/v1` path must keep returning the JSON error
  envelope, never the SPA HTML.
- Any other `GET`/`HEAD` path serves the exact embedded asset when it exists
  (hashed JS/CSS, icons, `manifest.webmanifest`, `sw.js`, `apple-touch-icon.png`,
  message files), otherwise
  `index.html` (SPA fallback). Path traversal is avoided by looking up a normalized
  path in the embedded table only; no filesystem path is joined from request input.
- Response headers: correct `Content-Type` from a fixed extension map (never sniffed),
  `X-Content-Type-Options: nosniff`, a strict `Content-Security-Policy`, and
  `Referrer-Policy: no-referrer`.
- Caching: content-hashed files under `/_app/immutable/` get
  `Cache-Control: public, max-age=31536000, immutable`; `index.html` and other
  non-hashed files get `no-cache` so a new binary's UI is picked up on the next load.
- Compression: pre-compressed Brotli/gzip assets emitted by the frontend build, or
  on-the-fly compression if the server stack already provides it. This stays inside
  the lightweight budgets in [SPEC.md](SPEC.md).
- `SPEC-control-api.md` § Non-goals currently states that `control-api` does **not**
  serve the web UI files. Giving `control-api` the fallback service therefore needs
  an explicit amendment to that spec; the alternative is that the `dnscraft` binary
  crate owns the fallback in front of the API router. Either way the path ownership
  above must hold. This is an open question, not an invented endpoint.

### Browser ↔ API interaction

- All calls are same-origin `fetch` with `credentials: "include"`; the session cookie
  is `HttpOnly` and never read by JavaScript.
- Requests use `Accept: application/json`; mutations use `Content-Type: application/json`
  and the CSRF header (see below).
- The SPA sends `If-Match` with the last observed `config_version` on config writes
  and handles `412` (`control_api.config.version` in the error table, named
  `control_api.config.conflict` in § Configuration model / Cluster hooks).
- Mutations that may be retried by the client send an `Idempotency-Key` (random UUID
  generated per user action, reused only for that retry).
- Refresh model: dashboard/status poll on a modest interval, back off when the tab is
  hidden or the last request failed; no WebSocket in v1. Server-sent events are only
  used if the live query-log tail is approved (see Open questions).
- On any `401` the SPA clears in-memory state, remembers the current route
  client-side, and redirects to `/login`; it does not display the stale page.

## Visual design language (Apple)

The interface follows Apple's Human Interface Guidelines as far as they sensibly apply
to a browser application. The four principles are normative: **Clarity** (text is legible
at every size, controls are unambiguous), **Deference** (chrome recedes so content and
data lead), **Depth** (layers and materials communicate hierarchy, used sparingly), and
**Consistency** (the same component looks and behaves the same on every screen). The UI
does not compete with the content: no decorative gradients, no accent color used for
decoration, no dense toolbars.

### Forbidden design elements

These are explicitly excluded and must never appear in the interface, even as options:

- **No emoji.** Emoji are forbidden as UI icons, status indicators, empty states and
  decoration. Icons are line icons from the open set only (see Iconography).
- **No pills.** Fully-rounded, pill/capsule-shaped badges, chips, tags, buttons and
  input shells are forbidden as styling tokens. Use the continuous-corner rectilinear
  shapes above. (Apple's functional controls that happen to be capsule-shaped — the
  switch knob and the segmented-control thumb — are standard controls, not "pills".)
- **No purple, and no "AI" aesthetic.** The primary accent is `--system-blue`. Purple —
  including purple/blue gradients, "blurple", aurora/gradient blobs and the typical
  AI-product look — is forbidden. Gradients are never used for surfaces, borders or
  fills.

### Typography

- **System font stack first**, so Apple devices render SF Pro natively without
  redistribution:
  `-apple-system, BlinkMacSystemFont, "SF Pro Text", "SF Pro Display", "Segoe UI", Roboto, sans-serif`.
- SF Pro Text is the intended face below 20 px and SF Pro Display at 20 px and above.
  The split is a platform behavior and cannot be reliably reproduced through one CSS
  stack on non-Apple devices; the stack above is the contract.
- **SF Pro and SF Symbols are not licensed for third-party redistribution and are never
  bundled.** Bundle **Inter** (SIL OFL 1.1) as a self-hosted WOFF2 variable font as the
  visual fallback on non-Apple devices. No external font CDN. `font-display: swap`;
  preload the Latin subset only.
- **SF Mono** for code, IP addresses, domains, timestamps, UUIDs, token IDs and error
  codes:
  `ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace`.
  Labels around those values stay in the body font; only the value itself is
  monospaced.
- Sizes use `rem` (root 16 px = 1 rem), never `px`, so browser zoom and a Dynamic
  Type-style scale work: body `1rem`, secondary `0.875rem`, footnote `0.8125rem`,
  headline `1.0625rem`, title `1.375rem`, large title `2rem`. Line height 1.4–1.5.
- Weights: 400 regular, 500 medium, 600 semibold. No faux bold. Tabular numerals
  (`font-variant-numeric: tabular-nums`) in tables, stat tiles and timestamps.

### Color: semantic tokens only

Components use only CSS custom properties; no literal color value appears in a
component. Tokens are defined on `:root`, redefined under
`prefers-color-scheme: dark` and `prefers-contrast: more`, and overridable by the
in-app theme switch (`data-theme="light|dark|system"`). The values below are the
starting points; they are verified for contrast, not treated as immutable.

| Token | Light | Dark | Use |
|---|---|---|---|
| `--label` | `#000000` | `#FFFFFF` | Primary text |
| `--secondary-label` | `rgba(60,60,67,0.60)` | `rgba(235,235,245,0.60)` | Supporting text, metadata |
| `--tertiary-label` | `rgba(60,60,67,0.30)` | `rgba(235,235,245,0.30)` | Placeholders, disabled |
| `--separator` | `rgba(60,60,67,0.29)` | `rgba(84,84,88,0.65)` | Hairlines, dividers |
| `--system-background` | `#FFFFFF` | `#000000` | Base canvas |
| `--secondary-system-background` | `#F2F2F7` | `#1C1C1E` | Cards, raised content |
| `--tertiary-system-background` | `#FFFFFF` | `#2C2C2E` | Higher elevation |
| `--system-grouped-background` | `#F2F2F7` | `#000000` | Grouped-list base |
| `--secondary-system-grouped-background` | `#FFFFFF` | `#1C1C1E` | Grouped-list rows |
| `--system-blue` | `#007AFF` | `#0A84FF` | Primary action, links, focus |
| `--system-red` | `#FF3B30` | `#FF453A` | Destructive, errors |
| `--system-green` | `#34C759` | `#30D158` | Allowed, success |
| `--system-orange` | `#FF9500` | `#FF9F0A` | Warnings |
| `--system-yellow` | `#FFCC00` | `#FFD60A` | Attention (used rarely) |

- Increased contrast (`prefers-contrast: more`) makes labels opaque, strengthens
  separators and raises contrast targets; it is a separate token set, not an opacity
  tweak at the component level.
- **Never convey meaning by color alone.** Blocked/allowed, warning and error states
  always pair the semantic color with an icon, a text label or a shape. Color-blind
  and grayscale rendering must remain understandable.
- Dark mode is first-class and automatic. It is **not a simple inversion**: the base
  is darker and elevated surfaces get lighter (`#000` → `#1C1C1E` → `#2C2C2E`), while
  semantic hues shift to their dark variants.
- **Purple is forbidden.** The only accent is `--system-blue`; purple, purple/blue
  gradients and any "AI-product" gradient aesthetic never appear (see Forbidden design
  elements).
- `color-scheme: light dark` on the root; theme bootstrap avoids a flash of the wrong
  palette (a hashed inline script permitted by CSP, or a server-set class).

### Layout, spacing and shape

- Safe-area insets are respected (`viewport-fit=cover`; padding uses
  `env(safe-area-inset-*)`) for notched phones and home-indicator areas.
- Content margin 16 px (narrow) / 20 px (wide). Spacing follows an 8-pt grid with a
  4-pt baseline: `0.25rem`, `0.5rem`, `0.75rem`, `1rem`, `1.25rem`, `1.5rem`, `2rem`.
- **Minimum touch target 44×44 pt** (`2.75rem` at the 16 px root) for every
  interactive control, using padding or invisible hit areas where the visual is
  smaller.
- Continuous corner radius: controls ~`0.625rem`, cards ~`0.875rem`; nested corners
  reduce radius so curves remain visually concentric.
- Content max width ~64rem on wide screens; the main column does not stretch
  edge-to-edge.
- **Sidebar on wide screens** (macOS/iPad pattern): persistent navigation with the
  current section highlighted; on narrow screens it becomes a list/drawer opened from
  the toolbar. The content area is one column on phones.

### Materials and depth

- Subtle translucency (`backdrop-filter: saturate(180%) blur(20px)`) is used only for
  the navigation bar, sidebar and sheets, never for content cards or tables. It is
  sparing: one or two surfaces per screen.
- `prefers-reduced-transparency: reduce` replaces translucency with an opaque
  background token and removes the blur.
- Depth is expressed by layered surfaces and one restrained shadow for sheets and
  popovers; content itself stays flat. Modals dim the background and trap focus.

### Motion

- Motion is purposeful, brief and interruptible: `--duration-fast: 150ms`,
  `--duration-normal: 200ms`, `--duration-slow: 300ms`, with a spring-like ease
  (`cubic-bezier(0.2, 0.8, 0.2, 1)`). Use it for navigation transitions, sheet
  presentation and expand/collapse; never for decorative loops.
- Data updates cross-fade instead of sliding or growing, so numbers do not move under
  the pointer.
- `prefers-reduced-motion: reduce` removes transforms and parallax and uses an instant
  swap or a short cross-fade.

### Iconography

- Line icons with a consistent ~1.5 px stroke and hierarchical weight, 20–24 px.
- **Emoji are forbidden** (see Forbidden design elements): never as UI icons, status
  indicators, empty states or decoration.
- **SF Symbols are not redistributable and are never bundled.** Use an open icon set
  (recommend **Lucide**, ISC) matched to the 1.5 px stroke, or reviewed inline SVG
  paths owned by the project. The exact set is an open question.
- Icons never carry meaning alone: pair with a visible label or an accessible name.
  Decorative icons are `aria-hidden="true"`; self-host icons, never an icon CDN.

### Reusable component standards

- **Grouped list / inset grouped table:** query log and clients. Rows have a primary
  label (domain or client name in SF Mono/text), a secondary label, and a trailing
  status. On wide screens an inset grouped table; on narrow screens the same data
  becomes a card list. Section headers are sticky where useful.
- **Grouped form:** configuration screens. Section headers, a short footer explaining
  consequences, and one control per row. Booleans use a switch; enumerated choices use
  a segmented control; numeric limits use a stepper; long options use a picker.
  Destructive controls are `--system-red` and open a confirmation sheet.
- **Search field:** native `type="search"`, translated placeholder, clear button,
  debounced; it is not the only way to filter (filters remain explicit).
- **Toolbar:** title on the leading edge; the primary action is a filled
  `--system-blue` button; secondary and destructive actions live in an overflow menu.
- **Sheet / modal:** used for create/edit on narrow screens and for every destructive
  confirmation; focus is trapped, Escape closes, and focus returns to the trigger.
- **Stat tile:** dashboard and statistics. Large rounded numerals in tabular figures,
  a secondary label, and a semantic accent for blocked (`--system-red`) and allowed
  (`--system-green`), always with text/icon. A small inline SVG sparkline is optional.
- **Status row:** module status uses an icon plus label plus color (never color alone);
  a warning banner uses `--system-orange` with a symbol and translated text.
- **Data values:** domains, IPs, timestamps, UUIDs, token IDs and error codes render
  in SF Mono and are copyable where useful.

### Accessibility (normative)

- **VoiceOver parity:** native elements first (`button`, `a`, `input`, `select`), ARIA
  roles/names/values/states only where native semantics do not suffice; logical DOM and
  reading order; visible focus (a 2–3 px `--system-blue` ring); focus trapping in
  sheets and restoration on close; every action keyboard-operable; Escape closes
  overlays.
- Contrast: **4.5:1** for normal text, **3:1** for large text and UI components; verify
  both color schemes and increased-contrast mode. Never color alone.
- Touch targets at least 44×44 pt; text scales via `rem` and remains usable at 200 %
  zoom without horizontal scrolling on a phone.
- Live regions (`aria-live="polite"`) announce toasts and async result changes;
  field errors are associated with `aria-describedby`; document titles change on
  route navigation.
- Reduced motion and reduced transparency are honored by every animated or
  translucent surface, not only the shell.

## Authentication and authorization

### OIDC flow

The browser never performs the OIDC exchange itself and never receives tokens. It
starts the flow and `control-api` owns PKCE, state, nonce and the code exchange
([SPEC-control-api.md](SPEC-control-api.md) § Auth):

1. The login page calls `GET /api/v1/auth/oidc/authorize-url`.
2. The SPA navigates to the returned authorization URL.
3. The provider redirects to `GET /api/v1/auth/oidc/callback`; `control-api`
   validates state/nonce/PKCE/ID token, maps groups to `viewer` or `admin`, sets the
   session cookie and redirects back to the SPA.
4. The SPA loads `GET /api/v1/auth/me` and renders the route for that role.

PKCE is S256 and is generated and stored server-side; the SPA has no verifier and no
token storage. The return path (`return_to`) and the callback's success/error
redirect shape are not specified in `SPEC-control-api.md`; they are required
additions (see Open questions). The SPA must handle a callback error by showing a
translated `control_api.auth.oidc` message and offering a retry.

### Local break-glass login

- The login page offers a local login form when the operator has enabled it. It calls
  `POST /api/v1/auth/local/login` and, on success, the response sets the same cookie
  session.
- `control_api.auth.local` is shown as a generic "credentials rejected" message; the
  UI never indicates whether the username exists.
- `control_api.auth.locked` (HTTP 423) shows the lockout state with the configured
  window, and disables the form until the user retries or an operator intervenes.
- The page must not claim which methods are enabled unless the server tells it. There
  is no public auth-capabilities endpoint today; the UI either probes the OIDC
  authorize endpoint or always renders both options. This is an open question.

### Sessions, CSRF and logout

- Session cookie: opaque, `HttpOnly`, `SameSite=Lax`, `Secure` when TLS is active,
  set by `control-api`. Lifetime is not hardcoded in the SPA; the UI reacts to `401`
  and to `SESSION_EXPIRED`-style codes. (The control-api documents 12 h absolute /
  60 min idle in one place and 30 min / 24 h defaults in another; the UI must not
  depend on either number.)
- **CSRF: synchronizer token.** The server binds a random token to the session and
  exposes it to the SPA (header, `GET /api/v1/auth/me` field, or a non-HttpOnly
  cookie; the exact mechanism is a required addition). Every
  `POST`/`PUT`/`PATCH`/`DELETE` sends it as `X-CSRF-Token`.
  - On `403 control_api.auth.csrf`, the SPA refreshes the token and retries the
    request exactly once; if it fails again, it forces a re-login instead of looping.
  - `GET`/`HEAD`/`OPTIONS` do not require the token.
  - Bearer-token requests (scripts, MCP) are out of scope for the UI; the SPA never
    stores or sends bearer tokens.
- Logout calls `POST /api/v1/auth/logout` with the CSRF token, then clears all
  in-memory state and navigates to `/login`.
- The SPA never writes the session to `localStorage`/`sessionStorage`; only UI
  preferences (theme, locale, last query-log filters) may be stored there.

### Role gating

- `GET /api/v1/auth/me` returns the principal and role (`viewer` or `admin`). Route
  guards hide or disable write controls for `viewer`; the server remains the sole
  authority.
- A `viewer` sees read-only versions of configuration screens built from
  `GET /api/v1/config` and `GET /api/v1/status` where the per-module `GET` routes are
  admin-only in the endpoint table. No mutation control is rendered.
- `403 control_api.auth.insufficient_scope` is a translated permission notice with
  the required role and a link back, never a blank page or a retry loop.
- `403 control_api.auth.invalid_scope` cannot normally arise for a cookie session
  (it describes a bearer token on the wrong endpoint family); if it does, the UI
  treats it as forbidden and shows the code.
- Role changes take effect on the next `GET /api/v1/auth/me`; there is no live push.

### Auth outcome handling

| Code | HTTP | UI behavior |
|---|---|---|
| `control_api.auth.oidc` | 4xx/5xx | Login error screen, translated message, retry button; show the code for support |
| `control_api.auth.local` | 401 | Generic "credentials rejected"; keep the form usable |
| `control_api.auth.locked` | 423 | Lockout notice; disable submit; explain the retry window |
| `control_api.auth.session_expired` | 401 | Clear state, redirect to `/login`, restore route after login |
| `control_api.auth.unauthenticated` | 401 | Same as session expired |
| `control_api.auth.csrf` | 403 | Refresh token, retry once, then re-login |
| `control_api.auth.insufficient_scope` | 403 | Translated permission notice with the required role |
| `control_api.auth.unknown_token` | 404 | Token-list row error (already revoked/unknown); refresh the list |

## Screen / route inventory

Roles are the minimum required to use the screen meaningfully. "Read" means the
screen is visible to a `viewer` via `GET /api/v1/config` when the module-specific
`GET` route is admin-only in the endpoint table. Every mutation is admin-only, as
listed in [SPEC-control-api.md](SPEC-control-api.md) § Endpoint table.

| Route | Screen | Role | control-api endpoints | Notes (Apple pattern) |
|---|---|---|---|---|
| `/login` | Login | public | `GET /api/v1/auth/oidc/authorize-url`, `GET /api/v1/auth/oidc/callback` (browser redirect), `POST /api/v1/auth/local/login` | Centered grouped card on the grouped background; large title; OIDC as the filled primary button, break-glass in a grouped section; lockout is an inline status row |
| `/setup` | First-run wizard | public → admin | `POST /api/v1/auth/local/login`, `GET /api/v1/status`, `GET /readyz`, `GET /api/v1/config`, `PUT /api/v1/config` | Grouped form, one section per step; toolbar with Back/Continue; progress; local-admin provisioning is a gap (Open questions) |
| `/dashboard` | Dashboard / node status | viewer/admin | `GET /api/v1/status`, `GET /api/v1/stats/overview`, `GET /readyz` | Stat-tile row (blocked/allowed with semantic color plus text/icon), grouped module-status list, toolbar refresh; persistent self-signed warning banner |
| `/config` | Full config editor / import-export | read: viewer; write: admin | `GET /api/v1/config`, `PUT /api/v1/config` | Grouped form sections with explanatory footers; save in the toolbar; diff presented in a sheet; `If-Match` with `config_version`; secrets never returned |
| `/config/versions` | Config versions and rollback | list: viewer; rollback: admin | `GET /api/v1/config/versions`, `POST /api/v1/config/versions/{version}/rollback` | Inset grouped list; version rows with secondary metadata; rollback in a confirmation sheet |
| `/config/policy` | **Zonen** (selection scopes), **Namen** (local records with per-zone overrides), **Profile** (behavior), **Test-Abfrage** (decision preview) | read: viewer via config; write: admin | `GET /api/v1/policy/views`, `GET /api/v1/policy/views/{id}`, `PUT/POST /api/v1/policy/views/{id}`, `DELETE /api/v1/policy/views/{id}`, `GET /api/v1/policy/records`, `PUT/POST /api/v1/policy/records`, `GET/POST/PUT/DELETE /api/v1/policy/profiles/{id}`, `GET/POST/PUT/DELETE /api/v1/policy/pause`, `POST /api/v1/policy/test-query` | **Zonen** editor: create/delete zones + their Bereiche (subnet ranges), node validity, profile link — no records here. **Namen** editor: one global name space, each name shows its records with a **default value plus per-zone overrides** (e.g. `nas.lan` resolves differently in Gäste vs VPN); records A/AAAA/CNAME/TXT/SRV/MX/PTR, exact names only, CNAME exclusivity, TTL default 60 s. Selection is source-IP only (longest-prefix → default, DoH/DoT clients included); test-query renders the ordered decision steps without writing the log |
| `/query-log` | Query log | viewer/admin | `GET /api/v1/query-log`, `GET /api/v1/query-log/export.ndjson`, `GET /api/v1/query-log/export.csv` | Sidebar; search field plus filter sheet; inset grouped table on wide, card list on narrow; domain/client/ID in SF Mono; status as icon + color + text; pagination footer; export in the overflow menu |
| `/query-log/:id` | Query detail ("why blocked?") | viewer/admin | `GET /api/v1/query-log/{id}` | Grouped detail sections; ordered decision steps; rule and list in SF Mono; toolbar allow action |
| `/query-log` (action) | One-click temporary allow | admin | `POST /api/v1/filtering/temporary-allows` (MCP-phase endpoint) | Confirmation sheet with the domain, a subdomain switch and a duration segmented control; fall back to the guided rule builder if unavailable |
| `/statistics` | Statistics dashboard | viewer/admin | `GET /api/v1/stats/overview`, `GET /api/v1/stats/top_clients`, `GET /api/v1/stats/top_domains`, `GET /api/v1/stats/cache` | Stat-tile row, period segmented control, inset grouped tables, inline SVG sparklines; rolls up to one year |
| `/clients` | Clients / device directory | list: viewer/admin; edit: admin | `GET /api/v1/clients`, `GET/POST/PUT/DELETE /api/v1/clients/manual`, `POST /api/v1/clients/sync` | Search field; inset grouped table on wide, card list on narrow; source badge; IP/MAC in SF Mono; edit in a sheet; names are untrusted data |
| `/doh-clients` | Verified DoH/DoT clients (Client IDs) | read: viewer via config; write: admin | `GET /api/v1/policy/views` (reads client identity), `PUT/POST /api/v1/policy/views/{id}` | Inset grouped list grouped by the **source-IP derived** Zone (not the Client ID); create in a sheet with a generated Client ID and the DoH `/dns-query/<id>` + DoT `<id>.dns.<domain>` endpoints; unknown IDs are rejected by the listener; client ID and protocol are query-log facets |
| `/filter-sets` | Filter sets | read: viewer via config; write: admin | `GET/POST/PUT/DELETE /api/v1/filter-sets`, `GET /api/v1/config` | Grouped form plus a guided rule-builder sheet and a CodeMirror raw-editor sheet; never require hard-to-type characters |
| `/filter-lists` | Filter list URLs | read: viewer via config; write: admin | `GET/POST/PUT/DELETE /api/v1/filter-lists`, `GET /api/v1/config` | Inset grouped list with status rows; add in the toolbar; edit in a sheet; per-list effectiveness is a gap (no endpoint) |
| `/listeners` | DNS listeners | read: viewer via config/status; write: admin | `GET/POST/PUT/DELETE /api/v1/listeners`, `GET /api/v1/status`, `GET /api/v1/config` | Inset grouped list; switches per protocol; exposure warning banner; warn that public listeners expose only registered Client IDs |
| `/tls` | TLS / ACME / DynDNS | read: viewer via config/status; write: admin | `GET/POST/PUT/DELETE /api/v1/tls`, `GET /api/v1/status`, `GET /api/v1/config` | Grouped status section plus grouped form; fingerprint in SF Mono; warning banner; destructive changes confirmed in a sheet; never render private keys |
| `/mcp-rules` | MCP-managed rules, allows, pauses | read: viewer/admin; write: admin | `GET /api/v1/filtering/mcp-rules`, `DELETE /api/v1/filtering/custom-rules`, `POST /api/v1/filtering/pause`, `POST /api/v1/filtering/resume` | Segmented control for `kind` (rules / temporary allows / pauses); inset grouped list; expiry countdown; removal in a confirmation sheet; 404 degrades to "not available on this node" |
| `/tokens` | API tokens | admin | `GET/POST /api/v1/auth/tokens`, `DELETE /api/v1/auth/tokens/{id}` | Inset grouped list; create in a sheet; one-time plaintext callout with copy; revoke confirmation; scope labels; self-signed confirmation before MCP tokens |
| `/audit` | Audit log | admin (see Open questions) | `GET /api/v1/audit` | Search field plus inset grouped table; row detail sheet renders redacted before/after JSON in SF Mono; never secrets |
| `/settings` | Settings / account | viewer/admin | `GET /api/v1/auth/me`, `POST /api/v1/auth/logout`, client-side theme/locale storage | Grouped form; theme segmented control (light/dark/system); locale picker; privacy footers |
| `*` | Not found | any | none | Empty state with a back action; SPA fallback; unknown `/api/v1` paths stay JSON |

The MCP server switch and limits (`control_api.mcp.enabled`, `write_tools_enabled`,
durations, caps) are configuration, edited through `/config` (`GET/PUT
/api/v1/config`); they are not a separate API endpoint.

### Navigation (sidebar)

The persistent sidebar is a grouped source list — never a flat run of links. Eight
sections order the screens by concern, from operational ("what is happening") to
administrative ("who can change things"):

| Section | Screens |
|---|---|
| Übersicht | Dashboard |
| Aktivität | Anfragen, Statistik |
| Filterung | Filtersätze, Filterlisten, Regeln & Freigaben |
| DNS-Regelwerk | Zonen, Namen, Profile, Test-Abfrage |
| Netzwerk | Geräte, DoH-Clients, Listener, TLS |
| Cluster | Knoten |
| Integrationen | MCP, API-Explorer |
| System | System (Konto, Darstellung, Protokollierung, Konfiguration & Versionen, API-Tokens, Audit-Log) |

`/login` and `/setup` are public and appear outside the sidebar. The system-level
configuration is consolidated into a single **System** screen rather than split
across separate settings/config/tokens/audit entries; its sections are grouped
inset lists within one scrollable screen. Admin-only sections (`/tokens`,
`/audit`) are hidden — not merely disabled — for `viewer`, so the navigation never
offers a dead end. Section labels are translated small caps
with slight letter-spacing; each item is an icon plus a label following the SF
Symbols metaphor. The active item uses the accent tint, never a colored bar. On
compact width the sidebar collapses to a drawer opened from the toolbar,
preserving the same grouping. The prototype at `docs/design/web-ui-prototype.html`
is the reference for this structure.

### Responsive structure and screen patterns

Breakpoints: compact (`< 48rem`, phones), regular (`≥ 48rem`, tablets/small laptops)
and wide (`≥ 64rem`, desktop). The persistent sidebar appears from regular width and
collapses to a drawer/list opened from the toolbar below it. Every screen has one
toolbar (title leading, primary action trailing, overflow for destructive/secondary
actions) and one scrollable content region.

- **Dashboard and statistics** use stat tiles for the headline numbers and inset
  grouped lists/tables for the detail; blocked and allowed always carry a label and
  an icon in addition to the semantic color.
- **Query log and clients** use an inset grouped table at regular/wide width and the
  same data as a card list at compact width. Rows expose primary and secondary
  labels, with domains, IPs, MACs, timestamps and IDs in SF Mono. Filters live in a
  sheet on compact and inline beside the search field on wide; both map to the same
  URL state and filter parameters.
- **Configuration screens** are grouped forms with section headers and footers. A
  switch toggles booleans, a segmented control selects enums (protocol, theme,
  period), a stepper edits bounded numbers, and a sheet hosts create/edit. Destructive
  actions use `--system-red`, a confirming sheet and an explicit verb.
- **Detail screens** (query record, audit row, version diff) use grouped sections and
  present machine data in SF Mono inside a horizontally scrollable region on compact
  width; the page itself never scrolls horizontally.
- **Empty, loading and error states** use the same inset grouped surface, an icon and
  a translated message, so a failed screen does not look like a different product.
- **Tokens and temporary allows** show the one-time plaintext or the expiry in a
  prominent callout, with a copy action and an explicit "cannot be shown again"
  explanation.

### Cross-screen behaviors

- **Query log**: every documented filter maps 1:1 to a query parameter; the URL is
  the source of truth so a filtered view can be bookmarked and shared. Exact domain
  and `domain_substr` are distinct inputs. Pagination uses `limit`/`offset` and the
  `has_more`/`next_offset` response. Exports reuse the current filter parameters.
  The UI explains IP truncation (`none`, `last_octet`, `last_group`) and that log
  data may be incomplete if `control_api.query_log.dropped` is non-zero.
- **Why blocked**: the detail view renders `steps` in order, the matching rule and
  list, `answer_source`, DNSSEC status, forward zone, selection cause and timings.
  Domain, rule text, list ID and client display name are untrusted data (rendered as
  text, never HTML).
- **Configuration**: module pages use the module-specific routes for small edits;
  `/config` provides the atomic full-config replace and export/import. The UI must
  not omit `mcp_rules` inadvertently: an omitted field carries existing MCP rules
  over, and only an explicit empty array deletes them. A diff view makes both cases
  visible before saving.
- **Rollback**: show the target version, its timestamp/actor (if exposed by the
  version list) and that rollback is itself audited; require explicit confirmation.
- **Tokens**: the plaintext token is displayed once with a copy button and a warning
  that it cannot be retrieved again. While `tls_mode = self_signed`, an MCP-scope
  token creation requires an explicit confirmation carrying
  `control_api.tls.self_signed`.
- **Unavailable features**: endpoints introduced in the MCP phase may return
  `404 control_api.not_found` on a build without them. The route shows a translated
  "not available on this node" state instead of an error toast.

## Internationalization (i18n)

- **Every user-facing string is keyed and translated.** This includes navigation,
  headings, field labels, placeholders, help text, buttons, `aria-label`, `title`,
  validation messages, empty states, error text, chart legends, relative times and
  the language/theme switchers. No literal appears in a component.
- Paraglide JS is the i18n layer ([SPEC.md](SPEC.md) § Stack). Message catalogues
  live under `web/messages/` (`en.json`, `de.json`); the source locale is English.
  Adding a locale must require only a new message file, no code change.
- **The API never sends prose.** Error bodies carry `code` plus structured `params`
  ([SPEC-control-api.md](SPEC-control-api.md) § General rules). The UI renders all
  text and uses parameters only as data (interpolated or displayed escaped).
- **Error-code → message contract.** A checked-in list of stable codes (generated
  from the API error catalogue/OpenAPI schema) maps each code to a message ID:
  `error.<code>` in the catalogue, encoded as the Paraglide ID
  `error_<code with non-alphanumerics replaced by "_">` (for example
  `control_api.rate_limited` → `error_control_api_rate_limited`).
  - `params` are passed as message parameters and use ICU-style plural/number
    formatting.
  - An unknown code falls back to `error_unknown` with the raw code shown in a
    copyable detail line; it never invents a translation of the code.
  - Forwarded module codes are included too: `policy.*`, `clients.*`, `filtering.*`,
    `filter_name.*`, `filter_build.*`, `listeners.config.*`, `tls.config.*`,
    `mcp.*`, plus `control_api.*`.
  - A test fails if any code in the list lacks a key in any shipped locale, and a
    lint/CI check fails on raw user-facing literals or missing keys
    ([SPEC.md](SPEC.md) § i18n).
- **Locale selection**, in order ([SPEC.md](SPEC.md) § i18n): stored user preference
  → browser `Accept-Language` → `en`. Because `control-api` has no locale-preference
  endpoint today, the v1 SPA stores an explicit choice in a first-party
  `dnscraft_locale` cookie/localStorage (per browser, not per account) and offers a
  switcher on the login page. Server-side per-user persistence is an open question.
- **Formatting:** all dates, times, relative times, numbers, byte sizes and
  durations use `Intl.*` with the active locale; timestamps arrive as UTC RFC 3339
  and render in the viewer's time zone. No hand-rolled pluralisation or string
  concatenation.
- **Layout:** no fixed-width text containers; CSS logical properties so an RTL
  locale remains possible. German string lengths are part of visual testing.
- **Domains:** display IDNs in Unicode with the punycode form available (for example
  in the detail tooltip); control characters from untrusted data are shown as
  replacement glyphs, never interpreted.
- The `<html lang>` attribute tracks the active locale, and document titles are
  translated.

### Accessibility and Dynamic Type

Apple's accessibility expectations apply to the web app, not only to native screens:

- **Dynamic Type parity:** all text sizes are `rem`-based, and the layout reflows at
  200 % browser zoom or an enlarged default font size without clipping or horizontal
  page scroll. Text containers have no fixed height; they wrap. Data-dense tables
  scroll inside their own region instead of widening the page.
- **VoiceOver parity:** native elements first; accessible names for icon-only
  buttons; translated `aria-label`/`aria-describedby`; correct roles, values and
  states for switches, segmented controls, tabs and dialogs; logical reading order;
  visible focus and focus management in sheets.
- **Contrast:** 4.5:1 for normal text and 3:1 for large text and UI components in
  light, dark and increased-contrast modes. Never color alone; status is always
  icon + text + color.
- **Targets:** 44×44 pt minimum for every interactive element, including row actions,
  pagination and icon buttons.
- **Motion and transparency:** `prefers-reduced-motion` and
  `prefers-reduced-transparency` are honored in every component; an animation is
  never the only feedback for an action.
- **Machine versus human text:** `Intl` formats human-facing dates, numbers and
  plurals; domains, IPs, timestamps, UUIDs, token IDs and error codes stay in SF Mono
  and are not translated. Translation never alters the characters of a copied value.

## Error handling

### Envelope and state model

Every API response uses `{ "data": ... }` on success and
`{ "error": { "code": "area.reason", "params": { ... } } }` on failure. The API
client parses the envelope; a 2xx with an unparseable body is treated as
`control_api.internal` (a bug or a proxy response), not as success. A failed
`fetch` (no HTTP status) is an offline/network state with a retry action.

UI states per screen: `loading`, `ready`, `empty`, `invalid-input`, `permission`,
`not-ready`, `offline`, `error`. Each is a translated component state; a component
never renders a raw stack trace or a server message.

### Error-code mapping

| Code / status | UI state and action |
|---|---|
| `control_api.internal` (5xx) | Error panel: translated "server error", the code in a copyable line, retry button; never show internals |
| `control_api.rate_limited` (429) | Non-blocking banner, temporarily disable the submit control, back off exponentially; honor `Retry-After` if present, otherwise use a bounded default |
| `control_api.not_ready` (503) | Onboarding/starting state with a link to the status screen; retry when `/readyz` succeeds |
| `control_api.not_found` (404) | Empty/removed state (for example a query-log record outside retention); not a fatal error |
| `control_api.config.invalid` / `config.apply` / `config.version` | Form-level message with field association; `config.apply` lists the failing module code; offer rollback |
| `control_api.config.version` (412; `config.conflict` in § Configuration model) | Conflict dialog: reload the latest config version and show the diff before retrying |
| `control_api.config.unknown_version` | Rollback target gone; refresh the versions list |
| `control_api.query_log.invalid` | Inline filter error on the offending field, preserving the rest of the form |
| `control_api.query_log.read` / `query_log.export` | Inline error with retry; large exports fail without a partial-file download where possible |
| `control_api.payload_too_large` (413) | Explain the size limit; keep the form data so the user can trim it |
| `control_api.auth.csrf` | Silent token refresh and one retry, then login |
| `control_api.auth.*` | See the auth table above |
| `control_api.tls.self_signed` | Warning, not an error: persistent dashboard/config banner with `tls_mode` and fingerprint |
| Module codes (`policy.*`, `clients.*`, `filtering.*`, `listeners.config.*`, `tls.config.*`, `mcp.*`) | Same lookup via `error.<code>`; field association when the form knows the field, otherwise a screen-level message |

Unknown/missing codes use `error_unknown`; the raw code is still available for
support and copied into a bug report. `params` are always treated as untrusted data.

## Security considerations

### XSS and untrusted data

The UI renders strings that are attacker-influenced or assistant-influenced:

- domain names, client display names, rule text, list IDs and filter names from the
  query log and MCP rules;
- `reason` fields supplied through MCP/API writes;
- redacted `before`/`after` JSON in the audit log;
- UniFi/manual client names and local domains;
- TLS SANs and error parameters.

Rules:

- Svelte auto-escapes text; the UI renders these values in text nodes, `<code>` or
  table cells. **`{@html}` is forbidden for any API-derived value** (a lint rule
  should flag it; any reviewed static exception is a code comment).
- No markdown/HTML rendering of log or config content. A config diff is rendered as
  text lines with syntax highlighting, never as HTML built from the payload.
- Never construct a URL from untrusted data without validation; only allow
  same-origin paths and `https:` links, never `javascript:`/`data:` in `href`/`src`.
- Length caps and control-character neutralisation are applied server-side
  ([SPEC-mcp.md](SPEC-mcp.md) § Prompt-injection), but the UI still renders values as
  data and truncates visually.
- Content-Security-Policy: `default-src 'self'; script-src 'self'; style-src 'self';
  img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none';
  base-uri 'none'; form-action 'self'; frame-ancestors 'none'`. No third-party
  scripts, fonts or analytics. If a style binding requires inline styles, use a
  nonce or hash rather than weakening `style-src`.
- `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `Permissions-Policy` minimal. Consider Trusted Types once browser support is
  acceptable; it is not mandatory in v1.

### CSRF, sessions and secrets

- CSRF is the synchronizer-token pattern described above; `SameSite=Lax` is defence
  in depth, not a substitute. No state-changing operation is a plain `GET`.
- The session cookie is `HttpOnly`; JavaScript cannot read it. The only
  credential-like value in JS is the CSRF token, which is useless without the
  cookie. Do not persist the CSRF token across sessions.
- No secrets in the bundle: the OIDC client secret, UniFi API key, Cloudflare token,
  TLS private keys, token hashes and plaintext bearer tokens never reach the client.
  Configuration exports are already secret-free; the UI does not send secrets back.
  `VITE_*` variables are build metadata only; CI greps the built bundle and source
  maps for known secret patterns.
- No third-party origins means no data leakage to CDNs; all assets are self-hosted.
- Query-log filters can contain domain names and client IDs; URL-backed filter state
  therefore lands in browser history. The UI offers "clear filters" and does not put
  sensitive values in the title; an alternative session-only state is an open
  question.

### Self-signed TLS bootstrap UX

- On first start the API serves a self-signed certificate. The browser shows its own
  certificate interstitial; the UI cannot and must not try to bypass it. The setup
  documentation explains accepting the certificate once or installing the bootstrap
  certificate, and names the node hostname (`<node>.dns.example.com`) used in the
  certificate.
- After login, the dashboard and TLS screen show a persistent, translated warning
  while `tls_mode = self_signed`, including the SHA-256 fingerprint so the owner can
  verify/pin it, and a link to the TLS settings.
- Creating an `mcp:read`/`mcp:write` token while self-signed requires an explicit
  confirmation explaining that the MCP client pins the bootstrap certificate. The
  warning disappears automatically once `tls_mode = acme` (the SPA re-reads status).
- The UI never claims the connection is trusted; it reflects the server-reported
  mode.
- **PWA consequence:** the self-signed bootstrap is not a secure context (unless the
  owner installs the bootstrap certificate as a trusted root), so the service worker
  cannot register and offline caching is unavailable until the certificate is trusted.
  See "Progressive Web App (iOS)".

## Progressive Web App (iOS)

The web UI is installable as a home-screen app on iOS. On iOS "install" is always the
user's manual **Share → Add to Home Screen**; there is no `beforeinstallprompt` and no
silent install, so the UI must not depend on an install prompt. The PWA is the same
static build served above and needs no additional runtime or dependency: the manifest,
service worker and icons are hand-written static files emitted by the frontend build.

### Web App Manifest

- A `manifest.webmanifest` is embedded and served at `/manifest.webmanifest` with
  `Content-Type: application/manifest+json` and `Cache-Control: no-cache`.
- Required members: `name`, `short_name`, `start_url` (`"/"`), `scope` (`"/"`),
  `display: "standalone"`, `theme_color` and `background_color` (both from the
  semantic tokens), and `icons` — 192×192 and 512×512 PNG with `purpose: "any"`, plus
  a 512×512 `purpose: "maskable"` variant for Android.
- `id` is a stable value and must never change after install (a new `id` is a new app
  identity).

### apple-touch-icon and iOS meta

- `<link rel="apple-touch-icon" href="/apple-touch-icon.png">` — a **180×180 PNG with
  no transparency** (opaque and square; iOS does not round or mask the icon). Also
  place `apple-touch-icon.png` at the web root so iOS finds it even without the link.
- `<meta name="apple-mobile-web-app-capable" content="yes">`,
  `<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">`
  (the status bar overlays the content — the safe-area insets above cover this), and
  `<meta name="apple-mobile-web-app-title" content="DNScraft">`.

### Service worker and offline

- A `sw.js` is embedded and served at the **root** `/sw.js`, un-hashed and
  `Cache-Control: no-cache` (a service worker is scoped to its directory, so root
  scope requires root placement). It precaches the app shell — `index.html`, hashed
  `/_app/immutable/*` JS/CSS, fonts and icons — and serves it from Cache Storage while
  offline (network-first for navigations, cache-first for hashed assets).
- API data is **not** cached by default: query log, config and stats are live. Offline
  the UI shows the cached shell plus a translated "backend unreachable" state.
  Read-only screens may optionally use a short stale-while-revalidate for
  `GET /api/v1/status` and the current config snapshot.
- Update strategy: version the cache by build hash; `skipWaiting` + `clients.claim`
  are acceptable for an admin tool, otherwise show a "new version available" reload
  prompt.

### HTTPS and the self-signed bootstrap

A service worker requires a secure context (HTTPS with a certificate the device
trusts, or `localhost`). The self-signed bootstrap is not trusted unless the owner
installs the bootstrap certificate as a root, so until then the service worker cannot
register and offline caching is unavailable. The app still runs as a home-screen web
app (icon, title, standalone) — only the offline shell degrades. Once `tls_mode =
acme` (or the root is installed), the service worker registers and offline returns.
The setup documentation states this explicitly; the UI advertises offline only after
registration succeeds.

## Testing strategy

No internet access, no real OIDC provider, no real Cloudflare/UniFi/ACME endpoints
([SPEC.md](SPEC.md) § Testing Strategy). The frontend test pyramid:

1. **Unit tests (vitest):**
   - i18n key coverage: every key in `en` exists in `de` (and any shipped locale);
     no unused-key requirement in v1; raw-literal lint is part of `pnpm lint`.
   - Error-code mapping completeness: every code in the checked-in code list maps to
     an existing message key in every locale; unknown codes fall back to
     `error_unknown` and still expose the code.
   - API client: envelope parsing, 4xx/5xx mapping, CSRF retry-once behavior,
     `If-Match`/`Idempotency-Key` headers, 401 redirect signal, offline/network error.
   - Formatters and guards: `Intl` date/number formatting per locale, timezone
     rendering, role/route guard decisions, query-log filter ↔ URL mapping.
2. **Component tests (vitest + `@testing-library/svelte`):**
   - Render login, dashboard, query-log table, config diff, token creation and audit
     rows with fixture data.
   - Click/keyboard behavior for destructive confirmations; hidden admin controls for
     `viewer`.
   - XSS fixture corpus rendered as inert text: `<script>alert(1)</script>`,
     quote-breaking JSON, `\n`/`\t`/NUL characters, bidi overrides, overlong values.
     Assert no element is created from the payload and no `{@html}` path exists.
   - Error states: `internal`, `rate_limited`, `not_ready`, `insufficient_scope`,
     `csrf`, and a malformed envelope.
3. **End-to-end (Playwright against a mock control-api):**
   - A scripted mock server (or Playwright request routing) on `127.0.0.1` that
     implements the documented envelope and the subset of endpoints each test needs.
     It never contacts the internet; the harness aborts any non-localhost request.
   - OIDC login (mock authorize/callback redirects), local login and lockout, logout,
     session expiry redirect with route restoration.
   - Query-log filtering and pagination, why-blocked detail, NDJSON/CSV download,
     export error.
   - Config edit with `If-Match`, conflict, apply error, version rollback.
   - Role gating: viewer sees read-only screens and gets the permission state on a
     forced admin call; admin succeeds.
   - Self-signed warning and MCP-token confirmation; unavailable MCP-phase endpoint
     (404) degrades gracefully.
   - One smoke test per shipped locale (`en`, `de`) as required by
     [SPEC.md](SPEC.md); set locale, timezone and clock explicitly for determinism.
4. **Static checks:** `pnpm check` (svelte-check + `tsc`), ESLint/Prettier,
   i18n/literal lint. The Rust build that embeds `web/build` runs after `pnpm build`
   in CI; a clean-checkout build test catches a missing asset directory.
5. **Design-system and accessibility checks:**
   - Token unit test: components reference only semantic tokens (a lint/grep fails on
     literal colors), every token resolves in light, dark and increased-contrast
     modes, and text/background pairs meet 4.5:1 (3:1 for large text and UI
     components) in each mode.
   - Component tests assert 44×44 minimum targets, visible focus, focus trapping and
     restoration in sheets, switch/segmented-control ARIA state, translated accessible
     names and `aria-live` announcements.
   - Playwright runs with light and dark color schemes, `reducedMotion: reduce`,
     increased-contrast/forced-colors emulation where supported, and compact /
     regular / wide viewports. It asserts no horizontal page scroll at 200 % text
     zoom and that the sidebar becomes a drawer on compact width.
   - An axe smoke check (`@axe-core/playwright`) covers login, dashboard, query log and
     one configuration form in both color schemes. It is a proposed check, not a hard
     gate on every route.
6. **Visual snapshots (optional):** screenshots of a stat tile, a grouped form and a
   query-log row at compact and regular width in both schemes, reviewed when the
   design system changes; not a hard CI gate.
7. **PWA checks:** a Lighthouse PWA audit (installability, manifest validity,
   `apple-touch-icon` presence, `display: standalone`), a service-worker offline test
   (register, precache the app shell, serve it with the network blocked), and a
   manifest/apple-meta validation in the static checks.

## Candidate dependencies

The stack below is fixed by [SPEC.md](SPEC.md) § Stack. Exact versions are the
current stable release at implementation start and pinned in `pnpm-lock.yaml`; the
version bands here are indicative and **unverified** until the implementation plan
checks the registry and licences.

| Dependency | Version band | Licence | Purpose | Status |
|---|---|---|---|---|
| TypeScript | 5.x | Apache-2.0 | Language, `strict` | Decided in SPEC.md |
| SvelteKit | 2.x | MIT | App framework, routing | Decided in SPEC.md |
| `@sveltejs/adapter-static` | 3.x | MIT | Static SPA output with `index.html` fallback | Decided in SPEC.md |
| Vite | bundled with SvelteKit (6.x/7.x) | MIT | Build tool | Decided implicitly by SvelteKit |
| pnpm | 9.x/10.x | MIT | Package manager, frozen lockfile | Decided in SPEC.md |
| Paraglide JS (`@inlang/paraglide-js`) | 2.x | MIT | Compile-time, tree-shaken i18n | Decided in SPEC.md |
| `rust-embed` | 8.x | MIT | Embed `web/build` in the Rust binary | Decided in SPEC.md |
| Vitest | 3.x | MIT | Unit/component tests | Decided in SPEC.md |
| Playwright | 1.x | Apache-2.0 | E2E smoke tests per locale | Decided in SPEC.md |
| CodeMirror 6 | 6.x | MIT | Raw filter-rule editor with validation/highlighting | Decided in SPEC.md |
| ESLint + Prettier | current | MIT | Lint/format, including i18n literal checks | Decided in SPEC.md |
| `svelte-check` | current | MIT | Svelte/TypeScript diagnostics | Decided in SPEC.md (`pnpm check`) |
| `@testing-library/svelte` | 5.x | MIT | Component tests | Proposed |
| `msw` (Mock Service Worker) | 2.x | MIT | Mock control-api in unit/component tests | Proposed |
| `openapi-typescript` | 7.x | MIT | Generate API types from the OpenAPI schema | Proposed; blocked on the schema being published (Open questions) |
| Inter (`@fontsource-variable/inter`) | 5.x | SIL OFL 1.1 | Bundled/self-hosted WOFF2 fallback for non-Apple devices | Proposed |
| `lucide-svelte` | 0.x | ISC | Open line icon set matched to the ~1.5 px Apple stroke | Proposed; exact set is an open question |
| `@axe-core/playwright` | 4.x | MPL-2.0 | Accessibility smoke checks in E2E | Proposed |

**Font and symbol licensing:** SF Pro and SF Symbols are **not** licensed for
third-party redistribution and are never bundled, copied or extracted. Apple devices
render SF Pro through the system stack; non-Apple devices use the bundled Inter
fallback. Icons come from an open set (Lucide recommended) or project-owned inline
SVG, never from SF Symbols.

Deliberately not included:

- No charting library in v1: statistics use tables plus small inline SVG built from
  the API numbers. Add a chart library only if the owner requires interactive charts
  (open question).
- No date library: `Intl.*` covers dates, relative times and numbers.
- No state-management library: Svelte stores and route-local state are sufficient.
- No CSS framework: Svelte scoped styles and a small design-token file.
- No analytics, icon CDN, external font CDN or UI component kit. Inter, the icon set
  and all assets are self-hosted; SF Pro and SF Symbols are never redistributed.
- No UI kit or component library: the Apple-like primitives are small, owned
  components built on the token file (grouped list, grouped form row, stat tile,
  sheet, toolbar, switch, segmented control).

## Success Criteria

1. `pnpm install --frozen-lockfile && pnpm check && pnpm lint && pnpm test &&
   pnpm build` succeeds; the resulting `web/build` is embedded with `rust-embed`, and
   the release binary serves `/` plus deep links from `index.html` with no Node
   runtime and no external file dependency.
2. Unknown `/api/v1/*` paths still return the JSON error envelope; they are never
   answered with the SPA `index.html`. Static responses carry the documented MIME,
   cache and security headers; no path traversal is possible.
3. OIDC login completes through `GET /api/v1/auth/oidc/authorize-url` and the
   `control-api` callback with PKCE/state/nonce handled server-side; the SPA never
   receives or stores an OIDC or API token. Local break-glass login works, and
   `control_api.auth.locked` renders a lockout state.
4. Every mutating request from a cookie session carries `X-CSRF-Token`; a
   `control_api.auth.csrf` response is retried once and then forces re-login. No
   state-changing action is a plain `GET`.
5. Session expiry (`401`) clears state and redirects to login, restoring the original
   route after a successful login; the SPA hardcodes no session duration.
6. A `viewer` can read every read-only screen and cannot render or trigger any admin
   mutation; a forced admin call shows the translated
   `control_api.auth.insufficient_scope` permission state. An `admin` can perform
   every documented write.
7. Every user-facing string comes from the message catalogue; `en` and `de` have
   zero missing keys; raw-literal and missing-key checks fail the build. Dates,
   times, numbers and plurals use `Intl`/ICU with the active locale. Locale selection
   follows stored preference → `Accept-Language` → `en`.
8. Every error code produced by `control-api` and the forwarded module namespaces in
   the checked-in code list maps to a translated message; unknown codes fall back to
   `error_unknown` and still show the raw code.
9. The dashboard shows current status, module states, build version and, while
   `tls_mode = self_signed`, a persistent translated warning with the SHA-256
   fingerprint; MCP token creation while self-signed requires explicit confirmation.
10. The query log supports every documented filter, pagination, URL-backed state, the
    single-record "why blocked?" view with the full decision record, and both NDJSON
    and CSV export with the current filters. `control_api.query_log.invalid` is shown
    inline on the offending field.
11. Configuration screens use `GET /api/v1/config` and the module-specific routes;
    writes send `If-Match` and handle `412`; versions can be listed and rolled back
    with confirmation; secrets from the environment never appear in any response or
    UI field; omitting `mcp_rules` is visibly distinguished from an explicit empty
    array.
12. Statistics, clients, filter sets/lists, listeners, TLS, MCP rules, API tokens and
    audit log screens call only endpoints documented in `SPEC-control-api.md`; each
    route enforces its required role; an unavailable MCP-phase endpoint (404) shows a
    translated "not available on this node" state.
13. The XSS fixture corpus (domains, client names, rule text, audit JSON, MCP reasons
    with markup, quotes, control characters and bidi overrides) renders inert; no
    API-derived value reaches `{@html}`; the strict CSP is served with the app.
14. The built bundle and source maps contain no OIDC secret, API key, TLS private key,
    token hash or plaintext token; CI checks this, and no third-party origin is
    contacted by the shipped app.
15. Unit/component tests cover i18n coverage, error-code mapping, envelope parsing,
    CSRF retry, role guards and XSS fixtures; Playwright E2E runs against a mock
    `control-api` on `127.0.0.1` with one smoke test per shipped locale and no
    internet access.
16. **Design tokens:** components use only semantic CSS custom properties (a lint
    check fails on literal colors); light, dark and increased-contrast variants are
    defined; dark mode is a re-mapped palette, not an inversion; status meaning is
    always conveyed by icon/text as well as color.
17. **Typography:** the system stack renders SF Pro on Apple devices, the bundled
    Inter fallback renders on other platforms, and SF Mono is used for domains, IPs,
    timestamps, IDs and error codes. All text sizes are `rem`-based and the UI remains
    usable at 200 % zoom.
18. **Layout and motion:** 16/20 px content margins, an 8-pt spacing grid, 44×44 pt
    targets, continuous corner radii and safe-area insets are applied; the sidebar is
    persistent at regular width and a drawer at compact width; transitions are
    150–300 ms and interruptible; `prefers-reduced-motion` and
    `prefers-reduced-transparency` are honored.
19. **Accessibility:** VoiceOver-compatible semantics (names, roles, values, states,
    reading order), visible and managed focus, keyboard operability, 4.5:1/3:1
    contrast in all schemes, and translated accessible names. The proposed axe smoke
    checks pass on login, dashboard, query log and a configuration form.
20. Theme switching (light/dark/system) and a locale switch work on login and
    authenticated screens; layout remains usable on phone width and with German
    strings, using CSS logical properties.
21. **Installable (iOS):** a valid `manifest.webmanifest` (`display: standalone`,
    `theme_color`/`background_color` from the tokens, 192/512 icons including one
    maskable) is served with `application/manifest+json`; `apple-touch-icon`
    (180×180, opaque) and the `apple-mobile-web-app-*` meta tags are present; the app
    launches standalone from the home screen with the correct title and icon.
22. **Offline app shell:** the service worker registers at the root scope, precaches
    the built app shell, and serves it while offline; API data is not cached by
    default, and the UI shows a translated "backend unreachable" state.
23. **Trusted TLS:** the PWA works fully once the certificate is trusted (ACME or an
    installed root); with the self-signed bootstrap it still runs as a home-screen app
    but does not advertise offline, and the service worker fails registration
    gracefully.

## Open questions

1. **Who serves the static assets?** `SPEC-control-api.md` § Non-goals says
   `control-api` does not serve the web UI files; this spec's routing contract
   requires an SPA fallback beside the API. Choose: (a) amend `control-api` to own a
   fallback service (recommended: same router, same TLS, one binary), or (b) let the
   `dnscraft` binary crate compose the embedded asset service in front of the API
   router. Either way, `/api/v1` 404s must stay JSON. Recommendation: (a).
2. **CSRF token issuance.** Where does the SPA obtain the synchronizer token
   (response header, `GET /api/v1/auth/me` field, or non-HttpOnly cookie), and what
   are the cookie and header names? `SPEC-control-api.md` requires CSRF but does not
   define the contract. Recommendation: a token field in `auth/me` plus a
   non-HttpOnly `dnscraft_csrf` cookie, sent as `X-CSRF-Token`.
3. **OIDC return path and callback redirect.** `authorize-url`/`callback` have no
   documented `return_to` parameter or post-login redirect shape. The SPA needs to
   restore the route after login. Recommendation: accept a same-origin `return_to`
   and validate it server-side.
4. **OpenAPI schema source.** [SPEC.md](SPEC.md) requires generated API types, but
   `SPEC-control-api.md` publishes no OpenAPI document or endpoint. Decide whether
   the schema is a checked-in build artifact or a served document, and add it to the
   control-api spec. The error-code list needed for i18n coverage should come from
   the same source.
5. **Locale preference storage.** [SPEC.md](SPEC.md) says "user preference (stored
   per user) → `Accept-Language` → `en`", but there is no preference endpoint. For v1
   this spec proposes a browser-local cookie; a server-side per-user preference needs
   a control-api addition (for example in `auth/me` or the config). Which does the
   owner want?
6. **Audit log role.** The endpoint table marks `GET /api/v1/audit` as
   `viewer/admin`, while § Security considerations says `viewer` users cannot access
   the audit log. This spec assumes admin-only. Confirm and align the control-api
   spec; if viewers may read it, define what is redacted.
7. **Statistics query parameters.** The endpoint table does not document `from`,
   `to`, `profile_id` or a top-N `limit` for the stats routes (the MCP tool assumes
   them). Confirm the parameter names and default window (24 h) before implementing
   the period selector.
8. **Live query-log tail.** [SPEC.md](SPEC.md) lists a streaming tail (SSE) as a
   feature, but `SPEC-control-api.md` has no SSE endpoint. Decide whether v1 includes
   it; if yes, add an endpoint (for example `/api/v1/query-log/stream`) and define
   event shape, filtering, heartbeat and cookie-auth behavior. Recommendation: defer
   to v2; polling and export cover the v1 acceptance criteria.
9. **Filter-list effectiveness.** [SPEC.md](SPEC.md) requires per-list loaded rules,
   unique contribution and hits, but there is no control-api endpoint for it
   (`/filter-lists` is CRUD configuration only). Add a read endpoint or defer the
   screen section.
10. **First-run local admin provisioning.** The wizard is required, but the endpoint
    table has no create-local-account route; "local accounts" are listed as editable
    configuration with no route. Decide: bootstrap the first admin from TOML/env only,
    or add an admin-account endpoint / expose accounts through `PUT /api/v1/config`
    with a defined secret-handling rule.
11. **TLS actions.** `TlsEngine::renew_now` and `dyndns_now` exist in Rust, but there
    is no HTTP endpoint for "renew now" or "update DynDNS now". The v1 screen shows
    status and config only unless an endpoint is added.
12. **API-token list shape.** The `GET /api/v1/auth/tokens` response fields
    (`id`, `scope`, `created_at`, `expires_at`, `last_used`, label?) are not
    specified. Define the response so the token table does not guess; plaintext must
    never be returned again after creation.
13. **Module CRUD versus full-config PUT.** Both surfaces can change configuration.
    The recommendation here is: module pages use the module routes for small edits,
    `/config` provides atomic full-config replace, import/export and cross-module
    changes. Confirm this split, or designate one canonical write path.
14. **Session lifetime documentation.** The control-api documents 12 h absolute /
    60 min idle in one place and 30 min idle / 24 h absolute defaults in another. The
    UI is duration-agnostic, but the owner should settle the defaults before writing
    the setup docs.
15. **Charting.** This spec proposes no chart library (tables plus inline SVG) to stay
    within the lightweight budget. If interactive charts, zoom or richer period
    comparisons are required, choose a library in a separate dependency decision.
16. **Query-log filter state in the URL.** Domain and client filters in the URL end up
    in browser history. Confirm URL-backed filter state is acceptable, or use
    session-only state with explicit "copy link" behavior.
17. **Login method discovery.** There is no public endpoint that reports whether OIDC
    and local login are enabled. Decide whether the login page probes the OIDC
    endpoint, always shows both methods, or a small public auth-capabilities endpoint
    is added to control-api.
18. **Error-screen bug report.** [SPEC.md](SPEC.md) describes a bug-report flow with
    diagnostics (recent structured log lines). The UI can assemble version, locale,
    error codes and route client-side, but recent server log lines have no endpoint.
    Decide whether to add a diagnostics endpoint, omit logs, or defer the feature.

19. **Test-query screen.** [SPEC.md](SPEC.md) lists "What does client X get for
    name Y, and why?" as a web-UI feature. The backing `POST /api/v1/policy/test-query`
    is an MCP-phase endpoint in `SPEC-control-api.md` and needs the resolver's
    `no_cache_write` flag, which does not exist yet. Decide whether this screen ships
    with v1 (blocked on those prerequisites) or in the MCP phase; this spec leaves it
    out of the v1 inventory.
20. **Icon set choice.** Lucide is recommended (ISC, ~1.5 px stroke); confirm the set
    and whether selected/active states need a second weight or a filled variant.
    Alternatives are Phosphor, Heroicons or project-owned inline SVG. SF Symbols must
    not be bundled under any choice.
21. **Bundle Inter or rely on system fonts?** Bundling Inter adds a self-hosted WOFF2
    (Latin subset) to the binary and guarantees a consistent fallback on non-Apple
    devices; relying on system fonts is smaller but gives a different face on Linux
    and Windows. Apple devices resolve SF Pro first either way. The exact monospace
    fallback on Linux/Windows is also open (SF Mono cannot be bundled).
22. **Translucency on web.** `backdrop-filter` blur has GPU, battery and
    browser-support costs outside Apple platforms. Confirm sparing use (nav bar,
    sidebar, sheets) with a reduced-transparency fallback, or disable blur entirely on
    compact/low-power devices.
23. **SF Pro Text/Display split.** The size-based face switch is an Apple platform
    behavior; the web stack cannot reproduce it reliably on other devices, where Inter
    is one family. Accept the difference, or introduce two Inter optical sizes (not
    recommended).
24. **Data density versus 44 pt targets.** The query log and clients screen can be
    dense. Confirm the compact-width card list (instead of a 44 pt-row table) and the
    desktop row height; both must keep 44 pt hit targets for every row action.
25. **Theme persistence and scope.** The in-app theme switch is stored per browser
    (cookie/localStorage) in this spec. Confirm it stays a per-browser preference or
    becomes the same per-user preference as the locale; the latter needs a
    control-api addition.
26. **CodeMirror theming.** CodeMirror 6 ships its own themes; confirm it is restyled
    to the light/dark/increased-contrast tokens (including SF Mono) rather than
    shipping its default palette.
27. **Self-signed bootstrap and offline.** With `tls_mode = self_signed` the origin is
    not a secure context (unless the owner installs the bootstrap cert as a trusted
    root), so the service worker cannot register. Confirm the v1 behavior: ship
    offline only for ACME/installed-root deployments, or also document a
    certificate-install path so offline works before ACME.
28. **Web Push.** iOS 16.4+ supports Web Push only for home-screen apps, with
    permission only on a user gesture and every push must show a notification; it also
    needs a trusted cert. Decide whether v1 includes any push (cert-expiry/outage
    alerts) or defers it. Recommendation: defer to v2.

### Required control-api additions (not invented here)

These are capabilities the UI needs but that `SPEC-control-api.md` does not yet
define. They must be added to the control-api spec and approved before the
corresponding UI screen is implemented; nothing in this document assumes they exist.

- CSRF token issuance/contract (header, `auth/me` field or cookie) and the cookie
  name for the session.
- OIDC `return_to` support on `authorize-url`/`callback` and a documented callback
  error redirect.
- An OpenAPI schema artifact or endpoint, plus an authoritative error-code catalogue
  for the i18n coverage test.
- Documented statistics query parameters (`from`, `to`, `profile_id`, top-N `limit`)
  and their defaults.
- A filter-list effectiveness read endpoint (per-list rules/hits/unique
  contribution), or an owner decision to omit that UI section.
- An SSE live query-log endpoint, only if the live tail is kept in v1 (with event
  shape, filtering and heartbeat).
- `POST /api/v1/tls/renew` and `POST /api/v1/tls/dyndns` (or equivalent), only if the
  TLS screen offers those actions.
- A defined first-run/local-admin provisioning path (bootstrap-only or an endpoint).
- A locale-preference mechanism, only if per-user storage is chosen over the
  browser-local cookie.
- The documented `GET /api/v1/auth/tokens` response shape and scope labels.
- A public (or unauthenticated) way for the login page to learn which auth methods
  are enabled, if probing is not acceptable.
