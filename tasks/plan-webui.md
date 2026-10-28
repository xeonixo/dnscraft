# Plan: web-ui build (W1–W10)

> Spec: [SPEC-web-ui.md](../SPEC-web-ui.md) · Design reference: `docs/design/web-ui-prototype.html`
> Rules: Apple design language (no emoji, no pills, no purple/gradients, semantic tokens only, rem units,
> 44pt targets), every string via Paraglide, no `{@html}` with API data. One commit per task.
> Implementation by Haiku agents, reviewed by Claude. Dependencies limited to those marked "Decided" in
> SPEC-web-ui § Candidate dependencies; "Proposed" ones need owner sign-off first.

| ID | Task | Depends | Acceptance (all runnable via `pnpm`) |
|---|---|---|---|
| W1 | Scaffold `web/`: SvelteKit 2 + adapter-static (`ssr=false`, `fallback: index.html`), TS strict, vitest, ESLint/Prettier, pnpm lockfile; `tokens.css` (light/dark/contrast, motion, spacing, radius) + token test | – | `check`, `lint`, `test`, `build` green; token test: all spec tokens defined in 3 modes, contrast >= 4.5:1 for label pairs |
| W2 | Paraglide i18n `en`/`de`, catalog-coverage test, raw-literal lint, locale switcher store | W1 | missing de key fails test; literal in component fails lint |
| W3 | App shell: sidebar (4 sections + Einstellungen), toolbar, compact drawer, theme switch; primitives GroupedList, Switch, Segmented, Sheet, StatTile | W2 | component tests: 44px targets, focus trap, aria state |
| W4 | API client: envelope, error-code map, CSRF retry-once, 401 redirect, `auth/me`, role guards; Login page | W3 | unit tests per SPEC § Testing 1 |
| W5 | Dashboard + Statistics | W4 | fixture-driven component tests |
| W6 | Query log + detail ("why blocked?") + exports | W4 | URL-backed filters |
| W7 | Config editor, versions, rollback | W4 | If-Match / 409 tests |
| W8 | Policy/Zonen/Namen/Profile/Test-Abfrage, Clients, Filter screens | W4 | |
| W9 | Listeners, TLS, Cluster, MCP rules, Tokens, Audit, Settings | W4 | |
| W10 | PWA, CSP/XSS corpus, Playwright e2e, rust-embed hand-off | W5–W9 | SPEC Success Criteria 1,13,21–23 |

Out of scope until owner decides: WX1–WX8, Alerts/Blocked-services backends (see `todo-webui-*`).
## Decisions (2026-10-28, delegated to Claude by owner: "technisch beste Wahl")

- Proposed deps approved: @testing-library/svelte, msw, lucide-svelte, @fontsource-variable/inter, @axe-core/playwright
  (plus Decided ones: vitest, playwright, paraglide, codemirror). Nothing else without asking.
- CSRF: token field in `GET /auth/me` + non-HttpOnly `dnscraft_csrf` cookie, header `X-CSRF-Token`.
- OIDC `return_to`: same-origin path only, validated server-side.
- Static assets served by `control-api` (same router/TLS; `/api/v1` 404 stays JSON). W10 rust-embed landed:
  STOP for owner human review of commits on main before release enablement.
- Missing backends (alerts, update check, backups, blocked services, WX1-WX8): placeholder "not available" states only.

Status: auto mode approved; W1–W10 done (web + rust-embed `web-ui` feature). Out of scope until owner decides: WX1–WX8 and missing backends (alerts/update/backups/blocked-services placeholders only).
