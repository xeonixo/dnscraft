# DNScraft web UI

Client-side SvelteKit SPA (adapter-static, `index.html` fallback), built into `web/build` and embedded into the binary.

- `pnpm install --frozen-lockfile`: install dependencies (pnpm 10)
- `pnpm dev`: local dev server
- `pnpm check`: svelte-check and `tsc --noEmit`
- `pnpm lint`: ESLint and Prettier check
- `pnpm test`: Vitest (token contrast and no-literal-color scan, message catalog coverage, locale helpers, raw-literal scan)
- `pnpm build`: production build to `build/` (generates PWA icons, then `build/sw.js` after the Vite build)
- `pnpm test:e2e`: Playwright smoke tests against the local mock (`pnpm build` first; uses installed Google Chrome via `channel: 'chrome'`)

## PWA

- `static/manifest.webmanifest`, root `sw.js` (generated into `build/` on `pnpm build`), and PNG icons under `static/icons/`.
- The service worker registers only in a secure context (`https://` or `http://localhost`). Self-signed bootstrap without a trusted root skips registration; the UI does not claim offline until registration succeeds.
- When the control-api cannot be reached, the shell shows `state_backend_unreachable`.

## Content-Security-Policy (production intent)

The mock server (`pnpm mock`) sends this policy on **HTML** responses so local dev matches production. `script-src` hashes are generated into `build/csp-script-hashes.json` on every `pnpm build` (theme bootstrap + the SvelteKit inline starter; the starter hash changes per build).

```
default-src 'self';
script-src 'self' 'sha256-…' 'sha256-…';
style-src 'self' 'unsafe-inline';
img-src 'self' data:;
connect-src 'self';
font-src 'self';
object-src 'none';
base-uri 'self';
frame-ancestors 'none';
form-action 'self';
```

- **`script-src` hashes:** every inline `<script>` in `build/index.html`. The theme bootstrap in `src/app.html` is stable (`sha256-+/UWW+kFTQfRcLtOTJw4BrviiPaL5UMxrjQpU8Pu7Mk=`); do not hard-code the SvelteKit starter hash.
- **`style-src 'unsafe-inline'`:** Svelte scoped component CSS is emitted as inline `<style>` blocks in the JS bundle; without a build-time nonce pipeline, `'unsafe-inline'` is required for those styles. Application logic still uses semantic tokens in `.css` files only.
- Also sent on HTML/static: `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`.
- Caching: `/_app/immutable/*` → `Cache-Control: public, max-age=31536000, immutable`; `index.html` and `/` → `no-cache`; `manifest.webmanifest` and `/sw.js` → `no-cache`.

## Internationalization

- Paraglide JS 2.26.0 (`@inlang/paraglide-js`), set up per the SvelteKit guide at paraglidejs.com/sveltekit
  and the Vite plugin guide (`paraglideVitePlugin` in `vite.config.ts`, `disableAsyncLocalStorage` because the app is SPA-only).
- Source locale `en`, shipped `de`. Messages live in `messages/en.json` and `messages/de.json` (flat snake_case keys).
- The inlang project is generated, not committed: `scripts/gen-inlang.mjs` writes `.generated/project.inlang/settings.json`
  and points `modules` at the pinned `@inlang/plugin-message-format@4.4.0` in `node_modules`. The SDK reads
  non-http module entries from disk, so nothing is fetched at build time. The script fails if the plugin is missing.
- Generated code goes to `src/lib/paraglide/` (git-ignored). `pnpm i18n` regenerates both; `check`, `lint`,
  `predev`, `prebuild` and `pretest` run the generator first.
- Not included: `@inlang/plugin-m-function-matcher`. Plural selectors would need it (and a locale-specific
  matcher) when the first plural message is added.
- Locale order: `localStorage` key `dnscraft_locale`, then browser languages, then `en`. No URL prefix.
  `src/lib/i18n/locale.ts` wraps `getLocale`/`setLocale` and maps control-api error codes to
  `error_*` message IDs (unknown codes fall back to `error_unknown`).
- Tests: `messages.test.ts` (key parity, placeholders), `locale.test.ts` (error mapping, storage
  failures), `no-literals.test.ts` (raw text and literal `aria-label`/`title`/`placeholder`/`alt` scan).

## Query log and local mock

- `/query-log` lists the query log: a domain search (debounced, `domain_substr`), every documented filter and
  paging parameter in the URL (`src/lib/querylog/filters.ts` maps URL, draft and API parameters), wide table or
  compact card list, density per viewer (localStorage, optional), pagination, and NDJSON/CSV export links that
  carry the current filters. `/query-log/:id` shows the decision steps, matching rule, client, timings, and for
  admins a temporary allow (`POST /api/v1/filtering/temporary-allows`).
- Untrusted values (domains, client names, rule text) go through `src/lib/safe-text.ts` and render as text only.
- `pnpm mock` starts a local fake control-api on `http://127.0.0.1:4173` (`MOCK_PORT`, `MOCK_ROLE=admin|viewer`,
  `MOCK_DROPPED=n` for the dropped-events notice). It serves `build/` with the SPA fallback and answers `/api/v1`
  from `mock/fixtures.mjs` (about 200 deterministic query-log rows, including hostile names). It binds loopback only
  and makes no outbound connections. Run `pnpm build` first. `pnpm test` also runs `mock/server.test.mjs`.
