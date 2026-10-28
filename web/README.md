# DNScraft web UI

Client-side SvelteKit SPA (adapter-static, `index.html` fallback), built into `web/build` and embedded into the binary.

- `pnpm install --frozen-lockfile`: install dependencies (pnpm 10)
- `pnpm dev`: local dev server
- `pnpm check`: svelte-check and `tsc --noEmit`
- `pnpm lint`: ESLint and Prettier check
- `pnpm test`: Vitest (token contrast and no-literal-color scan, message catalog coverage, locale helpers, raw-literal scan)
- `pnpm build`: production build to `build/`

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
