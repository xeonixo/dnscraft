# DNScraft web UI

Client-side SvelteKit SPA (adapter-static, `index.html` fallback), built into `web/build` and embedded into the binary.

- `pnpm install --frozen-lockfile`: install dependencies (pnpm 10)
- `pnpm dev`: local dev server
- `pnpm check`: svelte-check and `tsc --noEmit`
- `pnpm lint`: ESLint and Prettier check
- `pnpm test`: Vitest (token contrast and no-literal-color scan)
- `pnpm build`: production build to `build/`
