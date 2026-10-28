import { sveltekit } from '@sveltejs/kit/vite';
import { paraglideVitePlugin } from '@inlang/paraglide-js';
import { defineConfig } from 'vitest/config';

export default defineConfig({
	plugins: [
		// Compiles project.inlang and messages/*.json into src/lib/paraglide (git-ignored).
		// Locale order: stored choice (localStorage key dnscraft_locale), browser languages, base locale.
		// No URL locale prefix: the SPA has no locale routes.
		paraglideVitePlugin({
			project: './.generated/project.inlang',
			outdir: './src/lib/paraglide',
			strategy: ['localStorage', 'preferredLanguage', 'baseLocale'],
			localStorageKey: 'dnscraft_locale',
			isServer: 'import.meta.env.SSR',
			emitTsDeclarations: true,
			// SPA only (ssr=false): no AsyncLocalStorage, so no node:async_hooks in generated code.
			disableAsyncLocalStorage: true,
		}),
		sveltekit(),
	],
	test: {
		include: ['src/**/*.test.ts'],
		environment: 'node',
		// Vitest blanks CSS imports unless listed here; the token test reads the raw source of .css files.
		css: { include: [/\.css/] },
	},
});
