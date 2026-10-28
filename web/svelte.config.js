import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	preprocess: vitePreprocess(),
	kit: {
		// Client-side SPA: every route is served from index.html (see SPEC-web-ui.md, SPA decision).
		adapter: adapter({ fallback: 'index.html' }),
	},
};

export default config;
