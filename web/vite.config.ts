import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vitest/config';

export default defineConfig({
	plugins: [sveltekit()],
	test: {
		include: ['src/**/*.test.ts'],
		environment: 'node',
		// Vitest blanks CSS imports unless listed here; the token test reads the raw source of .css files.
		css: { include: [/\.css/] },
	},
});
