import { defineConfig, devices } from '@playwright/test';

const MOCK_PORT = process.env.MOCK_PORT ?? '4173';

export default defineConfig({
	testDir: 'e2e',
	fullyParallel: true,
	forbidOnly: !!process.env.CI,
	retries: process.env.CI ? 1 : 0,
	workers: process.env.CI ? 1 : undefined,
	reporter: [['list']],
	use: {
		...devices['Desktop Chrome'],
		// Prefer the installed Google Chrome so CI/local does not need
		// `playwright install chromium` (large download that often times out).
		channel: 'chrome',
		baseURL: `http://127.0.0.1:${MOCK_PORT}`,
		trace: 'on-first-retry',
	},
	webServer: [
		{
			// Use npm (always on PATH with Node); bare `pnpm` is often missing in spawned shells.
			command: 'npm run build && node mock/server.mjs',
			port: Number(MOCK_PORT),
			reuseExistingServer: !process.env.CI,
			timeout: 240_000,
		},
		{
			command: 'MOCK_PORT=4174 MOCK_ROLE=viewer node mock/server.mjs',
			port: 4174,
			reuseExistingServer: !process.env.CI,
			timeout: 240_000,
		},
	],
});
