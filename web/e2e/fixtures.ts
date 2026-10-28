import { test as base, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

export const test = base.extend({
	page: async ({ page }, use) => {
		await page.route('**/*', (route) => {
			const url = new URL(route.request().url());
			const host = url.hostname;
			if (host !== '127.0.0.1' && host !== 'localhost') {
				return route.abort('blockedbyclient');
			}
			return route.continue();
		});
		await use(page);
	},
});

export { expect };

export async function runAxe(page: import('@playwright/test').Page): Promise<void> {
	const results = await new AxeBuilder({ page }).analyze();
	expect(
		results.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical'),
	).toEqual([]);
}
