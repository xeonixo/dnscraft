import { test, expect, runAxe } from './fixtures';

test.describe('admin smoke', () => {
	test('local login reaches the dashboard', async ({ page }) => {
		await page.goto('/login');
		await page.getByLabel(/username|benutzername/i).fill('admin');
		await page.getByLabel(/password|passwort/i).fill('any');
		await page
			.locator('form')
			.getByRole('button', { name: /sign in|anmelden/i })
			.click();
		await expect(page).toHaveURL(/\/dashboard/);
		await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
	});

	test('query-log filters sync to the URL', async ({ page }) => {
		await page.goto('/login');
		await page.getByLabel(/username|benutzername/i).fill('admin');
		await page.getByLabel(/password|passwort/i).fill('any');
		await page
			.locator('form')
			.getByRole('button', { name: /sign in|anmelden/i })
			.click();
		await page.goto('/query-log');
		// Quick search box (not the filter sheet) writes domain_substr after debounce.
		const domain = page.getByRole('searchbox', { name: /search domains|domains durchsuchen/i });
		await domain.fill('example');
		await expect(page).toHaveURL(/domain_substr=example/, { timeout: 5_000 });
	});

	test('axe on login and dashboard', async ({ page }) => {
		await page.goto('/login');
		await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
		await runAxe(page);
		await page.getByLabel(/username|benutzername/i).fill('admin');
		await page.getByLabel(/password|passwort/i).fill('any');
		await page
			.locator('form')
			.getByRole('button', { name: /sign in|anmelden/i })
			.click();
		await expect(page).toHaveURL(/\/dashboard/);
		await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
		await runAxe(page);
	});
});

test.describe('viewer smoke', () => {
	test.use({ baseURL: 'http://127.0.0.1:4174' });

	test('hides admin token controls on settings', async ({ page }) => {
		await page.goto('/login');
		await page.getByLabel(/username|benutzername/i).fill('viewer');
		await page.getByLabel(/password|passwort/i).fill('any');
		await page
			.locator('form')
			.getByRole('button', { name: /sign in|anmelden/i })
			.click();
		await page.goto('/settings');
		await expect(page.getByRole('button', { name: /create token|token erstellen/i })).toHaveCount(
			0,
		);
	});
});

test.describe('locale de', () => {
	test('shows German login chrome', async ({ page }) => {
		await page.addInitScript(() => {
			globalThis.localStorage.setItem('dnscraft_locale', 'de');
		});
		await page.goto('/login');
		await expect(page.getByRole('heading', { level: 1 })).toContainText('Anmelden');
	});
});
