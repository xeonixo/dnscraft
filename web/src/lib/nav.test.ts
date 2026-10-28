import { describe, expect, it } from 'vitest';
import { isActivePath, navItemForPath, settingsTabs } from './nav';

describe('Einstellungen routes', () => {
	it.each(['/settings', '/settings/config', '/settings/mcp', '/settings/api'])(
		'resolves %s to the Einstellungen nav item',
		(path) => {
			expect(navItemForPath(path)?.path).toBe('/settings');
		},
	);

	it('lists the four tabs in tab-bar order', () => {
		expect(settingsTabs.map((tab) => tab.path)).toEqual([
			'/settings',
			'/settings/config',
			'/settings/mcp',
			'/settings/api',
		]);
	});

	it('keeps the parent item active for sub-paths and only for them', () => {
		expect(isActivePath('/settings', '/settings/config')).toBe(true);
		expect(isActivePath('/settings', '/settings')).toBe(true);
		expect(isActivePath('/query-log', '/query-log/rec-0001')).toBe(true);
		expect(isActivePath('/settings', '/settingsx')).toBe(false);
		expect(isActivePath('/query-log', '/queries')).toBe(false);
	});
});
