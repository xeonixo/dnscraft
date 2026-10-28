// @vitest-environment jsdom
import { get } from 'svelte/store';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { initTheme, resolveTheme, setTheme, theme, THEME_STORAGE_KEY } from './theme';

const root = () => document.documentElement;

beforeEach(() => {
	localStorage.clear();
	root().removeAttribute('data-theme');
});

afterEach(() => {
	vi.restoreAllMocks();
});

describe('theme store', () => {
	it('sets data-theme for light and dark and removes it for system', () => {
		setTheme('dark');
		expect(root().getAttribute('data-theme')).toBe('dark');
		expect(get(theme)).toBe('dark');

		setTheme('light');
		expect(root().getAttribute('data-theme')).toBe('light');

		setTheme('system');
		expect(root().hasAttribute('data-theme')).toBe(false);
		expect(get(theme)).toBe('system');
	});

	it('persists the choice under the dnscraft_theme key', () => {
		setTheme('dark');
		expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe('dark');
		expect(THEME_STORAGE_KEY).toBe('dnscraft_theme');
	});

	it('restores a stored choice on init and ignores unknown values', () => {
		localStorage.setItem(THEME_STORAGE_KEY, 'light');
		initTheme();
		expect(get(theme)).toBe('light');
		expect(root().getAttribute('data-theme')).toBe('light');

		localStorage.setItem(THEME_STORAGE_KEY, 'purple');
		initTheme();
		expect(get(theme)).toBe('system');
		expect(root().hasAttribute('data-theme')).toBe(false);
	});

	it('still applies the choice when localStorage throws', () => {
		vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
			throw new Error('storage denied');
		});
		vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
			throw new Error('storage denied');
		});

		expect(() => setTheme('dark')).not.toThrow();
		expect(root().getAttribute('data-theme')).toBe('dark');

		expect(() => initTheme()).not.toThrow();
		expect(get(theme)).toBe('system');
	});

	it('resolves the system choice through the color-scheme media query', () => {
		vi.stubGlobal(
			'matchMedia',
			vi.fn(() => ({ matches: true })),
		);
		expect(resolveTheme('system')).toBe('dark');
		expect(resolveTheme('light')).toBe('light');
		vi.unstubAllGlobals();
	});
});
