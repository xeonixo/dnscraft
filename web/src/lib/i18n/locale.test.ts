import { afterEach, describe, expect, it, vi } from 'vitest';

const paraglide = vi.hoisted(() => ({
	setLocale: vi.fn(),
	getLocale: vi.fn(() => 'en'),
}));

vi.mock('$lib/paraglide/runtime', () => ({
	setLocale: paraglide.setLocale,
	getLocale: paraglide.getLocale,
	locales: ['en', 'de'],
}));

import { LOCALE_STORAGE_KEY, errorMessageKey, setLocale } from './locale';

const AUTH_CODES = [
	'control_api.auth.oidc',
	'control_api.auth.local',
	'control_api.auth.locked',
	'control_api.auth.session_expired',
	'control_api.auth.unauthenticated',
	'control_api.auth.csrf',
	'control_api.auth.insufficient_scope',
	'control_api.auth.unknown_token',
];

describe('errorMessageKey', () => {
	it.each(AUTH_CODES)('maps %s to its own message', (code) => {
		const key = errorMessageKey(code);
		expect(key).toBe('error_' + code.replace(/\./g, '_'));
		expect(key).not.toBe('error_unknown');
	});

	it('encodes non-alphanumerics as underscores', () => {
		expect(errorMessageKey('control_api.auth.locked')).toBe('error_control_api_auth_locked');
	});

	it('falls back to error_unknown for codes without a message', () => {
		expect(errorMessageKey('control_api.not_in_spec')).toBe('error_unknown');
		expect(errorMessageKey('filter_list.not_in_catalog')).toBe('error_unknown');
	});

	it('maps the server codes that have a message to their own key', () => {
		expect(errorMessageKey('filter_list.fetch_failed')).toBe('error_filter_list_fetch_failed');
		expect(errorMessageKey('control_api.internal')).toBe('error_control_api_internal');
		expect(errorMessageKey('control_api.rate_limited')).toBe('error_control_api_rate_limited');
	});

	it('never invents a key for prototype-like input', () => {
		expect(errorMessageKey('constructor')).toBe('error_unknown');
		expect(errorMessageKey('')).toBe('error_unknown');
	});
});

describe('setLocale', () => {
	afterEach(() => {
		vi.unstubAllGlobals();
		paraglide.setLocale.mockClear();
	});

	it('hands the choice to Paraglide, which stores it and reloads', () => {
		setLocale('de');

		expect(LOCALE_STORAGE_KEY).toBe('dnscraft_locale');
		expect(paraglide.setLocale).toHaveBeenCalledWith('de');
	});

	it('does not throw when Paraglide cannot store the choice', () => {
		paraglide.setLocale.mockImplementationOnce(() => {
			throw new DOMException('blocked', 'SecurityError');
		});

		expect(() => setLocale('de')).not.toThrow();
		expect(paraglide.setLocale).toHaveBeenCalledWith('de');
	});
});
