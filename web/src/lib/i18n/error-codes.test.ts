import { describe, expect, it } from 'vitest';
import en from '../../../messages/en.json';
import de from '../../../messages/de.json';
import { ERROR_CODES } from '$lib/api/error-codes';
import { errorMessageKey } from './locale';

const catalogs: Record<string, Record<string, string>> = { en, de };

describe('error-code message coverage', () => {
	it('lists each code once', () => {
		expect(new Set(ERROR_CODES).size).toBe(ERROR_CODES.length);
	});

	it.each(ERROR_CODES)('maps %s to a message key in every locale', (code) => {
		const key = errorMessageKey(code);
		expect(key, code).not.toBe('error_unknown');
		for (const [locale, catalog] of Object.entries(catalogs)) {
			expect(catalog, `${locale} is missing ${key}`).toHaveProperty([key]);
		}
	});
});
