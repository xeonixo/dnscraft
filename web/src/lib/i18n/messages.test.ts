import { describe, expect, it } from 'vitest';
import en from '../../../messages/en.json';
import de from '../../../messages/de.json';

const catalogs: Record<string, Record<string, string>> = { en, de };
const PLACEHOLDER = /\{([A-Za-z_][A-Za-z0-9_]*)\}/g;

const placeholdersOf = (value: string): string[] =>
	[...value.matchAll(PLACEHOLDER)].map((m) => m[1]).sort();

describe('message catalogs', () => {
	it('has the same keys in every locale (both directions)', () => {
		const enKeys = Object.keys(en).sort();
		expect(Object.keys(de).sort()).toEqual(enKeys);
	});

	it.each(Object.keys(catalogs))('has no empty values in %s', (locale) => {
		const empty = Object.entries(catalogs[locale])
			.filter(([, value]) => value.trim().length === 0)
			.map(([key]) => key);
		expect(empty).toEqual([]);
	});

	it.each(Object.keys(catalogs))('uses snake_case keys in %s', (locale) => {
		const bad = Object.keys(catalogs[locale]).filter((key) => !/^[a-z][a-z0-9_]*$/.test(key));
		expect(bad).toEqual([]);
	});

	it('keeps the placeholders of every key identical across locales', () => {
		for (const key of Object.keys(en)) {
			expect(placeholdersOf(de[key as keyof typeof de]), key).toEqual(
				placeholdersOf(en[key as keyof typeof en]),
			);
		}
	});
});
