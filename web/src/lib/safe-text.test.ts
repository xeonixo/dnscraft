import { describe, expect, it } from 'vitest';
import { DISPLAY_LIMIT, FULL_LIMIT, REPLACEMENT, displayText, neutralize } from './safe-text';

describe('neutralize', () => {
	it.each([
		['NUL', 'bad\u0000name'],
		['newline', 'line\nbreak'],
		['tab', 'col\tumn'],
		['carriage return', 'a\rb'],
		['DEL', 'x\u007Fy'],
		['C1 control', 'x\u009By'],
	])('replaces %s with U+FFFD', (_name, input) => {
		const out = neutralize(input);
		expect(out).toContain(REPLACEMENT);
		expect(out).not.toMatch(/[\u0000-\u001F\u007F-\u009F]/u);
	});

	it.each([0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069])(
		'replaces bidi control U+%s',
		(code) => {
			const char = String.fromCodePoint(code);
			expect(neutralize(`evil${char}gnp.example`)).toBe(`evil${REPLACEMENT}gnp.example`);
		},
	);

	it('keeps ordinary Unicode, emoji and markup characters as they are', () => {
		expect(neutralize('bücher.example 🌐 <b>"x"</b>')).toBe('bücher.example 🌐 <b>"x"</b>');
	});
});

describe('displayText', () => {
	it('returns short values unchanged', () => {
		expect(displayText('ads.example.com')).toEqual({
			text: 'ads.example.com',
			full: 'ads.example.com',
			truncated: false,
		});
	});

	it('treats missing values as empty text', () => {
		expect(displayText(null).text).toBe('');
		expect(displayText(undefined).full).toBe('');
	});

	it('cuts overlong values by code points and marks them truncated', () => {
		const long = '€'.repeat(DISPLAY_LIMIT + 10);
		const shown = displayText(long);
		expect(shown.truncated).toBe(true);
		expect(shown.text).toBe(`${'€'.repeat(DISPLAY_LIMIT)}…`);
		expect(shown.full).toBe(long);
	});

	it('caps the expanded value at FULL_LIMIT', () => {
		const huge = 'a'.repeat(FULL_LIMIT + 50);
		const shown = displayText(huge);
		expect(shown.full.length).toBe(FULL_LIMIT);
		expect(shown.truncated).toBe(true);
	});

	it('neutralises before it measures, so the cut is on the visible text', () => {
		const shown = displayText('x\u0000'.repeat(3));
		expect(shown.text).toBe(`x${REPLACEMENT}x${REPLACEMENT}x${REPLACEMENT}`);
		expect(shown.truncated).toBe(false);
	});
});
