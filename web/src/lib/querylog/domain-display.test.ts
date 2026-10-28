import { describe, expect, it } from 'vitest';
import { decodePunycode, unicodeName } from './domain-display';

describe('punycode decoding (RFC 3492)', () => {
	it.each([
		['xn--bcher-kva', 'bücher'],
		['xn--mnchen-3ya', 'münchen'],
		['xn--80akhbyknj4f', 'испытание'],
	])('decodes %s', (ascii, unicode) => {
		expect(decodePunycode(ascii.slice(4))).toBe(unicode);
	});

	it('rejects malformed labels', () => {
		expect(() => decodePunycode('bcher-!')).toThrow();
		expect(() => decodePunycode('zzzzzzzz9')).toThrow();
	});
});

describe('unicodeName', () => {
	it('shows IDN labels in Unicode and keeps ASCII labels', () => {
		expect(unicodeName('xn--bcher-kva.example')).toBe('bücher.example');
		expect(unicodeName('www.xn--mnchen-3ya.de')).toBe('www.münchen.de');
	});

	it('leaves plain names and undecodable labels unchanged', () => {
		expect(unicodeName('www.example.com')).toBe('www.example.com');
		expect(unicodeName('xn--bcher-!.example')).toBe('xn--bcher-!.example');
	});
});
