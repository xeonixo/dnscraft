import { describe, expect, it } from 'vitest';
import { bestPrefix, findInvalidRange, ipMatches, parseCidr, parseRanges } from './cidr';

describe('parseCidr', () => {
	it.each([
		'192.0.2.0/24',
		'0.0.0.0/0',
		'255.255.255.255/32',
		' 192.0.2.128/25 ',
		'2001:db8::/64',
		'::/0',
		'::1/128',
		'1:2:3:4:5:6:7:8/128',
		'1:2:3:4:5:6:7::/112',
		'::ffff:192.0.2.1/128',
	])('accepts %s', (text) => {
		expect(parseCidr(text)).not.toBeNull();
	});

	it.each([
		'',
		'192.0.2.0',
		'192.0.2.0/33',
		'192.0.2/24',
		'256.0.0.1/32',
		'192.0.2.0/',
		'192.0.2.0/24/8',
		'abc/24',
		'2001:db8::/129',
		'2001:db8::1::2/64',
		'1:2:3:4:5:6:7:8:9/128',
		'1:2:3:4:5:6:7:8::/64',
		'fe80::1%eth0/64',
		'2001:db8:g::/48',
	])('rejects %s', (text) => {
		expect(parseCidr(text)).toBeNull();
	});
});

describe('ipMatches', () => {
	const ranges = parseRanges(['192.0.2.0/24', '2001:db8:10::/64']);

	it('matches IPv4 inside the prefix only', () => {
		expect(ipMatches('192.0.2.200', ranges)).toBe(true);
		expect(ipMatches('192.0.3.1', ranges)).toBe(false);
	});

	it('matches IPv6 inside a /64 and not outside it', () => {
		expect(ipMatches('2001:db8:10::1234', ranges)).toBe(true);
		expect(ipMatches('2001:db8:10:0:ffff:ffff:ffff:ffff', ranges)).toBe(true);
		expect(ipMatches('2001:db8:11::1', ranges)).toBe(false);
	});

	it('never matches across families', () => {
		expect(ipMatches('192.0.2.1', parseRanges(['::/0']))).toBe(false);
		expect(ipMatches('2001:db8::1', parseRanges(['0.0.0.0/0']))).toBe(false);
	});

	it('treats /0 as everything of its family', () => {
		expect(ipMatches('203.0.113.9', parseRanges(['0.0.0.0/0']))).toBe(true);
		expect(ipMatches('2001:db8::9', parseRanges(['::/0']))).toBe(true);
	});

	it('does not match an address that is not parseable', () => {
		expect(ipMatches('not-an-ip', ranges)).toBe(false);
		expect(ipMatches('', ranges)).toBe(false);
	});

	it('matches a compressed IPv6 address against its expanded range', () => {
		expect(ipMatches('::1', parseRanges(['0:0:0:0:0:0:0:0/120']))).toBe(true);
	});
});

describe('findInvalidRange', () => {
	it('accepts empty text and blank lines', () => {
		expect(findInvalidRange('')).toBeNull();
		expect(findInvalidRange('\n  \n')).toBeNull();
	});

	it('accepts a mixed valid list with spaces and CRLF', () => {
		expect(findInvalidRange(' 192.0.2.0/24 \r\n\r\n2001:db8::/64')).toBeNull();
	});

	it('reports the first bad line with its 1-based number', () => {
		expect(findInvalidRange('192.0.2.0/24\n\n192.0.2.1/33\n10.0.0.0/8')).toEqual({
			line: 3,
			text: '192.0.2.1/33',
		});
	});

	it('reports a line with no prefix', () => {
		expect(findInvalidRange('192.0.2.0')).toEqual({ line: 1, text: '192.0.2.0' });
	});
});

describe('bestPrefix', () => {
	it('returns the longest matching prefix, or -1 without a match', () => {
		const ranges = parseRanges(['192.0.2.0/24', '192.0.2.128/25', '2001:db8::/32']);
		expect(bestPrefix('192.0.2.200', ranges)).toBe(25);
		expect(bestPrefix('192.0.2.5', ranges)).toBe(24);
		expect(bestPrefix('2001:db8::1', ranges)).toBe(32);
		expect(bestPrefix('198.51.100.1', ranges)).toBe(-1);
		expect(bestPrefix('not an ip', ranges)).toBe(-1);
	});
});
