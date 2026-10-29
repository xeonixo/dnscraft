import { describe, expect, it } from 'vitest';
import {
	isIpLiteral,
	isLanAddress,
	isValidClientId,
	labelTaken,
	nameHasHomeAddress,
	randomSuffix,
	slugOf,
	splitAddresses,
	suggestClientId,
} from './client-id';

describe('client id helpers', () => {
	it('suggests a slug with the suffix and spells umlauts out', () => {
		expect(suggestClientId('Gäste Handy', 'k7q2')).toBe('gaeste-handy-k7q2');
		expect(suggestClientId('  ', 'abcd')).toBe('client-abcd');
		expect(slugOf('--iPhone von Anna!--')).toBe('iphone-von-anna');
	});

	it('produces ids that pass the id pattern', () => {
		const id = suggestClientId('x'.repeat(200), 'z9z9');
		expect(isValidClientId(id)).toBe(true);
		expect(isValidClientId('Bad_ID')).toBe(false);
	});

	it('compares labels case-insensitively and ignores the own entry', () => {
		const entries = [
			{ id: 'a', label: 'MacBook Pro' },
			{ id: 'b', label: null },
		];
		expect(labelTaken('macbook pro', entries, 'b')).toBe(true);
		expect(labelTaken('macbook pro', entries, 'a')).toBe(false);
		expect(labelTaken('', entries, null)).toBe(false);
	});

	it('splits addresses by line and comma', () => {
		expect(splitAddresses('192.0.2.1, 192.0.2.2\n\n 2001:db8::1 ')).toEqual([
			'192.0.2.1',
			'192.0.2.2',
			'2001:db8::1',
		]);
	});

	it('recognises LAN addresses and rejects public ones', () => {
		expect(isLanAddress('192.168.1.20')).toBe(true);
		expect(isLanAddress('10.0.0.5')).toBe(true);
		expect(isLanAddress('172.20.1.1')).toBe(true);
		expect(isLanAddress('172.32.1.1')).toBe(false);
		expect(isLanAddress('fd00::1')).toBe(true);
		expect(isLanAddress('203.0.113.7')).toBe(false);
	});

	it('checks IP literals loosely', () => {
		expect(isIpLiteral('192.168.1.2')).toBe(true);
		expect(isIpLiteral('192.168.1.300')).toBe(false);
		expect(isIpLiteral('fd00::2')).toBe(true);
		expect(isIpLiteral('dns.example.test')).toBe(false);
	});
});

describe('randomSuffix', () => {
	it('is at least 12 chars of [a-z0-9], differs per call and yields a valid id', () => {
		const a = randomSuffix();
		expect(a).toMatch(/^[a-z0-9]{12,}$/);
		expect(randomSuffix()).not.toBe(a);
		expect(isValidClientId(suggestClientId('', a))).toBe(true);
		expect(isValidClientId(suggestClientId('x'.repeat(200), a))).toBe(true);
	});
});

describe('nameHasHomeAddress', () => {
	const rec = (name: string, type: string, rdata: string, overrides = {}) => ({
		name,
		type,
		rdata,
		overrides,
	});
	const homes = new Set(['lan']);

	it('accepts a direct A record', () => {
		expect(nameHasHomeAddress([rec('dns.x.de.', 'A', '192.168.1.5')], 'DNS.x.de', homes)).toBe(
			true,
		);
		expect(nameHasHomeAddress([rec('dns.x.de', 'A', '203.0.113.5')], 'dns.x.de', homes)).toBe(
			false,
		);
		expect(
			nameHasHomeAddress(
				[rec('dns.x.de', 'A', '203.0.113.5', { lan: '10.0.0.1' })],
				'dns.x.de',
				homes,
			),
		).toBe(true);
	});

	it('follows CNAME to an A record', () => {
		const rows = [
			rec('dns.x.de', 'CNAME', 'ns1.dns.x.de.'),
			rec('NS1.dns.x.de', 'A', '172.20.10.90'),
		];
		expect(nameHasHomeAddress(rows, 'dns.x.de', homes)).toBe(true);
	});

	it('survives a CNAME loop', () => {
		const rows = [rec('a.x.de', 'CNAME', 'b.x.de'), rec('b.x.de', 'CNAME', 'a.x.de')];
		expect(nameHasHomeAddress(rows, 'a.x.de', homes)).toBe(false);
	});

	it('warns when the CNAME target has no address', () => {
		expect(nameHasHomeAddress([rec('dns.x.de', 'CNAME', 'gone.x.de')], 'dns.x.de', homes)).toBe(
			false,
		);
	});
});
