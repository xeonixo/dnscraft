import { describe, expect, it } from 'vitest';
import {
	findMatchingRecord,
	isInventoryDnsName,
	normalizeDnsName,
	supportsProxied,
	zoneForName,
	type DomainZone,
	type DomainZoneRecord,
} from './domain-zones';

const zones: DomainZone[] = [
	{
		id: 'zone-example',
		name: 'example.test',
		status: 'active',
		name_servers: [],
		source: 'public_domain',
	},
	{
		id: 'zone-deep',
		name: 'dns.example.test',
		status: 'active',
		name_servers: [],
		source: 'dns_provider',
	},
];

describe('normalizeDnsName', () => {
	it('strips trailing dots and lowercases', () => {
		expect(normalizeDnsName('Nas.Example.Test.')).toBe('nas.example.test');
		expect(normalizeDnsName('  x.LAN  ')).toBe('x.lan');
	});
});

describe('zoneForName', () => {
	it('picks the longest covering apex', () => {
		expect(zoneForName(zones, 'ns1.dns.example.test.')?.id).toBe('zone-deep');
		expect(zoneForName(zones, 'nas.example.test')?.id).toBe('zone-example');
		expect(zoneForName(zones, 'example.test.')?.id).toBe('zone-example');
	});

	it('returns null for purely internal names', () => {
		expect(zoneForName(zones, 'nas.lan.')).toBeNull();
		expect(zoneForName(zones, 'ha.home.arpa')).toBeNull();
	});
});

describe('findMatchingRecord', () => {
	const records: DomainZoneRecord[] = [
		{
			id: 'r1',
			name: 'nas.example.test',
			record_type: 'A',
			content: '203.0.113.10',
			ttl: 60,
			proxied: false,
		},
		{
			id: 'r2',
			name: 'nas.example.test.',
			record_type: 'AAAA',
			content: '2001:db8::10',
			ttl: 60,
			proxied: false,
		},
	];

	it('matches owner and type ignoring trailing dots and case', () => {
		expect(findMatchingRecord(records, 'Nas.Example.Test.', 'a')?.content).toBe('203.0.113.10');
		expect(findMatchingRecord(records, 'nas.example.test', 'AAAA')?.id).toBe('r2');
		expect(findMatchingRecord(records, 'nas.example.test', 'TXT')).toBeNull();
	});
});

describe('isInventoryDnsName', () => {
	it('flags DoT inventory hosts under an apex', () => {
		const apexes = ['example.test'];
		expect(isInventoryDnsName('dns.example.test', apexes)).toBe(true);
		expect(isInventoryDnsName('*.dns.example.test.', apexes)).toBe(true);
		expect(isInventoryDnsName('ns1.dns.example.test', apexes)).toBe(true);
		expect(isInventoryDnsName('_acme-challenge.dns.example.test', apexes)).toBe(true);
		expect(isInventoryDnsName('nas.example.test', apexes)).toBe(false);
		expect(isInventoryDnsName('nas.lan', apexes)).toBe(false);
	});
});

describe('supportsProxied', () => {
	it('allows orange-cloud only on A/AAAA/CNAME', () => {
		expect(supportsProxied('A')).toBe(true);
		expect(supportsProxied('aaaa')).toBe(true);
		expect(supportsProxied('CNAME')).toBe(true);
		expect(supportsProxied('TXT')).toBe(false);
		expect(supportsProxied('MX')).toBe(false);
	});
});
