import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
	findMatchingRecord,
	isInventoryDnsName,
	listAllDomainZoneRecords,
	normalizeDnsName,
	parseTtlInput,
	supportsProxied,
	ttlLabel,
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

describe('listAllDomainZoneRecords', () => {
	const json = (body: unknown): Response =>
		new Response(JSON.stringify({ data: body }), {
			status: 200,
			headers: { 'Content-Type': 'application/json' },
		});
	const rec = (n: number) => ({
		id: `r${n}`,
		name: `h${n}.example.test`,
		record_type: 'A',
		content: '192.0.2.1',
		ttl: 60,
		proxied: false,
	});

	let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;

	beforeEach(() => {
		fetchMock = vi.fn<typeof fetch>();
		vi.stubGlobal('fetch', fetchMock);
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('walks every page until total_pages', async () => {
		fetchMock
			.mockResolvedValueOnce(
				json({ records: [rec(1), rec(2)], page: 1, per_page: 100, total_count: 3, total_pages: 2 }),
			)
			.mockResolvedValueOnce(
				json({ records: [rec(3)], page: 2, per_page: 100, total_count: 3, total_pages: 2 }),
			);
		const all = await listAllDomainZoneRecords('zone-1');
		expect(all.map((r) => r.id)).toEqual(['r1', 'r2', 'r3']);
		const urls = fetchMock.mock.calls.map(([url]) => String(url));
		expect(urls[0]).toContain('/domain-zones/zone-1/records?page=1&per_page=100');
		expect(urls[1]).toContain('page=2');
	});

	it('stops at the hard page cap', async () => {
		fetchMock.mockImplementation(async () =>
			json({ records: [rec(1)], page: 1, per_page: 100, total_count: 999, total_pages: 999 }),
		);
		const all = await listAllDomainZoneRecords('zone-1');
		expect(fetchMock).toHaveBeenCalledTimes(50);
		expect(all).toHaveLength(50);
	});
});

describe('ttlLabel and parseTtlInput', () => {
	it('shows Cloudflare TTL 1 as Auto and other values as seconds', () => {
		expect(ttlLabel(1, 'Auto')).toBe('Auto');
		expect(ttlLabel(300, 'Auto')).toBe('300');
	});

	it('reads auto or 1 as TTL 1 and digits as seconds', () => {
		expect(parseTtlInput('auto', 'Auto')).toBe(1);
		expect(parseTtlInput(' Auto ', 'Auto')).toBe(1);
		expect(parseTtlInput('AUTO', 'Automatisch')).toBe(1);
		expect(parseTtlInput('1', 'Auto')).toBe(1);
		expect(parseTtlInput('300', 'Auto')).toBe(300);
		expect(parseTtlInput('', 'Auto')).toBeNull();
		expect(parseTtlInput('soon', 'Auto')).toBeNull();
	});
});
