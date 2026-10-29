import { describe, expect, it } from 'vitest';
import { localZoneName, zoneOfName } from './names-zones';
import type { DomainZone } from '$lib/api/domain-zones';

const attached: DomainZone[] = [
	{ id: 'z1', name: 'example.test', status: null, name_servers: [], source: 'public_domain' },
];

describe('localZoneName', () => {
	it('drops the first label of reverse names', () => {
		expect(localZoneName('5.10.20.172.in-addr.arpa.')).toBe('10.20.172.in-addr.arpa');
	});

	it('uses the last label with a leading dot for other names', () => {
		expect(localZoneName('nas.lan.')).toBe('.lan');
		expect(localZoneName('nas.home.lan')).toBe('.lan');
		expect(localZoneName('router')).toBe('.router');
	});
});

describe('zoneOfName', () => {
	it('prefers the attached Cloudflare apex', () => {
		expect(zoneOfName(attached, 'nas.example.test.')).toEqual({
			name: 'example.test',
			attached: true,
		});
	});

	it('falls back to the derived local zone', () => {
		expect(zoneOfName(attached, 'nas.lan.')).toEqual({ name: '.lan', attached: false });
	});
});
