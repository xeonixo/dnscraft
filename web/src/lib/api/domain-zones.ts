import { get, isRecord } from './client';

/** Attached Domain-Zone from `GET /api/v1/domain-zones` (SPEC / API-REFERENCE). */
export interface DomainZone {
	/** Cloudflare zone id when known (configured or resolved). */
	id: string | null;
	/** Zone apex name. */
	name: string;
	/** Cloudflare lifecycle status when resolved. */
	status: string | null;
	/** Authoritative nameserver hostnames when resolved. */
	name_servers: string[];
	/** `public_domain` or `dns_provider`. */
	source: string;
}

/** One DNS record from `GET /api/v1/domain-zones/{zone_id}/records`. */
export interface DomainZoneRecord {
	id: string;
	name: string;
	record_type: string;
	content: string;
	ttl: number;
	proxied: boolean;
}

export interface DomainZonesPage {
	zones: DomainZone[];
	has_cloudflare_token: boolean;
	discoverable?: DomainZone[];
}

export interface DomainZoneRecordsPage {
	records: DomainZoneRecord[];
	page: number;
	per_page: number;
	total_count: number;
	total_pages: number;
}

export interface ListDomainZonesOptions {
	/** Admin-only; adds `discoverable` from Cloudflare. */
	discover?: boolean;
}

export interface ListDomainZoneRecordsOptions {
	page?: number;
	per_page?: number;
	name_substr?: string;
}

/** Strip trailing dot and lowercase for DNS name comparisons. */
export function normalizeDnsName(name: string): string {
	return name.trim().replace(/\.+$/, '').toLowerCase();
}

/**
 * Longest attached apex that covers `fqdn` (`name === apex` or is a subdomain).
 * Returns null when the name is purely internal (no matching Domain-Zone).
 */
export function zoneForName(zones: readonly DomainZone[], fqdn: string): DomainZone | null {
	const name = normalizeDnsName(fqdn);
	if (name === '') return null;
	let best: DomainZone | null = null;
	for (const zone of zones) {
		const apex = normalizeDnsName(zone.name);
		if (apex === '') continue;
		if (name === apex || name.endsWith(`.${apex}`)) {
			if (!best || apex.length > normalizeDnsName(best.name).length) best = zone;
		}
	}
	return best;
}

/** Exact owner+type match against a Cloudflare record (trailing dots ignored). */
export function findMatchingRecord(
	records: readonly DomainZoneRecord[],
	fqdn: string,
	recordType: string,
): DomainZoneRecord | null {
	const name = normalizeDnsName(fqdn);
	const type = recordType.trim().toUpperCase();
	for (const record of records) {
		if (normalizeDnsName(record.name) === name && record.record_type.toUpperCase() === type) {
			return record;
		}
	}
	return null;
}

function parseZone(value: unknown): DomainZone | null {
	if (!isRecord(value) || typeof value.name !== 'string') return null;
	const id = typeof value.id === 'string' && value.id.trim() !== '' ? value.id : null;
	const status = typeof value.status === 'string' ? value.status : null;
	const name_servers = Array.isArray(value.name_servers)
		? value.name_servers.filter((ns): ns is string => typeof ns === 'string')
		: [];
	return {
		id,
		name: value.name,
		status,
		name_servers,
		source: typeof value.source === 'string' ? value.source : '',
	};
}

function parseRecord(value: unknown): DomainZoneRecord | null {
	if (!isRecord(value)) return null;
	if (typeof value.id !== 'string' || typeof value.name !== 'string') return null;
	if (typeof value.record_type !== 'string' || typeof value.content !== 'string') return null;
	const ttl = typeof value.ttl === 'number' && Number.isFinite(value.ttl) ? value.ttl : 1;
	return {
		id: value.id,
		name: value.name,
		record_type: value.record_type,
		content: value.content,
		ttl,
		proxied: value.proxied === true,
	};
}

function parseZonesPage(data: unknown): DomainZonesPage {
	if (!isRecord(data)) return { zones: [], has_cloudflare_token: false };
	const zones = Array.isArray(data.zones)
		? data.zones.map(parseZone).filter((z): z is DomainZone => z !== null)
		: [];
	const page: DomainZonesPage = {
		zones,
		has_cloudflare_token: data.has_cloudflare_token === true,
	};
	if (Array.isArray(data.discoverable)) {
		page.discoverable = data.discoverable
			.map(parseZone)
			.filter((z): z is DomainZone => z !== null);
	}
	return page;
}

function parseRecordsPage(data: unknown): DomainZoneRecordsPage {
	if (!isRecord(data)) {
		return { records: [], page: 1, per_page: 50, total_count: 0, total_pages: 0 };
	}
	const records = Array.isArray(data.records)
		? data.records.map(parseRecord).filter((r): r is DomainZoneRecord => r !== null)
		: [];
	const num = (value: unknown, fallback: number): number =>
		typeof value === 'number' && Number.isFinite(value) ? value : fallback;
	return {
		records,
		page: num(data.page, 1),
		per_page: num(data.per_page, 50),
		total_count: num(data.total_count, records.length),
		total_pages: num(data.total_pages, records.length === 0 ? 0 : 1),
	};
}

/** `GET /api/v1/domain-zones` — attached zones + token flag (viewer/admin). */
export const listDomainZones = (options: ListDomainZonesOptions = {}): Promise<DomainZonesPage> => {
	const query = options.discover ? '?discover=1' : '';
	return get<unknown>(`/domain-zones${query}`).then(parseZonesPage);
};

/** `GET /api/v1/domain-zones/{zone_id}/records` — paginated CF records for an attached zone. */
export const listDomainZoneRecords = (
	zoneId: string,
	options: ListDomainZoneRecordsOptions = {},
): Promise<DomainZoneRecordsPage> => {
	const params = new URLSearchParams();
	if (options.page != null) params.set('page', String(options.page));
	if (options.per_page != null) params.set('per_page', String(options.per_page));
	if (options.name_substr != null && options.name_substr.trim() !== '') {
		params.set('name_substr', options.name_substr.trim());
	}
	const query = params.size > 0 ? `?${params}` : '';
	return get<unknown>(`/domain-zones/${encodeURIComponent(zoneId)}/records${query}`).then(
		parseRecordsPage,
	);
};
