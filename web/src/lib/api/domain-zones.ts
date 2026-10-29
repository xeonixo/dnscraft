import { del, get, isRecord, post, put, type RequestOptions } from './client';

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

/** Body for create/update of a public Cloudflare record (API-REFERENCE). */
export interface DomainZoneRecordWrite {
	name: string;
	type: string;
	content: string;
	ttl?: number;
	proxied?: boolean;
	priority?: number;
	weight?: number;
	port?: number;
}

export interface AttachDomainZoneBody {
	name: string;
	zone_id?: string;
}

/** Record types Cloudflare accepts on Domain-Zonen mutate routes. */
export const PUBLIC_RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'TXT', 'MX', 'SRV'] as const;

/** Types that support Cloudflare orange-cloud proxying. */
export function supportsProxied(recordType: string): boolean {
	const type = recordType.trim().toUpperCase();
	return type === 'A' || type === 'AAAA' || type === 'CNAME';
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

/**
 * True when `fqdn` is a DoT/DoQ inventory name under an apex (`dns.`, `*.dns.`,
 * `<label>.dns.`, or `_acme-challenge.dns.`). Proxied (orange cloud) breaks these.
 */
export function isInventoryDnsName(fqdn: string, apexes: readonly string[]): boolean {
	const name = normalizeDnsName(fqdn);
	if (name === '') return false;
	for (const raw of apexes) {
		const apex = normalizeDnsName(raw);
		if (apex === '') continue;
		if (name === `dns.${apex}`) return true;
		if (name === `*.dns.${apex}`) return true;
		if (name === `_acme-challenge.dns.${apex}`) return true;
		if (name.endsWith(`.dns.${apex}`)) return true;
	}
	return false;
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
		page.discoverable = data.discoverable.map(parseZone).filter((z): z is DomainZone => z !== null);
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

/** Hard cap on pages per zone (50 × 100 records) so a bad `total_pages` cannot loop forever. */
export const MAX_ZONE_RECORD_PAGES = 50;

/**
 * Every record of an attached zone, paginated. Stops at `total_pages`, an empty page or the cap
 * (records past the cap are not loaded).
 */
export async function listAllDomainZoneRecords(zoneId: string): Promise<DomainZoneRecord[]> {
	const records: DomainZoneRecord[] = [];
	for (let page = 1; page <= MAX_ZONE_RECORD_PAGES; page++) {
		const result = await listDomainZoneRecords(zoneId, { page, per_page: 100 });
		records.push(...result.records);
		if (result.records.length === 0 || page >= result.total_pages) break;
	}
	return records;
}

/** Cloudflare TTL 1 means "Auto". */
export const CF_TTL_AUTO = 1;

/** TTL for display: Cloudflare TTL 1 shows the localized `autoLabel`, other values as seconds. */
export function ttlLabel(ttl: number, autoLabel: string): string {
	return ttl === CF_TTL_AUTO ? autoLabel : String(ttl);
}

/**
 * Parse a TTL field: `auto` (or the localized label) and `1` both mean Cloudflare Auto (1),
 * digits are seconds, anything else is null.
 */
export function parseTtlInput(text: string, autoLabel: string): number | null {
	const value = text.trim().toLowerCase();
	if (value === 'auto' || value === autoLabel.trim().toLowerCase()) return CF_TTL_AUTO;
	if (!/^\d+$/.test(value)) return null;
	return Number(value);
}

function requireRecord(data: unknown): DomainZoneRecord {
	const record = parseRecord(data);
	if (!record) throw new Error('malformed domain-zone record');
	return record;
}

function requireZone(data: unknown): DomainZone {
	const zone = parseZone(data);
	if (!zone) throw new Error('malformed domain-zone');
	return zone;
}

/** `POST /api/v1/domain-zones/{zone_id}/records` — create a public DNS record (admin). */
export const createDomainZoneRecord = (
	zoneId: string,
	body: DomainZoneRecordWrite,
	options?: RequestOptions,
): Promise<DomainZoneRecord> =>
	post<unknown>(`/domain-zones/${encodeURIComponent(zoneId)}/records`, {
		body,
		...options,
	}).then(requireRecord);

/** `PUT /api/v1/domain-zones/{zone_id}/records` — update a public DNS record by id (admin). */
export const updateDomainZoneRecord = (
	zoneId: string,
	body: DomainZoneRecordWrite & { id: string },
	options?: RequestOptions,
): Promise<DomainZoneRecord> =>
	put<unknown>(`/domain-zones/${encodeURIComponent(zoneId)}/records`, {
		body,
		...options,
	}).then(requireRecord);

/** `DELETE /api/v1/domain-zones/{zone_id}/records` — delete a public DNS record (admin). */
export const deleteDomainZoneRecord = (
	zoneId: string,
	id: string,
	options?: RequestOptions,
): Promise<{ deleted: boolean; id: string }> =>
	del<{ deleted: boolean; id: string }>(`/domain-zones/${encodeURIComponent(zoneId)}/records`, {
		body: { id },
		...options,
	});

/**
 * Upsert the public Cloudflare record for an owner+type, or delete when `content` is blank
 * and a matching record already exists.
 */
export async function upsertPublicRecord(
	zoneId: string,
	existing: DomainZoneRecord | null,
	body: DomainZoneRecordWrite,
): Promise<DomainZoneRecord | null> {
	const content = body.content.trim();
	if (content === '') {
		if (existing) {
			await deleteDomainZoneRecord(zoneId, existing.id);
		}
		return null;
	}
	const payload: DomainZoneRecordWrite = {
		name: body.name,
		type: body.type,
		content,
		ttl: body.ttl,
		proxied: body.proxied,
		priority: body.priority,
		weight: body.weight,
		port: body.port,
	};
	if (existing) {
		return updateDomainZoneRecord(zoneId, { ...payload, id: existing.id });
	}
	return createDomainZoneRecord(zoneId, payload);
}

/** `POST /api/v1/domain-zones/attach` — attach an apex into `dns_provider.zones` (admin). */
export const attachDomainZone = (
	body: AttachDomainZoneBody,
	options?: RequestOptions,
): Promise<DomainZone> =>
	post<unknown>('/domain-zones/attach', { body, ...options }).then(requireZone);

/** `DELETE /api/v1/domain-zones/attach/{apex}` — detach without deleting the Cloudflare zone. */
export const detachDomainZone = (
	apex: string,
	options?: RequestOptions,
): Promise<{ detached: boolean; name: string }> =>
	del<{ detached: boolean; name: string }>(
		`/domain-zones/attach/${encodeURIComponent(apex)}`,
		options,
	);
