import { del, get, post, put, type RequestOptions } from './client';
import { getConfig, ifMatchFor } from './config';
import type { DecisionStep } from './query-log';

export interface PolicyView {
	id: string;
	is_default: boolean;
	subnets: string[];
	nodes: string[];
	profile: string;
}

export interface PolicyRecord {
	name: string;
	type: string;
	ttl: number;
	rdata: string;
	overrides: Record<string, string>;
}

export interface PolicyProfile {
	id: string;
	filter_set: string;
	suppress_aaaa: boolean;
	firefox_canary: boolean;
	icloud_private_relay: boolean;
	rebind: boolean | null;
	rebind_exceptions: string[];
	forward_zones: string[] | null;
	safesearch: unknown;
	schedules: unknown[];
}

export interface ForwardZoneEntry {
	id: string;
	zone: string;
	targets: string[];
	validate: boolean;
}

export interface TestQueryBody {
	domain: string;
	qtype: string;
	source_ip: string;
	protocol: string;
	client_id?: string;
}

export interface TestQueryAnswerRecord {
	name: string;
	/** Wire type (`A`, `AAAA`, …). API may send `type` or `qtype`. */
	type: string;
	ttl: number;
	/** Presentation form (IPv4/IPv6, target name, …). API may send `data` or `rdata`. */
	data: string;
}

export interface TestQueryAnswer {
	rcode: string;
	records: TestQueryAnswerRecord[];
}

export interface TestQueryResult {
	steps: DecisionStep[];
	view_id?: string;
	profile_id?: string;
	filter_set_id?: string;
	answer_source?: string;
	forward_zone?: string | null;
	dnssec?: string | null;
	client_id?: string | null;
	filter?: unknown;
	rcode?: string;
	answer?: TestQueryAnswer;
	timings?: {
		select_us?: number;
		filter_us?: number;
		resolve_us?: number;
		total_us?: number;
	};
	[key: string]: unknown;
}

/** Normalize answer records from either control-api or MCP wire shapes. */
export function parseTestQueryRecords(raw: unknown): TestQueryAnswerRecord[] {
	if (!Array.isArray(raw)) return [];
	const out: TestQueryAnswerRecord[] = [];
	for (const row of raw) {
		if (!row || typeof row !== 'object') continue;
		const rec = row as Record<string, unknown>;
		const name = typeof rec.name === 'string' ? rec.name : '';
		const type =
			typeof rec.type === 'string'
				? rec.type
				: typeof rec.qtype === 'string'
					? rec.qtype
					: '';
		const data =
			typeof rec.data === 'string'
				? rec.data
				: typeof rec.rdata === 'string'
					? rec.rdata
					: '';
		const ttl = typeof rec.ttl === 'number' && Number.isFinite(rec.ttl) ? rec.ttl : 0;
		if (!type && !data) continue;
		out.push({ name, type: type || '?', ttl, data });
	}
	return out;
}

function asObject(value: unknown): Record<string, unknown> | null {
	return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : null;
}

function parseViews(data: { views?: unknown }): PolicyView[] {
	if (!Array.isArray(data.views)) return [];
	return data.views.filter(isView);
}

function isView(value: unknown): value is PolicyView {
	if (typeof value !== 'object' || value === null) return false;
	const row = value as PolicyView;
	return (
		typeof row.id === 'string' &&
		typeof row.is_default === 'boolean' &&
		Array.isArray(row.subnets) &&
		Array.isArray(row.nodes) &&
		typeof row.profile === 'string'
	);
}

function parseRecords(data: { records?: unknown }): PolicyRecord[] {
	if (!Array.isArray(data.records)) return [];
	return data.records.filter(isRecord);
}

function isRecord(value: unknown): value is PolicyRecord {
	if (typeof value !== 'object' || value === null) return false;
	const row = value as PolicyRecord;
	return (
		typeof row.name === 'string' &&
		typeof row.type === 'string' &&
		typeof row.ttl === 'number' &&
		typeof row.rdata === 'string' &&
		typeof row.overrides === 'object' &&
		row.overrides !== null
	);
}

function parseProfile(value: unknown): PolicyProfile | null {
	if (typeof value !== 'object' || value === null) return null;
	const row = value as PolicyProfile;
	if (typeof row.id !== 'string' || typeof row.filter_set !== 'string') return null;
	return row;
}

/** Stable id from a zone apex when the stored `id` was left empty. */
export function forwardZoneIdFromApex(zone: string): string {
	const slug = zone
		.trim()
		.replace(/\.+$/, '')
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, '-')
		.replace(/^-+|-+$/g, '');
	return slug || 'forward-zone';
}

export function parseForwardZones(config: Record<string, unknown> | null): ForwardZoneEntry[] {
	const resolver = asObject(config?.resolver);
	const raw = resolver?.forward_zones;
	if (!Array.isArray(raw)) return [];
	const zones: ForwardZoneEntry[] = [];
	for (const item of raw) {
		if (typeof item !== 'object' || item === null) continue;
		const row = item as Record<string, unknown>;
		const zone = typeof row.zone === 'string' ? row.zone.trim() : '';
		if (!zone) continue;
		const rawId = typeof row.id === 'string' ? row.id.trim() : '';
		const id = rawId || forwardZoneIdFromApex(zone);
		const targets = Array.isArray(row.targets) ? row.targets.map(String) : [];
		zones.push({
			id,
			zone,
			targets,
			validate: row.validate === true,
		});
	}
	return zones;
}

export function profilesFromConfig(config: Record<string, unknown> | null): PolicyProfile[] {
	const policy = asObject(config?.policy);
	const raw = policy?.profiles;
	if (!Array.isArray(raw)) return [];
	return raw.map(parseProfile).filter((p): p is PolicyProfile => p !== null);
}

export const listViews = (): Promise<PolicyView[]> =>
	get<{ views: unknown }>('/policy/views').then((data) => parseViews(data));

export const getView = (id: string): Promise<PolicyView> =>
	get<{ view: unknown }>(`/policy/views/${encodeURIComponent(id)}`).then((data) => {
		const view = isView(data.view) ? data.view : null;
		if (!view) throw new Error('malformed');
		return view;
	});

export const saveView = (
	id: string,
	body: Omit<PolicyView, 'id'>,
	options?: RequestOptions,
): Promise<{ version: number; view: PolicyView }> =>
	put(`/policy/views/${encodeURIComponent(id)}`, { body: { ...body, id }, ...options });

export const deleteView = (id: string, options?: RequestOptions): Promise<{ version: number }> =>
	del(`/policy/views/${encodeURIComponent(id)}`, options);

export const listRecords = (): Promise<PolicyRecord[]> =>
	get<{ records: unknown }>('/policy/records').then((data) => parseRecords(data));

export const saveRecord = (
	body: Omit<PolicyRecord, 'overrides'> & { overrides?: Record<string, string> },
	options?: RequestOptions,
): Promise<{ version: number; record: PolicyRecord }> =>
	put('/policy/records', { body, ...options });

export const deleteRecord = (
	body: { name: string; type: string },
	options?: RequestOptions,
): Promise<{ version: number }> => del('/policy/records', { body, ...options });

export const listProfiles = async (): Promise<PolicyProfile[]> => {
	const snapshot = await getConfig();
	return profilesFromConfig(snapshot.config);
};

export const getProfile = (id: string): Promise<PolicyProfile> =>
	get<{ profile: unknown }>(`/policy/profiles/${encodeURIComponent(id)}`).then((data) => {
		const profile = parseProfile(data.profile);
		if (!profile) throw new Error('malformed');
		return profile;
	});

export const saveProfile = (
	id: string,
	body: Omit<PolicyProfile, 'id'>,
	options?: RequestOptions,
): Promise<{ version: number; profile: PolicyProfile }> =>
	put(`/policy/profiles/${encodeURIComponent(id)}`, { body: { ...body, id }, ...options });

export const deleteProfile = (id: string, options?: RequestOptions): Promise<{ version: number }> =>
	del(`/policy/profiles/${encodeURIComponent(id)}`, options);

/**
 * One registered Client ID. `label` names the device, `device` is a directory client id (or null).
 * `view` pins the ID to a Netzbereich for requests that no range recognises (or null for the default).
 */
export interface ClientIdEntry {
	id: string;
	label: string | null;
	device: string | null;
	view: string | null;
}

export interface ClientIdFields {
	label?: string | null;
	device?: string | null;
	view?: string | null;
}

function parseClientId(value: unknown): ClientIdEntry | null {
	if (typeof value === 'string') return { id: value, label: null, device: null, view: null };
	const row = asObject(value);
	if (!row || typeof row.id !== 'string') return null;
	return {
		id: row.id,
		label: typeof row.label === 'string' ? row.label : null,
		device: typeof row.device === 'string' ? row.device : null,
		view: typeof row.view === 'string' ? row.view : null,
	};
}

/** Strings from older snapshots read as `{ id }`; objects keep their label and device. */
export const listClientIds = (): Promise<ClientIdEntry[]> =>
	get<{ client_ids: unknown }>('/policy/client-ids').then((data) =>
		Array.isArray(data.client_ids)
			? data.client_ids.map(parseClientId).filter((entry): entry is ClientIdEntry => entry !== null)
			: [],
	);

/** `label`, `device` and `view` are sent only when given; `null` in a field stores "no value". */
export const createClientId = (
	id: string,
	fields: ClientIdFields = {},
	options?: RequestOptions,
): Promise<{ version: number; client_id: string }> =>
	post('/policy/client-ids', { body: { id, ...fields }, ...options });

/** Changes label, device and/or view of an existing Client ID; the id itself never changes. */
export const updateClientId = (
	id: string,
	fields: ClientIdFields,
	options?: RequestOptions,
): Promise<{ version: number; client_id: string }> =>
	put(`/policy/client-ids/${encodeURIComponent(id)}`, { body: fields, ...options });

export const revokeClientId = (
	id: string,
	options?: RequestOptions,
): Promise<{ version: number }> => del(`/policy/client-ids/${encodeURIComponent(id)}`, options);

export const runTestQuery = (body: TestQueryBody): Promise<TestQueryResult> =>
	post<TestQueryResult>('/policy/test-query', { body });

export const loadForwardZones = async (): Promise<{
	version: number | null;
	zones: ForwardZoneEntry[];
}> => {
	const snapshot = await getConfig();
	return {
		version: snapshot.version,
		zones: parseForwardZones(snapshot.config),
	};
};

export const saveForwardZones = async (
	zones: ForwardZoneEntry[],
	version: number | null,
): Promise<number> => {
	const snapshot = await getConfig();
	const config = structuredClone(snapshot.config ?? {}) as Record<string, unknown>;
	const resolver = asObject(config.resolver) ?? {};
	resolver.forward_zones = zones.map((zone) => ({
		id: zone.id,
		zone: zone.zone,
		targets: zone.targets,
		validate: zone.validate,
	}));
	config.resolver = resolver;
	const result = await put<{ version: number }>('/config', {
		body: config,
		ifMatch: ifMatchFor(version),
	});
	return result.version;
};
