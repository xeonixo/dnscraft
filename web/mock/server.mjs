// Local mock of the DNScraft control-api for UI work. Plain Node http, no dependencies.
//
// It serves web/build (SPA fallback to index.html) and an in-memory fake /api/v1 on the same origin,
// bound to 127.0.0.1 only. It never opens outbound connections. Data comes from mock/fixtures.mjs,
// and writes (temporary allows, pauses, cache flushes) change nothing beyond the response.
//
// Environment: MOCK_PORT (default 4173), MOCK_ROLE (admin | viewer, default admin),
// MOCK_DROPPED (query_log_dropped count reported by the overview, default 0).

import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { dirname, extname, join, normalize, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
	BASE_SECURITY_HEADERS,
	cacheControlForPath,
	htmlSecurityHeaders,
} from './security-headers.mjs';
import {
	buildRecords,
	initialConfig,
	MOCK_AUDIT,
	MOCK_CLUSTER_NODES,
	MOCK_DIRECTORY_CLIENTS,
	MOCK_TOKENS,
	PROTOCOLS,
} from './fixtures.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT_BUILD_DIR = resolve(HERE, '..', 'build');
const MOCK_CSRF_TOKEN = 'mock-csrf-token-not-a-secret';
const MAX_ROWS_PER_REQUEST = 10_000;
const DEFAULT_LIMIT = 50;
const STATUSES = ['allowed', 'blocked', 'dnssec_bogus', 'servfail'];
const ORDER_BY = ['time', 'client', 'domain', 'rcode'];
const DURATIONS = { PT5M: 300, PT15M: 900, PT1H: 3600 };
const CSV_COLUMNS = [
	'id',
	'time',
	'node_id',
	'listener_id',
	'protocol',
	'source_ip',
	'source_ip_truncated',
	'client_id',
	'client_name',
	'query_name',
	'query_type',
	'query_class',
	'view_id',
	'profile_id',
	'answer_source',
	'dnssec',
	'rcode',
	'answer_size',
];
/** Top-level sections a config snapshot may hold (config_apply.rs TOP_LEVEL_KEYS). */
const TOP_LEVEL_KEYS = [
	'filtering',
	'clients',
	'policy',
	'listeners',
	'tls',
	'resolver',
	'control_api_settings',
	'notifications',
	'mcp',
];
/** Client-IP modes for newly recorded query-log entries (absent means `none`). */
const QUERY_LOG_IP_TRUNCATE = ['none', 'last_octet', 'last_group'];
/** Sections every replace must provide (config_apply.rs REQUIRED_SECTIONS). */
const REQUIRED_SECTIONS = ['filtering', 'clients', 'policy', 'listeners', 'tls'];
const MCP_RULE_KEYS = [
	'id',
	'domain',
	'include_subdomains',
	'created_at',
	'expires_at',
	'token_id',
];
const CONTENT_TYPES = {
	'.html': 'text/html; charset=utf-8',
	'.js': 'text/javascript; charset=utf-8',
	'.mjs': 'text/javascript; charset=utf-8',
	'.css': 'text/css; charset=utf-8',
	'.json': 'application/json; charset=utf-8',
	'.webmanifest': 'application/manifest+json; charset=utf-8',
	'.svg': 'image/svg+xml',
	'.png': 'image/png',
	'.ico': 'image/x-icon',
	'.woff2': 'font/woff2',
	'.txt': 'text/plain; charset=utf-8',
};

/** A failure with the control-api envelope: stable code, HTTP status, non-secret params. */
class ApiFailure extends Error {
	constructor(status, code, params = {}) {
		super(code);
		this.status = status;
		this.code = code;
		this.params = params;
	}
}

const statusOf = (record) => {
	if (record.filter?.block_mode) return 'blocked';
	if (record.rcode === 'SERVFAIL') return 'servfail';
	if (record.dnssec === 'bogus') return 'dnssec_bogus';
	return 'allowed';
};

function parseCount(name, raw, minimum) {
	if (!/^\d+$/.test(raw.trim())) {
		throw new ApiFailure(400, 'control_api.pagination.invalid', {
			reason: `${name} must be a non-negative integer, got \`${raw}\``,
		});
	}
	const value = Number(raw.trim());
	if (value < minimum) {
		throw new ApiFailure(400, 'control_api.pagination.invalid', {
			reason: `${name} must be at least ${minimum}, got \`${raw}\``,
		});
	}
	return value;
}

function invalidQuery(reason) {
	return new ApiFailure(400, 'control_api.query_log.invalid', { reason });
}

function parseTimestamp(raw, name) {
	const millis = Date.parse(raw.trim());
	if (!/^\d{4}-\d{2}-\d{2}T/.test(raw.trim()) || Number.isNaN(millis)) {
		throw invalidQuery(`\`${name}\` must be an RFC 3339 timestamp`);
	}
	return millis;
}

function parseBool(raw, name) {
	if (raw === undefined || raw === '') return false;
	if (raw === 'true' || raw === '1') return true;
	if (raw === 'false' || raw === '0') return false;
	throw invalidQuery(`\`${name}\` must be a boolean`);
}

/** Mirrors RawQueryLogParams::into_filter: the same checks, codes and order. */
export function parseQuery(params) {
	const limitRaw = params.get('limit');
	const offsetRaw = params.get('offset');
	const limit = limitRaw === null ? DEFAULT_LIMIT : parseCount('limit', limitRaw, 1);
	const offset = offsetRaw === null ? 0 : parseCount('offset', offsetRaw, 0);
	const from = params.get('from') ? parseTimestamp(params.get('from'), 'from') : null;
	const to = params.get('to') ? parseTimestamp(params.get('to'), 'to') : null;
	if (from !== null && to !== null && from > to) {
		throw invalidQuery('`from` must not be after `to`');
	}
	const protocol = params.get('protocol') || null;
	if (protocol !== null && !PROTOCOLS.includes(protocol)) {
		throw invalidQuery(`\`protocol\` must be one of ${PROTOCOLS.join(', ')}`);
	}
	const status = params.get('status') || null;
	if (status !== null && !STATUSES.includes(status)) {
		throw invalidQuery(`\`status\` must be one of ${STATUSES.join(', ')}`);
	}
	const orderBy = params.get('order_by') || 'time';
	if (!ORDER_BY.includes(orderBy)) {
		throw invalidQuery('`order_by` must be time, client, domain or rcode');
	}
	const order = params.get('order') || 'desc';
	if (order !== 'asc' && order !== 'desc') {
		throw invalidQuery('`order` must be asc or desc');
	}
	return {
		from,
		to,
		node_id: params.get('node_id') || null,
		client_id: params.get('client_id') || null,
		client_name_substr: params.get('client_name_substr') || null,
		domain: params.get('domain') || null,
		domain_substr: params.get('domain_substr') || null,
		protocol,
		view_id: params.get('view_id') || null,
		profile_id: params.get('profile_id') || null,
		status,
		only_blocked: parseBool(params.get('only_blocked') ?? '', 'only_blocked'),
		only_with_clients: parseBool(params.get('only_with_clients') ?? '', 'only_with_clients'),
		order_by: orderBy,
		order,
		limit,
		offset,
	};
}

const RECORDS = buildRecords();

/** The rows a filter selects, already ordered. Paging is applied by the caller. */
export function selectRecords(filter) {
	const needle = filter.domain_substr?.toLowerCase();
	const clientNeedle = filter.client_name_substr?.toLowerCase();
	const rows = RECORDS.filter((record) => {
		const time = Date.parse(record.time);
		if (filter.from !== null && time < filter.from) return false;
		if (filter.to !== null && time > filter.to) return false;
		if (filter.node_id && record.node_id !== filter.node_id) return false;
		if (filter.client_id && record.client_id !== filter.client_id) return false;
		if (clientNeedle && !(record.client?.display_name ?? '').toLowerCase().includes(clientNeedle)) {
			return false;
		}
		if (filter.domain && record.query.name !== filter.domain) return false;
		if (needle && !record.query.name.toLowerCase().includes(needle)) return false;
		if (filter.protocol && record.protocol !== filter.protocol) return false;
		if (filter.view_id && record.view_id !== filter.view_id) return false;
		if (filter.profile_id && record.profile_id !== filter.profile_id) return false;
		if (filter.status && statusOf(record) !== filter.status) return false;
		if (filter.only_blocked && statusOf(record) !== 'blocked') return false;
		if (filter.only_with_clients && record.client === null) return false;
		return true;
	});
	const keyOf = {
		time: (record) => Date.parse(record.time),
		client: (record) => record.client?.display_name ?? record.client_id ?? '',
		domain: (record) => record.query.name,
		rcode: (record) => record.rcode,
	}[filter.order_by];
	const sign = filter.order === 'asc' ? 1 : -1;
	return rows.sort((a, b) => {
		const ka = keyOf(a);
		const kb = keyOf(b);
		if (ka !== kb) return (ka < kb ? -1 : 1) * sign;
		return (a.id < b.id ? -1 : 1) * sign;
	});
}

/** One query page, in the shape `GET /api/v1/query-log` returns. */
export function listPage(params) {
	const filter = parseQuery(params);
	const limit = Math.min(filter.limit, MAX_ROWS_PER_REQUEST);
	const rows = selectRecords(filter);
	const page = rows.slice(filter.offset, filter.offset + limit);
	const hasMore = rows.length > filter.offset + limit;
	return {
		queries: page,
		has_more: hasMore,
		next_offset: hasMore ? filter.offset + limit : null,
	};
}

function csvField(value) {
	let text = value === null || value === undefined ? '' : String(value);
	if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
	if (/[",\n\r]/.test(text)) text = `"${text.replace(/"/g, '""')}"`;
	return text;
}

function csvLine(record) {
	return CSV_COLUMNS.map((column) => {
		const values = {
			client_name: record.client?.display_name ?? null,
			query_name: record.query.name,
			query_type: record.query.type,
			query_class: record.query.class,
			view_id: record.view_id,
			profile_id: record.profile_id,
			answer_source: record.answer_source,
			dnssec: record.dnssec,
			rcode: record.rcode,
		};
		return csvField(column in values ? values[column] : record[column]);
	}).join(',');
}

function overview(params) {
	const rows = selectRecords({ ...parseWindow(params), order_by: 'time', order: 'desc' });
	const bySource = {};
	for (const record of rows)
		bySource[record.answer_source] = (bySource[record.answer_source] ?? 0) + 1;
	const blocked = rows.filter((record) => statusOf(record) === 'blocked').length;
	return {
		source: 'raw',
		total: rows.length,
		allowed: rows.length - blocked,
		blocked,
		allowed_ratio: rows.length === 0 ? 0 : (rows.length - blocked) / rows.length,
		query_log_dropped: Number(process.env.MOCK_DROPPED ?? 0) || 0,
		by_answer_source: bySource,
	};
}

function parseWindow(params) {
	const from = params.get('from') ? Date.parse(params.get('from')) : null;
	const to = params.get('to') ? Date.parse(params.get('to')) : null;
	return {
		from: Number.isNaN(from) ? null : from,
		to: Number.isNaN(to) ? null : to,
		...emptyFilter(),
	};
}

function emptyFilter() {
	return {
		node_id: null,
		client_id: null,
		client_name_substr: null,
		domain: null,
		domain_substr: null,
		protocol: null,
		view_id: null,
		profile_id: null,
		status: null,
		only_blocked: false,
		only_with_clients: false,
	};
}

function groupCounts(rows, keyOf) {
	const groups = new Map();
	for (const record of rows) {
		const key = keyOf(record);
		const entry = groups.get(key.id) ?? { ...key, queries: 0, blocked: 0 };
		entry.queries += 1;
		if (statusOf(record) === 'blocked') entry.blocked += 1;
		groups.set(key.id, entry);
	}
	return [...groups.values()].sort((a, b) => b.queries - a.queries || a.id.localeCompare(b.id));
}

function readJsonBody(request) {
	return new Promise((resolveBody, reject) => {
		const chunks = [];
		request.on('data', (chunk) => chunks.push(chunk));
		request.on('error', reject);
		request.on('end', () => {
			const text = Buffer.concat(chunks).toString('utf8');
			if (text === '') return resolveBody({});
			try {
				resolveBody(JSON.parse(text));
			} catch {
				reject(new ApiFailure(400, 'mcp.invalid_input'));
			}
		});
	});
}

function send(response, status, body, headers = {}) {
	response.writeHead(status, {
		...BASE_SECURITY_HEADERS,
		'Cache-Control': 'no-store',
		...headers,
	});
	response.end(body);
}

/**
 * Engine status per list id, as the filter engine reports it. Times are relative to now so the
 * page shows fresh updates. The failing list keeps the rules of its last good build.
 */
function listStatusFor(id, now = Date.now()) {
	const hoursAgo = (hours) => new Date(now - hours * 3_600_000).toISOString();
	if (id === 'adguard-dns-filter') {
		return {
			rules_parsed: 41230,
			rules_skipped: 12,
			unique_contribution: 38210,
			last_success: hoursAgo(3),
			last_attempt: hoursAgo(3),
			error_code: null,
			http_status: 200,
		};
	}
	if (id === 'stevenblack-hosts') {
		return {
			rules_parsed: 79950,
			rules_skipped: 3,
			unique_contribution: 61240,
			last_success: hoursAgo(9),
			last_attempt: hoursAgo(9),
			error_code: null,
			http_status: 200,
		};
	}
	if (id === 'trackers-main') {
		return {
			rules_parsed: 8415,
			rules_skipped: 0,
			unique_contribution: 1790,
			last_success: hoursAgo(50),
			last_attempt: hoursAgo(0.5),
			error_code: 'filter_list.fetch_failed',
			http_status: 503,
		};
	}
	return undefined;
}

function withListStatus(list) {
	const status = listStatusFor(list.id);
	return status ? { ...list, status } : list;
}

function sendData(response, data, status = 200) {
	send(response, status, JSON.stringify({ data }), {
		'Content-Type': 'application/json; charset=utf-8',
	});
}

function sendError(response, failure) {
	const error = { code: failure.code, params: failure.params };
	send(response, failure.status, JSON.stringify({ error }), {
		'Content-Type': 'application/json; charset=utf-8',
	});
}

/**
 * The versioned configuration of one mock server. Versions are kept in order; the last one is current.
 * Each server starts from the same snapshot, so tests never see state from another server.
 */
function createConfigStore() {
	const start = Date.parse('2026-10-20T08:00:00Z') / 1000;
	const versions = [];
	for (let version = 1; version <= 12; version++) {
		versions.push({ version, created_at: start + version * 6 * 3600, config: initialConfig() });
	}
	return { versions };
}

const currentOf = (store) => store.versions[store.versions.length - 1];

function appendVersion(store, config) {
	const version = currentOf(store).version + 1;
	store.versions.push({ version, created_at: Math.floor(Date.now() / 1000), config });
	return version;
}

const rfc3339 = (seconds) => new Date(seconds * 1000).toISOString().replace('.000Z', 'Z');
const isObject = (value) => typeof value === 'object' && value !== null && !Array.isArray(value);

function configInvalid(reason) {
	return new ApiFailure(400, 'control_api.config.invalid', { reason });
}

/** Parses a config body; malformed JSON is the config-invalid code, as in config_routes.rs. */
async function readConfigBody(request) {
	const text = await readText(request);
	try {
		return JSON.parse(text);
	} catch {
		throw configInvalid('malformed JSON body');
	}
}

function readText(request) {
	return new Promise((resolveText, reject) => {
		const chunks = [];
		request.on('data', (chunk) => chunks.push(chunk));
		request.on('error', reject);
		request.on('end', () => resolveText(Buffer.concat(chunks).toString('utf8')));
	});
}

/**
 * Compares If-Match with the current version (config_apply.rs check_if_match). Returns null when the
 * precondition holds or is absent, otherwise a reason string.
 */
function ifMatchProblem(raw, current) {
	if (raw === undefined) return null;
	const value = raw.trim();
	if (value === '*') return null;
	const digits = value.replace(/^W\//, '').trim().replace(/^"|"$/g, '');
	if (!/^\d+$/.test(digits)) return `invalid If-Match value \`${raw}\``;
	return Number(digits) === current
		? null
		: `If-Match version ${digits} is not the current version`;
}

/**
 * Applies the mcp_rules rule to a candidate: an omitted field carries the stored rules of the same
 * filter set over, an explicit array replaces them, unknown fields are rejected (config_apply.rs).
 */
function mergeCandidate(body, stored) {
	if (!isObject(body)) throw configInvalid('config body must be a JSON object');
	for (const key of Object.keys(body)) {
		if (!TOP_LEVEL_KEYS.includes(key)) throw configInvalid(`unknown field \`${key}\``);
	}
	const snapshot = structuredClone(body);
	const storedSets = Array.isArray(stored?.filtering?.sets) ? stored.filtering.sets : [];
	const sets = snapshot.filtering?.sets;
	if (Array.isArray(sets)) {
		for (const set of sets) {
			if (!isObject(set)) continue;
			if (!('mcp_rules' in set)) {
				const prior = storedSets.find((candidate) => candidate.id === set.id);
				set.mcp_rules = structuredClone(prior?.mcp_rules ?? []);
			} else if (Array.isArray(set.mcp_rules)) {
				for (const rule of set.mcp_rules) {
					if (!isObject(rule)) throw configInvalid('each `mcp_rules` entry must be an object');
					for (const key of Object.keys(rule)) {
						if (!MCP_RULE_KEYS.includes(key)) {
							throw configInvalid(`unknown field \`${key}\` in \`mcp_rules\``);
						}
					}
				}
			} else {
				throw configInvalid('`mcp_rules` must be an array');
			}
		}
	}
	// query_log is a patch target: keys the candidate leaves out keep their stored value.
	const log = snapshot.control_api_settings?.query_log;
	const storedLog = stored?.control_api_settings?.query_log;
	if (isObject(log) && isObject(storedLog)) {
		for (const [key, value] of Object.entries(storedLog)) {
			if (!(key in log)) log[key] = structuredClone(value);
		}
	}
	if (isObject(log) && 'ip_truncate' in log && !QUERY_LOG_IP_TRUNCATE.includes(log.ip_truncate)) {
		throw configInvalid('`query_log.ip_truncate` must be none, last_octet or last_group');
	}
	return snapshot;
}

/**
 * Cross-module checks. Returns the first blocking error (as PUT reports it) and the warnings, which
 * are only ever produced by the dry run.
 */
function checkCandidate(snapshot) {
	for (const section of REQUIRED_SECTIONS) {
		if (!(section in snapshot)) {
			return {
				error: {
					code: 'control_api.config.invalid',
					path: null,
					params: { reason: `missing section \`${section}\`` },
				},
				warnings: [],
			};
		}
	}
	const sets = Array.isArray(snapshot.filtering.sets) ? snapshot.filtering.sets : [];
	const setIds = new Set(sets.map((set) => set.id));
	const profiles = Array.isArray(snapshot.policy.profiles) ? snapshot.policy.profiles : [];
	let error = null;
	profiles.forEach((profile, index) => {
		if (error || setIds.has(profile.filter_set)) return;
		const path = `policy.profiles[${index}].filter_set`;
		error = {
			code: 'policy.config.unknown_filter_set',
			path,
			params: { path, filter_set: profile.filter_set },
		};
	});
	const warnings = [];
	sets.forEach((set, index) => {
		if (Array.isArray(set.lists) && set.lists.length === 0) {
			const path = `filtering.sets[${index}].lists`;
			warnings.push({ code: 'filtering.config.no_lists', path, params: { path } });
		}
	});
	return { error, warnings };
}

/** Section and sub-key diff, the same shape and naming rules as config_apply.rs diff_snapshots. */
function diffSnapshots(previous, next) {
	const before = previous ?? {};
	const after = next ?? {};
	const changedSections = [];
	const added = [];
	const removed = [];
	const changed = [];
	for (const name of [...new Set([...Object.keys(before), ...Object.keys(after)])].sort()) {
		const a = before[name];
		const b = after[name];
		if (JSON.stringify(a) === JSON.stringify(b)) continue;
		changedSections.push(name);
		if (a === undefined) {
			added.push(name);
		} else if (b === undefined) {
			removed.push(name);
		} else if (isObject(a) && isObject(b)) {
			for (const key of [...new Set([...Object.keys(a), ...Object.keys(b)])].sort()) {
				const path = `${name}.${key}`;
				if (a[key] === undefined && b[key] !== undefined) added.push(path);
				else if (a[key] !== undefined && b[key] === undefined) removed.push(path);
				else if (JSON.stringify(a[key]) !== JSON.stringify(b[key])) changed.push(path);
			}
		} else {
			changed.push(name);
		}
	}
	return { changed_sections: changedSections, added, removed, changed };
}

const EMPTY_DIFF = { changed_sections: [], added: [], removed: [], changed: [] };

/** Trimmed label, or null when empty. Mirrors the API rule: 1..64 characters. */
function clientIdLabel(value) {
	if (value === null || value === undefined) return null;
	const label = String(value).trim();
	if (label === '') return null;
	if (Array.from(label).length > 64)
		throw new ApiFailure(400, 'policy.config.invalid', {
			reason: 'client_id_label',
			field: 'label',
		});
	return label;
}

function clientIdDevice(value) {
	if (value === null || value === undefined || value === '') return null;
	return String(value).slice(0, 128);
}

/** A pinned Netzbereich must exist in the candidate config; null (or '') clears the pin. */
function clientIdView(value, config) {
	if (value === null || value === undefined || value === '') return null;
	const id = String(value);
	if (!(config.policy.views ?? []).some((view) => view.id === id)) {
		throw new ApiFailure(400, 'policy.config.invalid', { reason: 'view_unknown', field: 'view' });
	}
	return id;
}

/** Labels are unique case-insensitively; `ownId` is the entry being renamed (it may keep its label). */
function labelTaken(ids, label, ownId) {
	const wanted = label.toLowerCase();
	return ids.some((item) => item.id !== ownId && (item.label ?? '').toLowerCase() === wanted);
}

function policyConfig(store) {
	return currentOf(store).config.policy ?? {};
}

function filteringConfig(store) {
	return currentOf(store).config.filtering ?? {};
}

function clientsConfig(store) {
	return currentOf(store).config.clients ?? { manual: [] };
}

function replaceConfig(store, config) {
	const version = appendVersion(store, config);
	return version;
}

function upsertId(list, id, value) {
	const index = list.findIndex((item) => item?.id === id);
	if (index >= 0) list[index] = value;
	else list.push(value);
}

function testQuerySteps(domain) {
	return [
		{
			stage: 'select',
			verdict: 'selected',
			selection: { cause: 'subnet', prefix: '192.0.2.0/24' },
		},
		domain.includes('ads')
			? { stage: 'filter_qname', verdict: 'blocked' }
			: { stage: 'resolve', verdict: 'resolved', source: 'recursion' },
	];
}

/** Attached Domain-Zonen from TLS config (`public_domain` + `dns_provider.zones`). */
function attachedDomainZones(tls, hasToken) {
	const zones = [];
	const publicDomain = typeof tls.public_domain === 'string' ? tls.public_domain.trim() : '';
	const provider = isObject(tls.dns_provider) ? tls.dns_provider : {};
	const cf = isObject(provider.cloudflare) ? provider.cloudflare : {};
	const publicZoneId =
		typeof cf.zone_id === 'string' && cf.zone_id.trim() !== '' ? cf.zone_id.trim() : null;
	if (publicDomain) {
		zones.push({
			id: publicZoneId,
			name: publicDomain,
			status: hasToken ? 'active' : null,
			name_servers: hasToken ? ['ada.ns.cloudflare.com', 'bob.ns.cloudflare.com'] : [],
			source: 'public_domain',
		});
	}
	for (const entry of Array.isArray(provider.zones) ? provider.zones : []) {
		if (!isObject(entry) || typeof entry.name !== 'string' || entry.name.trim() === '') continue;
		const name = entry.name.trim();
		if (publicDomain && name.toLowerCase() === publicDomain.toLowerCase()) continue;
		zones.push({
			id: typeof entry.zone_id === 'string' && entry.zone_id.trim() !== '' ? entry.zone_id : null,
			name,
			status: hasToken ? 'active' : null,
			name_servers: hasToken ? ['ada.ns.cloudflare.com'] : [],
			source: 'dns_provider',
		});
	}
	return zones;
}

/**
 * Seed Cloudflare DNS records for the mock public domain.
 * Includes the Split-DNS example `nas.example.test` (LAN override lives in policy.records).
 */
function seedDomainZoneRecords(tls) {
	const publicDomain = typeof tls.public_domain === 'string' ? tls.public_domain.trim() : '';
	const apex = publicDomain || 'example.test';
	return [
		{
			id: 'cf-rec-nas-a',
			name: `nas.${apex}`,
			record_type: 'A',
			content: '203.0.113.10',
			ttl: 60,
			proxied: false,
		},
		{
			id: 'cf-rec-ns1-a',
			name: `ns1.dns.${apex}`,
			record_type: 'A',
			content: '192.0.2.10',
			ttl: 120,
			proxied: false,
		},
		{
			id: 'cf-rec-wildcard-cname',
			name: `*.dns.${apex}`,
			record_type: 'CNAME',
			content: `ns1.dns.${apex}`,
			ttl: 120,
			proxied: false,
		},
	];
}

const PUBLIC_RECORD_TYPES = new Set(['A', 'AAAA', 'CNAME', 'TXT', 'MX', 'SRV']);

function requireCloudflareToken(runtime) {
	if (!runtime.cloudflareApiToken) {
		throw new ApiFailure(400, 'tls.secret.missing', {
			name: 'DNSCRAFT_CLOUDFLARE_API_TOKEN',
		});
	}
}

function attachedZoneById(tls, zoneId) {
	return attachedDomainZones(tls, true).find((zone) => zone.id === zoneId) ?? null;
}

function normalizeOwnerName(name) {
	return String(name ?? '')
		.trim()
		.replace(/\.+$/, '');
}

const PUBLIC_ROUTES = new Set(['POST /api/v1/auth/local/login']);
/** Writes a viewer may send: the sign-out, and the dry-run reads that are POSTs by path. */
const VIEWER_POSTS = new Set([
	'POST /api/v1/auth/logout',
	'POST /api/v1/filtering/explain-block',
	'POST /api/v1/policy/test-query',
]);

async function route(request, response, options) {
	const url = new URL(request.url, 'http://127.0.0.1');
	const path = url.pathname;
	const key = `${request.method} ${path}`;

	if (key === 'GET /readyz') return sendData(response, { ready: true });
	if (!path.startsWith('/api/v1/')) throw new ApiFailure(404, 'control_api.not_found');

	const mutating = request.method !== 'GET' && request.method !== 'HEAD';
	if (mutating && !PUBLIC_ROUTES.has(key)) {
		if (request.headers['x-csrf-token'] !== MOCK_CSRF_TOKEN) {
			throw new ApiFailure(403, 'control_api.auth.csrf');
		}
		if (options.role !== 'admin' && !VIEWER_POSTS.has(key)) {
			throw new ApiFailure(403, 'control_api.auth.insufficient_scope', { required: 'admin' });
		}
	}

	// Configuration family: admin only for reads and writes (roles.rs is_config_path).
	if (
		(path === '/api/v1/config' || path.startsWith('/api/v1/config/')) &&
		options.role !== 'admin'
	) {
		throw new ApiFailure(403, 'control_api.auth.insufficient_scope', { required: 'admin' });
	}

	const principal = { role: options.role, actor_id: 'mock-admin', actor_type: 'user' };
	switch (key) {
		case 'GET /api/v1/auth/me':
			return sendData(response, { ...principal, csrf_token: MOCK_CSRF_TOKEN });
		case 'POST /api/v1/auth/local/login': {
			const body = await readJsonBody(request);
			if (typeof body.username !== 'string' || body.username === '') {
				throw new ApiFailure(401, 'control_api.auth.local');
			}
			return sendData(response, {
				role: options.role,
				actor_id: body.username,
				csrf_token: MOCK_CSRF_TOKEN,
			});
		}
		case 'POST /api/v1/auth/logout':
			return sendData(response, {});
		case 'GET /api/v1/status':
			return sendData(response, {
				version: 'mock',
				ready: true,
				modules_not_ready: [],
				tls_mode: 'acme',
				tls_fingerprint: '',
				tls: { identifiers: ['dns.example.test'] },
				cluster: {
					role: 'master',
					master_reachable: true,
					applied_version: 12,
					lag: 0,
					queue_depth: 0,
					last_sync: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
					degraded_nodes: 1,
				},
			});
		case 'GET /api/v1/stats/overview':
			return sendData(response, overview(url.searchParams));
		case 'GET /api/v1/stats/top_domains': {
			const limit = Number(url.searchParams.get('limit') ?? 10);
			const rows = groupCounts(
				selectRecords({
					...parseWindow(url.searchParams),
					...emptyFilter(),
					order_by: 'time',
					order: 'desc',
				}),
				(record) => ({ id: record.query.name, domain: record.query.name }),
			);
			return sendData(response, {
				domains: rows
					.slice(0, limit)
					.map(({ domain, queries, blocked }) => ({ domain, queries, blocked })),
			});
		}
		case 'GET /api/v1/stats/top_clients': {
			const limit = Number(url.searchParams.get('limit') ?? 10);
			const rows = groupCounts(
				selectRecords({
					...parseWindow(url.searchParams),
					...emptyFilter(),
					order_by: 'time',
					order: 'desc',
				}),
				(record) => ({
					id: record.client_id ?? record.source_ip,
					client_id: record.client_id ?? record.source_ip,
					client_name: record.client?.display_name ?? '',
				}),
			);
			return sendData(response, {
				clients: rows.slice(0, limit).map(({ client_id, client_name, queries, blocked }) => ({
					client_id,
					client_name,
					queries,
					blocked,
				})),
			});
		}
		case 'GET /api/v1/stats/cache': {
			const rows = selectRecords({
				...parseWindow(url.searchParams),
				...emptyFilter(),
				order_by: 'time',
				order: 'desc',
			});
			// Mirrors stats.rs cache_stats: each resolve step counts once; source cache is a hit,
			// any other source (recursion, stale) a miss. Steps without a source are not counted.
			const sources = rows.flatMap((record) =>
				record.steps.filter((step) => step.stage === 'resolve').map((step) => step.source),
			);
			const hits = sources.filter((source) => source === 'cache').length;
			const misses = sources.filter((source) => source != null && source !== 'cache').length;
			return sendData(response, {
				hits,
				misses,
				hit_ratio: hits + misses === 0 ? 0 : hits / (hits + misses),
			});
		}
		case 'GET /api/v1/resolver/upstreams':
			return sendData(response, {
				window_seconds: 300,
				items: [
					{
						name: 'dns.quad9.net',
						kind: 'forward_target',
						zone: '.',
						protocol: 'dot',
						state: 'up',
						rtt_ms: { p50: 18, p95: 41 },
						success_rate: 0.9997,
						samples: 40,
						last_error: null,
						last_checked: null,
					},
					{
						name: 'dns.google',
						kind: 'forward_target',
						zone: '.',
						protocol: 'doh',
						state: 'up',
						rtt_ms: { p50: 26, p95: 58 },
						success_rate: 0.9994,
						samples: 36,
						last_error: null,
						last_checked: null,
					},
					{
						name: 'recursion',
						kind: 'recursion',
						zone: null,
						protocol: 'udp',
						state: 'degraded',
						rtt_ms: { p50: 22, p95: 120 },
						success_rate: 0.97,
						samples: 1184,
						last_error: { code: 'resolver.timeout' },
						last_checked: null,
					},
				],
			});
		case 'POST /api/v1/resolver/cache/flush': {
			const body = await readJsonBody(request);
			return sendData(response, {
				scope: body.domain ? 'domain' : 'all',
				domain: body.domain ?? null,
				evicted: 0,
			});
		}
		case 'POST /api/v1/filtering/pause': {
			const body = await readJsonBody(request);
			const seconds = DURATIONS[body.duration];
			if (seconds === undefined) throw new ApiFailure(400, 'mcp.invalid_input');
			const paused_until = new Date(Date.now() + seconds * 1000).toISOString();
			options.runtime.pauseUntil = paused_until;
			options.runtime.pauseSet = body.filter_set_id ?? 'default';
			return sendData(response, {
				filter_set_id: body.filter_set_id ?? 'default',
				paused_until,
			});
		}
		case 'POST /api/v1/filtering/temporary-allows': {
			const body = await readJsonBody(request);
			if (
				typeof body.domain !== 'string' ||
				body.domain === '' ||
				typeof body.include_subdomains !== 'boolean'
			) {
				throw new ApiFailure(400, 'mcp.invalid_input');
			}
			const seconds = DURATIONS[body.duration];
			if (seconds === undefined) throw new ApiFailure(400, 'mcp.invalid_input');
			const now = Date.now();
			return sendData(response, {
				domain: body.domain.toLowerCase().replace(/\.$/, ''),
				include_subdomains: body.include_subdomains,
				created_at: new Date(now).toISOString(),
				expires_at: new Date(now + seconds * 1000).toISOString(),
				filter_set_id: body.filter_set_id ?? 'default',
			});
		}
		case 'GET /api/v1/config': {
			const current = currentOf(options.store);
			return sendData(response, { version: current.version, config: current.config });
		}
		case 'PUT /api/v1/config': {
			const body = await readConfigBody(request);
			const current = currentOf(options.store);
			if (ifMatchProblem(request.headers['if-match'], current.version)) {
				throw new ApiFailure(409, 'control_api.config.version');
			}
			const snapshot = mergeCandidate(body, current.config);
			const { error } = checkCandidate(snapshot);
			if (error) throw new ApiFailure(400, error.code, error.params ?? {});
			return sendData(response, { version: appendVersion(options.store, snapshot) });
		}
		case 'POST /api/v1/config/validate': {
			// A dry run: nothing is stored, applied or audited, and the version does not move.
			const body = await readConfigBody(request);
			const current = currentOf(options.store);
			const errors = [];
			if (ifMatchProblem(request.headers['if-match'], current.version)) {
				errors.push({ code: 'control_api.config.version', path: null, params: null });
			}
			let diff = EMPTY_DIFF;
			let warnings = [];
			try {
				const snapshot = mergeCandidate(body, current.config);
				const checked = checkCandidate(snapshot);
				if (checked.error) errors.push(checked.error);
				warnings = checked.warnings;
				diff = diffSnapshots(current.config, snapshot);
			} catch (failure) {
				if (!(failure instanceof ApiFailure)) throw failure;
				errors.push({ code: failure.code, path: null, params: failure.params });
			}
			return sendData(response, {
				valid: errors.length === 0,
				config_version: current.version,
				errors: errors.map((entry) => ({
					...entry,
					path: entry.path ?? entry.params?.path ?? null,
				})),
				warnings,
				diff,
			});
		}
		case 'GET /api/v1/config/versions': {
			const limit = parseCount('limit', url.searchParams.get('limit') ?? '50', 1);
			const offset = parseCount('offset', url.searchParams.get('offset') ?? '0', 0);
			const rows = [...options.store.versions].reverse();
			const hasMore = rows.length > offset + limit;
			return sendData(response, {
				current_version: currentOf(options.store).version,
				versions: rows
					.slice(offset, offset + limit)
					.map(({ version, created_at }) => ({ version, created_at: rfc3339(created_at) })),
				has_more: hasMore,
				next_offset: hasMore ? offset + limit : null,
			});
		}
		case 'GET /api/v1/query-log':
			return sendData(response, listPage(url.searchParams));
		case 'GET /api/v1/query-log/export.ndjson': {
			const rows = selectRecords(parseQuery(url.searchParams));
			const body = rows.map((record) => JSON.stringify(record)).join('\n');
			return send(response, 200, body === '' ? '' : `${body}\n`, {
				'Content-Type': 'application/x-ndjson; charset=utf-8',
				'Content-Disposition': 'attachment; filename="query-log.ndjson"',
			});
		}
		case 'GET /api/v1/query-log/export.csv': {
			const rows = selectRecords(parseQuery(url.searchParams));
			const lines = [CSV_COLUMNS.join(','), ...rows.map(csvLine)];
			return send(response, 200, `${lines.join('\n')}\n`, {
				'Content-Type': 'text/csv; charset=utf-8',
				'Content-Disposition': 'attachment; filename="query-log.csv"',
			});
		}
		case 'GET /api/v1/query-log/stream': {
			// WX2 live tail for local UI work: periodic synthetic rows, same filters as the list.
			response.writeHead(200, {
				...BASE_SECURITY_HEADERS,
				'Content-Type': 'text/event-stream',
				'Cache-Control': 'no-store',
				'X-Accel-Buffering': 'no',
			});
			response.write(': open\n\n');
			const filter = parseQuery(url.searchParams);
			const tick = setInterval(() => {
				const base = selectRecords(filter)[0] ?? RECORDS[0];
				if (!base || response.writableEnded) return;
				const now = Date.now();
				const record = {
					...base,
					id: `live-${now}`,
					time: new Date(now).toISOString(),
					query: { ...base.query, name: `live-${now}.example` },
				};
				response.write(`event: row\ndata: ${JSON.stringify(record)}\n\n`);
			}, 2_000);
			const ping = setInterval(() => {
				if (!response.writableEnded) response.write(': ping\n\n');
			}, 15_000);
			const stop = () => {
				clearInterval(tick);
				clearInterval(ping);
			};
			request.on('close', stop);
			response.on('close', stop);
			return;
		}
		case 'GET /api/v1/policy/views':
			return sendData(response, { views: policyConfig(options.store).views ?? [] });
		case 'GET /api/v1/policy/records':
			return sendData(response, { records: policyConfig(options.store).records ?? [] });
		case 'GET /api/v1/policy/client-ids':
			return sendData(response, {
				client_ids: (policyConfig(options.store).client_ids ?? []).map((entry) => ({
					view: null,
					...entry,
				})),
			});
		case 'GET /api/v1/clients':
			return sendData(response, {
				clients: MOCK_DIRECTORY_CLIENTS,
				manual: clientsConfig(options.store).manual ?? [],
			});
		case 'GET /api/v1/filter-sets':
			return sendData(response, { filter_sets: filteringConfig(options.store).sets ?? [] });
		case 'GET /api/v1/filter-lists':
			return sendData(response, {
				filter_lists: (filteringConfig(options.store).lists ?? []).map(withListStatus),
			});
		case 'POST /api/v1/clients/sync':
			return sendData(response, {
				generation: 2,
				rebuilt: true,
				client_count: MOCK_DIRECTORY_CLIENTS.length,
				ip_conflicts: 0,
			});
		case 'GET /api/v1/clients/unifi': {
			const clients = clientsConfig(options.store);
			const profiles = (clients.unifi_profiles ?? []).map((profile) => ({
				...profile,
				has_api_key: Boolean(options.runtime.unifiApiKeys?.[profile.id]),
			}));
			return sendData(response, {
				profiles,
				bindings: clients.unifi_bindings ?? {},
				local_domain: clients.local_domain,
				local_domain_mode: clients.local_domain_mode,
			});
		}
		case 'POST /api/v1/policy/test-query': {
			const body = await readJsonBody(request);
			return sendData(response, {
				steps: testQuerySteps(String(body.domain ?? '')),
				view_id: 'lan',
				profile_id: 'default',
				rcode: 'NOERROR',
				answer: { rcode: 'NOERROR', records: [] },
			});
		}
		case 'GET /api/v1/listeners':
			return sendData(response, {
				listeners: currentOf(options.store).config.listeners?.listeners ?? [],
			});
		case 'GET /api/v1/tls':
			return sendData(response, {
				tls: currentOf(options.store).config.tls ?? {},
				has_cloudflare_token: Boolean(options.runtime.cloudflareApiToken),
			});
		case 'GET /api/v1/tls/status':
			return sendData(response, {
				mode: 'self_signed',
				fingerprint_sha256: '3a9c7f11de420b886501ee2a94c30d77'.padEnd(64, '0'),
				not_before: '2026-10-26T11:02:00Z',
				not_after: '2027-01-15T00:00:00Z',
				days_to_expiry: 79,
				identifiers: ['dns.example.test', '*.dns.example.test'],
				issuer: 'DNScraft (self-signed)',
				subject: 'dns.example.test',
				key_type: 'ECDSA P-256',
				last_issue: '2026-10-26T11:02:00Z',
				last_renew_attempt: null,
				last_error: null,
				self_signed: true,
				dyndns_ipv4: '192.0.2.10',
				dyndns_ipv6: '2001:db8:8f3a:1:a00:27ff:fe4e:66a1',
				last_dyndns_success: new Date(Date.now() - 5 * 60_000).toISOString(),
			});
		case 'POST /api/v1/tls/renew':
			return sendData(response, { started: true });
		case 'POST /api/v1/tls/rotate':
			return sendData(response, { rotated: true });
		case 'POST /api/v1/tls/preflight':
			return sendData(response, { ok: true, checks: [] });
		case 'POST /api/v1/tls/dyndns':
			return sendData(response, { updated: true });
		case 'POST /api/v1/tls/revoke': {
			await readJsonBody(request);
			return sendData(response, { revoked: true });
		}
		case 'PUT /api/v1/tls/certificate': {
			await readJsonBody(request);
			return sendData(response, { mode: 'manual' });
		}
		case 'PUT /api/v1/tls/cloudflare-token': {
			const body = await readJsonBody(request);
			if (!Object.prototype.hasOwnProperty.call(body, 'api_token')) {
				return sendData(response, { updated: false });
			}
			if (body.api_token === null) {
				options.runtime.cloudflareApiToken = null;
				return sendData(response, { updated: true, has_cloudflare_token: false });
			}
			const token = String(body.api_token ?? '');
			if (!token) {
				throw new ApiFailure(400, 'tls.config.invalid', {
					reason: 'api_token must not be empty; use null to clear',
				});
			}
			options.runtime.cloudflareApiToken = token;
			return sendData(response, { updated: true, has_cloudflare_token: true });
		}
		case 'GET /api/v1/domain-zones': {
			const tls = currentOf(options.store).config.tls ?? {};
			const hasToken = Boolean(options.runtime.cloudflareApiToken);
			const zones = attachedDomainZones(tls, hasToken);
			const payload = { zones, has_cloudflare_token: hasToken };
			const discover = url.searchParams.get('discover');
			if (discover === '1' || discover === 'true' || discover === 'yes' || discover === 'on') {
				if (options.role !== 'admin') {
					throw new ApiFailure(403, 'control_api.auth.insufficient_scope', {
						required: 'admin',
					});
				}
				if (!hasToken) {
					throw new ApiFailure(400, 'tls.secret.missing', {
						name: 'DNSCRAFT_CLOUDFLARE_API_TOKEN',
					});
				}
				payload.discoverable = [
					...zones,
					{
						id: 'zone-unattached',
						name: 'other.example',
						status: 'active',
						name_servers: ['ada.ns.cloudflare.com'],
						source: 'discoverable',
					},
				];
			}
			return sendData(response, payload);
		}
		case 'POST /api/v1/domain-zones/attach': {
			const body = await readJsonBody(request);
			const name = normalizeOwnerName(body.name).toLowerCase();
			if (!name) throw new ApiFailure(400, 'tls.config.invalid', { reason: 'name is required' });
			const config = structuredClone(currentOf(options.store).config);
			config.tls = config.tls ?? {};
			config.tls.dns_provider = isObject(config.tls.dns_provider)
				? config.tls.dns_provider
				: { kind: 'cloudflare', cloudflare: {}, zones: [], manual_txt: [] };
			const provider = config.tls.dns_provider;
			provider.zones = Array.isArray(provider.zones) ? provider.zones : [];
			const publicDomain =
				typeof config.tls.public_domain === 'string' ? config.tls.public_domain.trim() : '';
			if (publicDomain && name === publicDomain.toLowerCase()) {
				throw new ApiFailure(400, 'tls.config.invalid', { reason: 'already_public_domain' });
			}
			if (
				provider.zones.some(
					(entry) => isObject(entry) && String(entry.name ?? '').toLowerCase() === name,
				)
			) {
				throw new ApiFailure(400, 'tls.config.invalid', { reason: 'already_attached' });
			}
			const zoneId =
				typeof body.zone_id === 'string' && body.zone_id.trim() !== ''
					? body.zone_id.trim()
					: `zone-${name.replace(/\./g, '-')}`;
			if (!body.zone_id) requireCloudflareToken(options.runtime);
			provider.zones.push({ name, zone_id: zoneId });
			replaceConfig(options.store, config);
			return sendData(response, {
				id: zoneId,
				name,
				status: 'active',
				name_servers: ['ada.ns.cloudflare.com'],
				source: 'dns_provider',
			});
		}
		case 'GET /api/v1/update/check':
			return sendData(response, {
				enabled: true,
				current: '0.1.0-mock',
				latest: '0.2.0-mock',
				update_available: true,
				release_url: 'https://example.com/releases/0.2.0',
				checked_at: new Date().toISOString(),
			});
		case 'GET /api/v1/audit': {
			if (options.role !== 'admin') {
				throw new ApiFailure(403, 'control_api.auth.insufficient_scope', { required: 'admin' });
			}
			const limit = parseCount('limit', url.searchParams.get('limit') ?? '50', 1);
			const offset = parseCount('offset', url.searchParams.get('offset') ?? '0', 0);
			return sendData(response, { audit: MOCK_AUDIT.slice(offset, offset + limit) });
		}
		case 'GET /api/v1/auth/tokens': {
			if (options.role !== 'admin') {
				throw new ApiFailure(403, 'control_api.auth.insufficient_scope', { required: 'admin' });
			}
			return sendData(response, { tokens: options.runtime.tokens });
		}
		case 'POST /api/v1/auth/tokens': {
			const body = await readJsonBody(request);
			const id = `tok-${++options.runtime.tokenSerial}`.padEnd(16, '0');
			const row = {
				id,
				name: String(body.name ?? 'token'),
				scope: String(body.scope ?? 'viewer'),
				actor_id: principal.actor_id,
				created_at: new Date().toISOString(),
				expires_at: null,
			};
			options.runtime.tokens.push(row);
			return sendData(response, {
				...row,
				token: `plaintext-${id}-not-a-secret`,
				warnings: ['control_api.tls.self_signed'],
			});
		}
		case 'GET /api/v1/cluster/nodes': {
			if (options.role !== 'admin') {
				throw new ApiFailure(403, 'control_api.auth.insufficient_scope', { required: 'admin' });
			}
			return sendData(response, options.runtime.clusterNodes);
		}
		case 'POST /api/v1/cluster/join-tokens': {
			const body = await readJsonBody(request);
			return sendData(response, {
				token: `join-${String(body.node_id ?? 'node')}-one-time`,
				expires_at: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
			});
		}
		case 'GET /api/v1/filtering/mcp-rules': {
			const kind = url.searchParams.get('kind') ?? 'rules';
			const filterSetId = url.searchParams.get('filter_set_id') ?? 'default';
			const sets = filteringConfig(options.store).sets ?? [];
			const set = sets.find((item) => item.id === filterSetId) ?? sets[0];
			const rules = (set?.mcp_rules ?? []).map((rule) => ({
				...rule,
				rule_text: `${rule.include_subdomains ? '||' : '|'}${rule.domain}^`,
				filter_set_id: set.id,
			}));
			if (kind === 'temporary_allows') {
				const now = Date.now();
				const setId = set?.id ?? 'default';
				return sendData(response, {
					filter_set_id: setId,
					kind,
					temporary_allows: MOCK_TEMPORARY_ALLOWS.filter(
						(allow) => allow.filter_set_id === setId,
					).map((allow) => ({
						domain: allow.domain,
						include_subdomains: allow.include_subdomains,
						created_at: new Date(now - 60_000).toISOString(),
						expires_at: new Date(now + allow.minutes * 60_000).toISOString(),
						filter_set_id: setId,
					})),
					has_more: false,
					next_offset: null,
				});
			}
			if (kind === 'pauses') {
				return sendData(response, {
					filter_set_id: set?.id ?? 'default',
					kind,
					pauses:
						options.runtime.pauseUntil && options.runtime.pauseSet === (set?.id ?? 'default')
							? [
									{
										filter_set_id: set?.id ?? 'default',
										paused_until: options.runtime.pauseUntil,
									},
								]
							: [],
					has_more: false,
					next_offset: null,
				});
			}
			return sendData(response, {
				filter_set_id: set?.id ?? 'default',
				kind: 'rules',
				rules,
				has_more: false,
				next_offset: null,
			});
		}
		case 'POST /api/v1/filtering/resume':
			options.runtime.pauseUntil = null;
			return sendData(response, { filter_set_id: 'default' });
		case 'DELETE /api/v1/filtering/custom-rules': {
			const body = await readJsonBody(request);
			const config = structuredClone(currentOf(options.store).config);
			for (const set of config.filtering.sets ?? []) {
				if (set.id !== (body.filter_set_id ?? 'default')) continue;
				set.mcp_rules = (set.mcp_rules ?? []).filter((rule) => rule.domain !== body.domain);
			}
			replaceConfig(options.store, config);
			return sendData(response, {
				removed: true,
				domain: body.domain,
				filter_set_id: body.filter_set_id ?? 'default',
			});
		}
		default:
			break;
	}

	const domainZoneAttach = /^\/api\/v1\/domain-zones\/attach\/([^/]+)$/.exec(path);
	if (domainZoneAttach && request.method === 'DELETE') {
		const apex = decodeURIComponent(domainZoneAttach[1]).trim().toLowerCase();
		if (!apex) throw new ApiFailure(400, 'tls.config.invalid', { reason: 'apex is required' });
		const config = structuredClone(currentOf(options.store).config);
		config.tls = config.tls ?? {};
		const publicDomain =
			typeof config.tls.public_domain === 'string' ? config.tls.public_domain.trim() : '';
		if (publicDomain && apex === publicDomain.toLowerCase()) {
			throw new ApiFailure(400, 'tls.config.invalid', { reason: 'cannot_detach_public_domain' });
		}
		const provider = isObject(config.tls.dns_provider) ? config.tls.dns_provider : null;
		if (!provider) throw new ApiFailure(404, 'control_api.not_found');
		const before = Array.isArray(provider.zones) ? provider.zones.length : 0;
		provider.zones = (provider.zones ?? []).filter(
			(entry) => !(isObject(entry) && String(entry.name ?? '').toLowerCase() === apex),
		);
		if (provider.zones.length === before) throw new ApiFailure(404, 'control_api.not_found');
		replaceConfig(options.store, config);
		return sendData(response, { detached: true, name: apex });
	}

	const domainZoneRecords = /^\/api\/v1\/domain-zones\/([^/]+)\/records$/.exec(path);
	if (domainZoneRecords) {
		const zoneId = decodeURIComponent(domainZoneRecords[1]);
		requireCloudflareToken(options.runtime);
		const tls = currentOf(options.store).config.tls ?? {};
		if (!attachedZoneById(tls, zoneId)) {
			throw new ApiFailure(404, 'control_api.not_found');
		}
		if (!Array.isArray(options.runtime.domainZoneRecords)) {
			options.runtime.domainZoneRecords = seedDomainZoneRecords(tls);
		}
		const records = options.runtime.domainZoneRecords;

		if (request.method === 'GET') {
			const needle = (url.searchParams.get('name_substr') ?? '').trim().toLowerCase();
			let filtered = records;
			if (needle) {
				filtered = records.filter((row) => row.name.toLowerCase().includes(needle));
			}
			const page = Math.max(1, Number(url.searchParams.get('page') ?? 1) || 1);
			const perPage = Math.min(
				100,
				Math.max(1, Number(url.searchParams.get('per_page') ?? 50) || 50),
			);
			const totalCount = filtered.length;
			const totalPages = totalCount === 0 ? 0 : Math.ceil(totalCount / perPage);
			const start = (page - 1) * perPage;
			return sendData(response, {
				records: filtered.slice(start, start + perPage),
				page,
				per_page: perPage,
				total_count: totalCount,
				total_pages: totalPages,
			});
		}

		if (request.method === 'POST') {
			const body = await readJsonBody(request);
			const recordType = String(body.type ?? body.record_type ?? '')
				.trim()
				.toUpperCase();
			const name = normalizeOwnerName(body.name);
			const content = String(body.content ?? '').trim();
			if (!name || !content) {
				throw new ApiFailure(400, 'tls.config.invalid', { reason: 'name and content required' });
			}
			if (!PUBLIC_RECORD_TYPES.has(recordType)) {
				throw new ApiFailure(400, 'control_api.config.invalid', { reason: 'unsupported_type' });
			}
			const ttl =
				typeof body.ttl === 'number' && Number.isFinite(body.ttl) ? Number(body.ttl) : 1;
			const row = {
				id: `cf-rec-${++options.runtime.domainZoneRecordSerial}`,
				name,
				record_type: recordType,
				content,
				ttl,
				proxied: body.proxied === true,
			};
			records.push(row);
			return sendData(response, row);
		}

		if (request.method === 'PUT') {
			const body = await readJsonBody(request);
			const id = String(body.id ?? '').trim();
			if (!id) throw new ApiFailure(400, 'tls.config.invalid', { reason: 'id is required' });
			const index = records.findIndex((row) => row.id === id);
			if (index < 0) throw new ApiFailure(404, 'control_api.not_found');
			const recordType = String(body.type ?? body.record_type ?? records[index].record_type)
				.trim()
				.toUpperCase();
			if (!PUBLIC_RECORD_TYPES.has(recordType)) {
				throw new ApiFailure(400, 'control_api.config.invalid', { reason: 'unsupported_type' });
			}
			const name = normalizeOwnerName(body.name) || records[index].name;
			const content = String(body.content ?? '').trim();
			if (!content) {
				throw new ApiFailure(400, 'tls.config.invalid', { reason: 'content is required' });
			}
			const ttl =
				typeof body.ttl === 'number' && Number.isFinite(body.ttl)
					? Number(body.ttl)
					: records[index].ttl;
			const row = {
				id,
				name,
				record_type: recordType,
				content,
				ttl,
				proxied: body.proxied === true,
			};
			records[index] = row;
			return sendData(response, row);
		}

		if (request.method === 'DELETE') {
			const body = await readJsonBody(request);
			const id = String(body.id ?? '').trim();
			if (!id) throw new ApiFailure(400, 'tls.config.invalid', { reason: 'id is required' });
			const before = records.length;
			options.runtime.domainZoneRecords = records.filter((row) => row.id !== id);
			if (options.runtime.domainZoneRecords.length === before) {
				throw new ApiFailure(404, 'control_api.not_found');
			}
			return sendData(response, { deleted: true, id });
		}
	}

	const policyView = /^\/api\/v1\/policy\/views\/([^/]+)$/.exec(path);
	if (policyView) {
		const id = decodeURIComponent(policyView[1]);
		const views = policyConfig(options.store).views ?? [];
		if (request.method === 'GET') {
			const view = views.find((item) => item.id === id);
			if (!view) throw new ApiFailure(404, 'control_api.not_found');
			return sendData(response, { view });
		}
		if (request.method === 'PUT' || request.method === 'POST') {
			const body = await readJsonBody(request);
			const config = structuredClone(currentOf(options.store).config);
			config.policy.views = [...(config.policy.views ?? [])];
			upsertId(config.policy.views, id, { ...body, id });
			const version = replaceConfig(options.store, config);
			const view = config.policy.views.find((item) => item.id === id);
			return sendData(response, { version, view });
		}
		if (request.method === 'DELETE') {
			const pinned = (policyConfig(options.store).client_ids ?? [])
				.filter((item) => item.view === id)
				.map((item) => item.id);
			if (pinned.length > 0) {
				throw new ApiFailure(400, 'policy.config.invalid', {
					reason: 'view_in_use',
					view: id,
					client_ids: pinned,
				});
			}
			const config = structuredClone(currentOf(options.store).config);
			config.policy.views = (config.policy.views ?? []).filter((item) => item.id !== id);
			const version = replaceConfig(options.store, config);
			return sendData(response, { version, deleted: true, id });
		}
	}

	const policyProfile = /^\/api\/v1\/policy\/profiles\/([^/]+)$/.exec(path);
	if (policyProfile) {
		const id = decodeURIComponent(policyProfile[1]);
		const profiles = policyConfig(options.store).profiles ?? [];
		if (request.method === 'GET') {
			const profile = profiles.find((item) => item.id === id);
			if (!profile) throw new ApiFailure(404, 'control_api.not_found');
			return sendData(response, { profile });
		}
		if (request.method === 'PUT' || request.method === 'POST') {
			const body = await readJsonBody(request);
			const config = structuredClone(currentOf(options.store).config);
			config.policy.profiles = [...(config.policy.profiles ?? [])];
			upsertId(config.policy.profiles, id, { ...body, id });
			const version = replaceConfig(options.store, config);
			const profile = config.policy.profiles.find((item) => item.id === id);
			return sendData(response, { version, profile });
		}
		if (request.method === 'DELETE') {
			const config = structuredClone(currentOf(options.store).config);
			config.policy.profiles = (config.policy.profiles ?? []).filter((item) => item.id !== id);
			const version = replaceConfig(options.store, config);
			return sendData(response, { version, deleted: true, id });
		}
	}

	if (path === '/api/v1/policy/records' && request.method !== 'GET') {
		const body = await readJsonBody(request);
		const config = structuredClone(currentOf(options.store).config);
		const records = [...(config.policy.records ?? [])];
		if (request.method === 'DELETE') {
			const index = records.findIndex((item) => item.name === body.name && item.type === body.type);
			if (index < 0) throw new ApiFailure(404, 'control_api.not_found');
			records.splice(index, 1);
			config.policy.records = records;
			const version = replaceConfig(options.store, config);
			return sendData(response, {
				version,
				deleted: true,
				name: body.name,
				type: body.type,
			});
		}
		const record = {
			name: body.name,
			type: body.type,
			ttl: body.ttl ?? 60,
			rdata: body.rdata,
			overrides: body.overrides ?? {},
		};
		const index = records.findIndex(
			(item) => item.name === record.name && item.type === record.type,
		);
		if (index >= 0) records[index] = record;
		else records.push(record);
		config.policy.records = records;
		const version = replaceConfig(options.store, config);
		return sendData(response, { version, record });
	}

	if (path === '/api/v1/policy/client-ids' && request.method === 'POST') {
		const body = await readJsonBody(request);
		const config = structuredClone(currentOf(options.store).config);
		const ids = [...(config.policy.client_ids ?? [])];
		const label = clientIdLabel(body.label);
		if (ids.some((item) => item.id === body.id)) {
			throw new ApiFailure(400, 'policy.config.invalid', { reason: 'client_id_exists' });
		}
		if (label !== null && labelTaken(ids, label, body.id)) {
			throw new ApiFailure(400, 'policy.config.invalid', {
				reason: 'client_id_label_taken',
				field: 'label',
			});
		}
		ids.push({
			id: body.id,
			label,
			device: clientIdDevice(body.device),
			view: clientIdView(body.view, config),
		});
		config.policy.client_ids = ids;
		const version = replaceConfig(options.store, config);
		return sendData(response, { version, client_id: body.id });
	}

	const clientIdItem = /^\/api\/v1\/policy\/client-ids\/([^/]+)$/.exec(path);
	if (clientIdItem && request.method === 'PUT') {
		const id = decodeURIComponent(clientIdItem[1]);
		const body = await readJsonBody(request);
		const config = structuredClone(currentOf(options.store).config);
		const ids = [...(config.policy.client_ids ?? [])];
		const index = ids.findIndex((item) => item.id === id);
		if (index < 0) throw new ApiFailure(404, 'control_api.not_found');
		const label = body.label === undefined ? ids[index].label : clientIdLabel(body.label);
		if (label !== null && labelTaken(ids, label, id)) {
			throw new ApiFailure(400, 'policy.config.invalid', {
				reason: 'client_id_label_taken',
				field: 'label',
			});
		}
		const device = body.device === undefined ? ids[index].device : clientIdDevice(body.device);
		const view =
			body.view === undefined ? (ids[index].view ?? null) : clientIdView(body.view, config);
		ids[index] = { id, label, device, view };
		config.policy.client_ids = ids;
		const version = replaceConfig(options.store, config);
		return sendData(response, { version, client_id: id });
	}

	if (clientIdItem && request.method === 'DELETE') {
		const id = decodeURIComponent(clientIdItem[1]);
		const config = structuredClone(currentOf(options.store).config);
		config.policy.client_ids = (config.policy.client_ids ?? []).filter((item) => item.id !== id);
		const version = replaceConfig(options.store, config);
		return sendData(response, { version, deleted: true, id });
	}

	if (path === '/api/v1/clients/manual') {
		const config = structuredClone(currentOf(options.store).config);
		const manual = [...(config.clients.manual ?? [])];
		if (request.method === 'GET') return sendData(response, { manual });
		const body = await readJsonBody(request);
		if (request.method === 'POST') {
			manual.push(body);
			config.clients.manual = manual;
			const version = replaceConfig(options.store, config);
			return sendData(response, { version, entry: body });
		}
		if (request.method === 'PUT') {
			const index = manual.findIndex((item) => item.name === body.name);
			if (index >= 0) manual[index] = body;
			else manual.push(body);
			config.clients.manual = manual;
			const version = replaceConfig(options.store, config);
			return sendData(response, { version, entry: body, created: index < 0 });
		}
		if (request.method === 'DELETE') {
			config.clients.manual = manual.filter((item) => item.name !== body.name);
			const version = replaceConfig(options.store, config);
			return sendData(response, { version, deleted: true, name: body.name });
		}
	}

	if (path === '/api/v1/listeners' && request.method !== 'GET') {
		const body = await readJsonBody(request);
		const config = structuredClone(currentOf(options.store).config);
		const listeners = [...(config.listeners?.listeners ?? [])];
		if (request.method === 'DELETE') {
			config.listeners.listeners = listeners.filter((item) => item.id !== body.id);
			const version = replaceConfig(options.store, config);
			return sendData(response, { version, deleted: true, id: body.id });
		}
		const nodes = Array.isArray(body.nodes)
			? [
					...new Set(
						body.nodes
							.filter((entry) => typeof entry === 'string')
							.map((entry) => entry.trim())
							.filter(Boolean),
					),
				]
			: [];
		const listener = {
			id: body.id,
			protocol: body.protocol,
			address: body.address,
			exposure: body.exposure ?? 'local',
			h3: body.h3 === true,
			nodes,
		};
		const index = listeners.findIndex((item) => item.id === listener.id);
		const created = index < 0;
		if (index >= 0) listeners[index] = listener;
		else listeners.push(listener);
		config.listeners = { listeners };
		const version = replaceConfig(options.store, config);
		return sendData(response, { version, listener, created });
	}

	if (path === '/api/v1/tls' && request.method === 'PUT') {
		const body = await readConfigBody(request);
		const config = structuredClone(currentOf(options.store).config);
		config.tls = body;
		const version = replaceConfig(options.store, config);
		return sendData(response, { version, tls: body });
	}

	const clusterPut = /^\/api\/v1\/cluster\/nodes\/([^/]+)$/.exec(path);
	if (request.method === 'PUT' && clusterPut) {
		const nodeId = decodeURIComponent(clusterPut[1]);
		const body = await readJsonBody(request);
		const display_name = String(body.display_name ?? '').trim() || null;
		const hostname = String(body.hostname ?? '').trim().toLowerCase() || null;
		if (hostname && !/^[a-z0-9-]+(\.[a-z0-9-]+)*$/.test(hostname)) {
			throw new ApiFailure(400, 'cluster.role.invalid');
		}
		options.runtime.clusterNodes = options.runtime.clusterNodes.map((node) =>
			node.node_id === nodeId ? { ...node, display_name, hostname } : node,
		);
		return sendData(response, { node_id: nodeId, display_name, hostname });
	}

	const clusterDelete = /^\/api\/v1\/cluster\/nodes\/([^/]+)$/.exec(path);
	if (request.method === 'DELETE' && clusterDelete) {
		const nodeId = decodeURIComponent(clusterDelete[1]);
		options.runtime.clusterNodes = options.runtime.clusterNodes.map((node) =>
			node.node_id === nodeId ? { ...node, revoked: true } : node,
		);
		return sendData(response, { node_id: nodeId, revoked: true });
	}

	const tokenDelete = /^\/api\/v1\/auth\/tokens\/([^/]+)$/.exec(path);
	if (request.method === 'DELETE' && tokenDelete) {
		if (options.role !== 'admin') {
			throw new ApiFailure(403, 'control_api.auth.insufficient_scope', { required: 'admin' });
		}
		const id = decodeURIComponent(tokenDelete[1]);
		const before = options.runtime.tokens.length;
		options.runtime.tokens = options.runtime.tokens.filter((token) => token.id !== id);
		if (options.runtime.tokens.length === before) {
			throw new ApiFailure(404, 'control_api.auth.unknown_token');
		}
		return sendData(response, { id, revoked: true });
	}

	if (path === '/api/v1/filter-sets' && request.method !== 'GET') {
		const body = await readJsonBody(request);
		const config = structuredClone(currentOf(options.store).config);
		const sets = [...(config.filtering.sets ?? [])];
		if (request.method === 'DELETE') {
			config.filtering.sets = sets.filter((item) => item.id !== body.id);
			const version = replaceConfig(options.store, config);
			return sendData(response, { version, deleted: true, id: body.id });
		}
		const set = { ...body, block_mode: body.block_mode ?? 'refused' };
		const replaced = sets.some((item) => item.id === set.id);
		upsertId(sets, set.id, set);
		config.filtering.sets = sets;
		const version = replaceConfig(options.store, config);
		return sendData(response, { version, filter_set: set, created: !replaced });
	}

	if (path === '/api/v1/filter-lists' && request.method !== 'GET') {
		const body = await readJsonBody(request);
		const config = structuredClone(currentOf(options.store).config);
		const lists = [...(config.filtering.lists ?? [])];
		if (request.method === 'DELETE') {
			config.filtering.lists = lists.filter((item) => item.id !== body.id);
			const version = replaceConfig(options.store, config);
			return sendData(response, { version, deleted: true, id: body.id });
		}
		const list = body;
		const replaced = lists.some((item) => item.id === list.id);
		upsertId(lists, list.id, list);
		config.filtering.lists = lists;
		const version = replaceConfig(options.store, config);
		return sendData(response, { version, filter_list: list, created: !replaced });
	}

	const rollback = /^\/api\/v1\/config\/versions\/([^/]+)\/rollback$/.exec(path);
	if (request.method === 'POST' && rollback) {
		const current = currentOf(options.store);
		if (ifMatchProblem(request.headers['if-match'], current.version)) {
			throw new ApiFailure(409, 'control_api.config.version');
		}
		const target = /^\d+$/.test(rollback[1]) ? Number(rollback[1]) : 0;
		const found = options.store.versions.find((entry) => entry.version === target);
		if (!found) throw new ApiFailure(404, 'control_api.config.unknown_version');
		const version = appendVersion(options.store, structuredClone(found.config));
		return sendData(response, { version, restored_from: target });
	}

	const detail = /^\/api\/v1\/query-log\/([^/]+)$/.exec(path);
	if (request.method === 'GET' && detail) {
		const record = RECORDS.find((item) => item.id === decodeURIComponent(detail[1]));
		if (!record) throw new ApiFailure(404, 'control_api.not_found');
		return sendData(response, record);
	}
	throw new ApiFailure(404, 'control_api.not_found');
}

/** Serves a file under buildDir; anything else that is not an API call falls back to index.html. */
async function serveStatic(request, response, buildDir) {
	const url = new URL(request.url, 'http://127.0.0.1');
	const relative = normalize(decodeURIComponent(url.pathname)).replace(/^[/\\]+/, '');
	const candidate = resolve(buildDir, relative);
	if (candidate !== buildDir && !candidate.startsWith(buildDir + sep)) {
		return send(response, 400, 'Bad request', { 'Content-Type': 'text/plain; charset=utf-8' });
	}
	let file = candidate;
	try {
		if ((await stat(file)).isDirectory()) file = join(file, 'index.html');
	} catch {
		file = join(buildDir, 'index.html');
	}
	try {
		const body = await readFile(file);
		const type = CONTENT_TYPES[extname(file)] ?? 'application/octet-stream';
		const servedPath = file === join(buildDir, 'index.html') ? '/' : url.pathname;
		const security = type.startsWith('text/html')
			? htmlSecurityHeaders(buildDir)
			: BASE_SECURITY_HEADERS;
		return send(response, 200, body, {
			'Content-Type': type,
			'Cache-Control': cacheControlForPath(servedPath),
			...security,
		});
	} catch {
		return send(response, 503, 'The web build is missing. Run `pnpm build` first.', {
			'Content-Type': 'text/plain; charset=utf-8',
		});
	}
}

/** Temporary allows the mock reports as running; `minutes` is counted from each read. */
const MOCK_TEMPORARY_ALLOWS = [
	{
		domain: 'allowed.example.test',
		include_subdomains: false,
		minutes: 4,
		filter_set_id: 'default',
	},
	{ domain: 'zeitung.example.de', include_subdomains: true, minutes: 42, filter_set_id: 'kids' },
];

/** Creates the mock HTTP server. Nothing listens until `listen` is called. */
function createRuntimeState() {
	return {
		clusterNodes: structuredClone(MOCK_CLUSTER_NODES),
		tokens: structuredClone(MOCK_TOKENS),
		tokenSerial: MOCK_TOKENS.length,
		unifiApiKeys: Object.create(null),
		cloudflareApiToken: 'mock-cloudflare-token',
		domainZoneRecords: null,
		domainZoneRecordSerial: 100,
		// One pause running at start (filter set `kids`, 12 minutes), so the Regeln page has one to show.
		pauseUntil: new Date(Date.now() + 12 * 60_000).toISOString(),
		pauseSet: 'kids',
	};
}

export function createMockServer({ buildDir = DEFAULT_BUILD_DIR, role = 'admin' } = {}) {
	const root = resolve(buildDir);
	const store = createConfigStore();
	const runtime = createRuntimeState();
	return createServer(async (request, response) => {
		try {
			if (request.url.startsWith('/api/') || request.url.startsWith('/readyz')) {
				await route(request, response, { role, store, runtime });
			} else {
				await serveStatic(request, response, root);
			}
		} catch (failure) {
			if (failure instanceof ApiFailure) return sendError(response, failure);
			return sendError(response, new ApiFailure(500, 'control_api.internal'));
		}
	});
}

export const MOCK_CSRF = MOCK_CSRF_TOKEN;

// Started directly (pnpm mock), not when imported by the test.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
	const role = process.env.MOCK_ROLE ?? 'admin';
	if (role !== 'admin' && role !== 'viewer') {
		console.error('MOCK_ROLE must be admin or viewer.');
		process.exit(1);
	}
	const port = Number(process.env.MOCK_PORT ?? 4173);
	const server = createMockServer({ role });
	server.listen(port, '127.0.0.1', () => {
		console.log(`DNScraft mock control-api on http://127.0.0.1:${port} (role ${role}).`);
		console.log('Local only: nothing here contacts the internet. Stop with Ctrl+C.');
	});
}
