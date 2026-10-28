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
import { buildRecords, initialConfig, PROTOCOLS } from './fixtures.mjs';

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
];
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
		'X-Content-Type-Options': 'nosniff',
		'Referrer-Policy': 'no-referrer',
		'Cache-Control': 'no-store',
		...headers,
	});
	response.end(body);
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
			const hits = rows.filter((record) => record.answer_source === 'cache').length;
			const misses = rows.filter((record) => record.answer_source === 'resolver').length;
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
						name: 'recursion',
						kind: 'recursion',
						zone: null,
						protocol: 'udp',
						state: 'degraded',
						rtt_ms: null,
						success_rate: 0.9,
						samples: 0,
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
			return sendData(response, {
				filter_set_id: body.filter_set_id ?? 'default',
				paused_until: new Date(Date.now() + seconds * 1000).toISOString(),
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
		default:
			break;
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
		return send(response, 200, body, { 'Content-Type': type });
	} catch {
		return send(response, 503, 'The web build is missing. Run `pnpm build` first.', {
			'Content-Type': 'text/plain; charset=utf-8',
		});
	}
}

/** Creates the mock HTTP server. Nothing listens until `listen` is called. */
export function createMockServer({ buildDir = DEFAULT_BUILD_DIR, role = 'admin' } = {}) {
	const root = resolve(buildDir);
	const store = createConfigStore();
	return createServer(async (request, response) => {
		try {
			if (request.url.startsWith('/api/') || request.url.startsWith('/readyz')) {
				await route(request, response, { role, store });
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
