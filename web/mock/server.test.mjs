// Boots the mock on an ephemeral 127.0.0.1 port and checks the fake control-api contract the UI
// relies on. Run with `pnpm test` (node --test). No network access beyond loopback.

import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { CSP } from './security-headers.mjs';
import { createMockServer, MOCK_CSRF } from './server.mjs';

let server;
let base;
let buildDir;

before(async () => {
	buildDir = await mkdtemp(join(tmpdir(), 'dnscraft-mock-'));
	await writeFile(join(buildDir, 'index.html'), '<!doctype html><title>mock</title>');
	server = createMockServer({ buildDir, role: 'admin' });
	await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
	const { port, address } = server.address();
	assert.equal(address, '127.0.0.1', 'the mock must bind loopback only');
	base = `http://127.0.0.1:${port}`;
});

after(() => {
	server.close();
});

describe('mock static security headers', () => {
	it('sends a strict CSP on HTML responses', async () => {
		const response = await fetch(`${base}/`);
		assert.equal(response.status, 200);
		assert.match(response.headers.get('content-type'), /text\/html/);
		assert.equal(response.headers.get('content-security-policy'), CSP);
		assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
		assert.equal(response.headers.get('referrer-policy'), 'no-referrer');
		assert.equal(response.headers.get('cache-control'), 'no-cache');
	});
});

describe('mock control-api', () => {
	it('reports the signed-in principal and its CSRF token', async () => {
		const response = await fetch(`${base}/api/v1/auth/me`);
		assert.equal(response.status, 200);
		const body = await response.json();
		assert.equal(body.data.role, 'admin');
		assert.equal(body.data.actor_type, 'user');
		assert.equal(body.data.csrf_token, MOCK_CSRF);
	});

	it('merges per-list engine status into the filter-list read', async () => {
		const response = await fetch(`${base}/api/v1/filter-lists`);
		assert.equal(response.status, 200);
		const { filter_lists: lists } = (await response.json()).data;
		const byId = Object.fromEntries(lists.map((list) => [list.id, list]));
		assert.equal(byId['adguard-dns-filter'].status.rules_parsed, 41230);
		assert.equal(byId['adguard-dns-filter'].status.error_code, null);
		assert.equal(byId['trackers-main'].status.error_code, 'filter_list.fetch_failed');
		assert.equal(byId['trackers-main'].status.http_status, 503);
		assert.equal(byId['legacy-hosts'].enabled, false);
		assert.equal('status' in byId['legacy-hosts'], false);
	});

	it('pages and filters the query log with the documented envelope', async () => {
		const response = await fetch(`${base}/api/v1/query-log?limit=3&domain_substr=example`);
		assert.equal(response.status, 200);
		const { data } = await response.json();
		assert.equal(data.queries.length, 3);
		assert.equal(data.has_more, true);
		assert.equal(data.next_offset, 3);
		for (const record of data.queries) {
			assert.match(record.query.name, /example/);
			assert.ok(Array.isArray(record.steps));
		}
	});

	it('answers unknown /api/v1 paths with the JSON not-found envelope', async () => {
		const response = await fetch(`${base}/api/v1/does-not-exist`);
		assert.equal(response.status, 404);
		assert.equal(response.headers.get('content-type'), 'application/json; charset=utf-8');
		assert.deepEqual(await response.json(), {
			error: { code: 'control_api.not_found', params: {} },
		});
	});

	it('rejects a malformed filter with the query-log invalid code', async () => {
		const response = await fetch(`${base}/api/v1/query-log?protocol=udp`);
		assert.equal(response.status, 400);
		const body = await response.json();
		assert.equal(body.error.code, 'control_api.query_log.invalid');
		assert.match(body.error.params.reason, /`protocol`/);
	});

	it('streams the CSV export with the current filters', async () => {
		const response = await fetch(`${base}/api/v1/query-log/export.csv?protocol=doh`);
		assert.equal(response.status, 200);
		assert.match(response.headers.get('content-type'), /^text\/csv/);
		const lines = (await response.text()).trim().split('\n');
		assert.match(lines[0], /^id,time,node_id/);
		assert.ok(lines.length > 1);
		for (const line of lines.slice(1)) assert.ok(line.includes(',doh,'));
	});

	it('serves a single record and not-found for an unknown id', async () => {
		const found = await fetch(`${base}/api/v1/query-log/rec-0000`);
		assert.equal(found.status, 200);
		assert.equal((await found.json()).data.id, 'rec-0000');
		const missing = await fetch(`${base}/api/v1/query-log/rec-missing`);
		assert.equal(missing.status, 404);
	});

	it('falls back to index.html for SPA routes', async () => {
		const response = await fetch(`${base}/query-log/rec-0000`);
		assert.equal(response.status, 200);
		assert.match(await response.text(), /<title>mock<\/title>/);
	});
});

describe('mock write rules', () => {
	it('refuses admin writes to a viewer', async () => {
		const viewer = createMockServer({ buildDir, role: 'viewer' });
		await new Promise((resolve) => viewer.listen(0, '127.0.0.1', resolve));
		try {
			const { port } = viewer.address();
			const response = await fetch(`http://127.0.0.1:${port}/api/v1/filtering/pause`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': MOCK_CSRF },
				body: JSON.stringify({ duration: 'PT5M' }),
			});
			assert.equal(response.status, 403);
			assert.equal((await response.json()).error.code, 'control_api.auth.insufficient_scope');
		} finally {
			viewer.close();
		}
	});

	it('requires the CSRF header on writes', async () => {
		const response = await fetch(`${base}/api/v1/filtering/pause`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ duration: 'PT5M' }),
		});
		assert.equal(response.status, 403);
		assert.equal((await response.json()).error.code, 'control_api.auth.csrf');
	});
});

describe('mock configuration API', () => {
	let configServer;
	let configBase;

	const headers = (extra = {}) => ({
		'Content-Type': 'application/json',
		'X-CSRF-Token': MOCK_CSRF,
		...extra,
	});
	const getConfig = async () => (await fetch(`${configBase}/api/v1/config`)).json();
	const putConfig = (body, ifMatch) =>
		fetch(`${configBase}/api/v1/config`, {
			method: 'PUT',
			headers: headers(ifMatch === undefined ? {} : { 'If-Match': String(ifMatch) }),
			body: JSON.stringify(body),
		});

	before(async () => {
		configServer = createMockServer({ buildDir, role: 'admin' });
		await new Promise((resolve) => configServer.listen(0, '127.0.0.1', resolve));
		configBase = `http://127.0.0.1:${configServer.address().port}`;
	});

	after(() => {
		configServer.close();
	});

	it('returns the current version and snapshot without secret fields', async () => {
		const { data } = await getConfig();
		assert.equal(data.version, 12);
		assert.ok(Array.isArray(data.config.filtering.sets));
		assert.doesNotMatch(JSON.stringify(data.config), /secret|token_hash|password/i);
	});

	it('refuses configuration reads to a viewer with the admin scope code', async () => {
		const viewer = createMockServer({ buildDir, role: 'viewer' });
		await new Promise((resolve) => viewer.listen(0, '127.0.0.1', resolve));
		try {
			const response = await fetch(`http://127.0.0.1:${viewer.address().port}/api/v1/config`);
			assert.equal(response.status, 403);
			const body = await response.json();
			assert.equal(body.error.code, 'control_api.auth.insufficient_scope');
			assert.deepEqual(body.error.params, { required: 'admin' });
		} finally {
			viewer.close();
		}
	});

	it('rejects a stale If-Match with 409 and the version code, without storing anything', async () => {
		const { data: before } = await getConfig();
		const response = await putConfig(before.config, 11);
		assert.equal(response.status, 409);
		assert.equal((await response.json()).error.code, 'control_api.config.version');
		assert.equal((await getConfig()).data.version, 12);
	});

	it('validates without bumping the version: errors, warnings and a diff', async () => {
		const { data: current } = await getConfig();
		const candidate = structuredClone(current.config);
		candidate.policy.profiles[0].filter_set = 'missing-set';
		candidate.filtering.sets[1].lists = [];
		const response = await fetch(`${configBase}/api/v1/config/validate`, {
			method: 'POST',
			headers: headers({ 'If-Match': '12' }),
			body: JSON.stringify(candidate),
		});
		assert.equal(response.status, 200);
		const { data } = await response.json();
		assert.equal(data.valid, false);
		assert.equal(data.config_version, 12);
		assert.equal(data.errors[0].code, 'policy.config.unknown_filter_set');
		assert.equal(data.errors[0].path, 'policy.profiles[0].filter_set');
		assert.equal(data.warnings[0].code, 'filtering.config.no_lists');
		assert.ok(data.diff.changed_sections.includes('policy'));
		assert.equal((await getConfig()).data.version, 12);
	});

	it('reports a valid candidate as valid and a malformed body as a 400 config error', async () => {
		const { data: current } = await getConfig();
		const valid = await fetch(`${configBase}/api/v1/config/validate`, {
			method: 'POST',
			headers: headers(),
			body: JSON.stringify(current.config),
		});
		assert.deepEqual((await valid.json()).data.errors, []);

		const malformed = await fetch(`${configBase}/api/v1/config/validate`, {
			method: 'POST',
			headers: headers(),
			body: '{"filtering": ',
		});
		assert.equal(malformed.status, 400);
		assert.equal((await malformed.json()).error.code, 'control_api.config.invalid');
	});

	it('saves with a matching If-Match, bumps the version and keeps omitted mcp_rules', async () => {
		const { data: current } = await getConfig();
		const body = structuredClone(current.config);
		const storedRules = current.config.filtering.sets[0].mcp_rules;
		delete body.filtering.sets[0].mcp_rules;
		const response = await putConfig(body, 12);
		assert.equal(response.status, 200);
		assert.equal((await response.json()).data.version, 13);
		const after = (await getConfig()).data.config;
		assert.deepEqual(after.filtering.sets[0].mcp_rules, storedRules);
	});

	it('deletes mcp_rules only when the field is an explicit empty array', async () => {
		const { data: current } = await getConfig();
		const body = structuredClone(current.config);
		body.filtering.sets[0].mcp_rules = [];
		assert.equal((await putConfig(body, 13)).status, 200);
		assert.deepEqual((await getConfig()).data.config.filtering.sets[0].mcp_rules, []);
	});

	it('lists versions newest first with paging', async () => {
		const response = await fetch(`${configBase}/api/v1/config/versions?limit=3`);
		const { data } = await response.json();
		assert.equal(data.current_version, 14);
		assert.deepEqual(
			data.versions.map((row) => row.version),
			[14, 13, 12],
		);
		assert.equal(data.has_more, true);
		assert.equal(data.next_offset, 3);
		assert.match(data.versions[0].created_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
	});

	it('rolls back to a stored version as a new version and rejects unknown targets', async () => {
		const missing = await fetch(`${configBase}/api/v1/config/versions/99/rollback`, {
			method: 'POST',
			headers: headers(),
		});
		assert.equal(missing.status, 404);
		assert.equal((await missing.json()).error.code, 'control_api.config.unknown_version');

		const response = await fetch(`${configBase}/api/v1/config/versions/3/rollback`, {
			method: 'POST',
			headers: headers({ 'If-Match': '14' }),
		});
		assert.equal(response.status, 200);
		assert.deepEqual((await response.json()).data, { version: 15, restored_from: 3 });
		assert.equal((await getConfig()).data.version, 15);
	});
});

describe('mock query log volume and variety', () => {
	const list = async (query) => {
		const response = await fetch(`${base}/api/v1/query-log?${query}`);
		assert.equal(response.status, 200);
		return (await response.json()).data;
	};
	const since = (ms) => new Date(Date.now() - ms).toISOString();

	it('has more rows in wider windows and always some in the last hour', async () => {
		const counts = [];
		for (const ms of [15 * 60_000, 3_600_000, 86_400_000, 7 * 86_400_000]) {
			const data = await list(`limit=200&from=${encodeURIComponent(since(ms))}`);
			counts.push(data.queries.length);
		}
		assert.ok(counts[1] > 0, 'the 1 h preset must not be empty');
		assert.ok(counts[0] <= counts[1] && counts[1] < counts[2], `windows grow: ${counts}`);
	});

	it('serves many query types and response codes, newest first', async () => {
		const data = await list('limit=200&offset=0');
		const times = data.queries.map((q) => Date.parse(q.time));
		assert.deepEqual(
			times,
			[...times].sort((a, b) => b - a),
		);
		const types = new Set();
		const rcodes = new Set();
		for (let offset = 0; offset < 2500; offset += 200) {
			const page = await list(`limit=200&offset=${offset}`);
			for (const q of page.queries) {
				types.add(q.query.type);
				rcodes.add(q.rcode);
			}
		}
		for (const type of ['A', 'AAAA', 'HTTPS', 'CNAME', 'MX', 'TXT', 'PTR', 'SRV']) {
			assert.ok(types.has(type), `missing query type ${type}`);
		}
		for (const rcode of ['NOERROR', 'NXDOMAIN', 'SERVFAIL', 'REFUSED']) {
			assert.ok(rcodes.has(rcode), `missing rcode ${rcode}`);
		}
	});
});

describe('mock client ids, labels and the home record', () => {
	let idServer;
	let idBase;
	const headers = { 'Content-Type': 'application/json', 'X-CSRF-Token': MOCK_CSRF };
	const listIds = async () =>
		(await (await fetch(`${idBase}/api/v1/policy/client-ids`)).json()).data.client_ids;

	before(async () => {
		idServer = createMockServer({ buildDir, role: 'admin' });
		await new Promise((resolve) => idServer.listen(0, '127.0.0.1', resolve));
		idBase = `http://127.0.0.1:${idServer.address().port}`;
	});

	after(() => {
		idServer.close();
	});

	it('lists labelled client ids with a device or null', async () => {
		const ids = await listIds();
		assert.ok(ids.length >= 6 && ids.length <= 8);
		assert.equal(ids[0].label, 'iPhone von Anna');
		assert.equal(ids[0].device, 'dir-iphone-k7q2x9');
		assert.ok(ids.some((entry) => entry.device === null));
	});

	it('creates, relabels with null to clear, and deletes a client id', async () => {
		const created = await fetch(`${idBase}/api/v1/policy/client-ids`, {
			method: 'POST',
			headers,
			body: JSON.stringify({ id: 'test-phone-1234', label: 'Test Phone' }),
		});
		assert.equal(created.status, 200);
		let ids = await listIds();
		assert.deepEqual(
			ids.find((entry) => entry.id === 'test-phone-1234'),
			{ id: 'test-phone-1234', label: 'Test Phone', device: null, view: null },
		);

		const renamed = await fetch(`${idBase}/api/v1/policy/client-ids/test-phone-1234`, {
			method: 'PUT',
			headers,
			body: JSON.stringify({ label: null, device: 'dir-nas-d4n7x2' }),
		});
		assert.equal(renamed.status, 200);
		ids = await listIds();
		assert.deepEqual(
			ids.find((entry) => entry.id === 'test-phone-1234'),
			{ id: 'test-phone-1234', label: null, device: 'dir-nas-d4n7x2', view: null },
		);

		const removed = await fetch(`${idBase}/api/v1/policy/client-ids/test-phone-1234`, {
			method: 'DELETE',
			headers,
		});
		assert.equal(removed.status, 200);
		assert.equal(
			(await listIds()).some((entry) => entry.id === 'test-phone-1234'),
			false,
		);
	});

	it('refuses a duplicate label case-insensitively and an unknown id', async () => {
		const duplicate = await fetch(`${idBase}/api/v1/policy/client-ids`, {
			method: 'POST',
			headers,
			body: JSON.stringify({ id: 'dup-check-0001', label: 'macbook pro' }),
		});
		assert.equal(duplicate.status, 400);
		assert.equal((await duplicate.json()).error.code, 'policy.config.invalid');

		const missing = await fetch(`${idBase}/api/v1/policy/client-ids/no-such-id`, {
			method: 'PUT',
			headers,
			body: JSON.stringify({ label: 'x' }),
		});
		assert.equal(missing.status, 404);
	});

	it('serves query-log rows for a client id so last-seen has data', async () => {
		const response = await fetch(`${idBase}/api/v1/query-log?client_id=iphone-k7q2x9&limit=1`);
		const { queries } = (await response.json()).data;
		assert.equal(queries.length, 1);
		assert.equal(queries[0].client_id, 'iphone-k7q2x9');
	});

	it('creates the dns.<public domain> record with a home override through the records endpoint', async () => {
		const response = await fetch(`${idBase}/api/v1/policy/records`, {
			method: 'PUT',
			headers,
			body: JSON.stringify({
				name: 'dns.example.test',
				type: 'A',
				ttl: 60,
				rdata: '',
				overrides: { lan: '192.0.2.2' },
			}),
		});
		assert.equal(response.status, 200);
		const { records } = (await (await fetch(`${idBase}/api/v1/policy/records`)).json()).data;
		const record = records.find((row) => row.name === 'dns.example.test');
		assert.deepEqual(record.overrides, { lan: '192.0.2.2' });
	});
});

describe('mock Netzbereich pins for client ids', () => {
	let pinServer;
	let pinBase;
	const headers = { 'Content-Type': 'application/json', 'X-CSRF-Token': MOCK_CSRF };
	const send = (path, method, body) =>
		fetch(`${pinBase}${path}`, { method, headers, body: JSON.stringify(body) });
	const pinnedIds = async () =>
		(await (await fetch(`${pinBase}/api/v1/policy/client-ids`)).json()).data.client_ids;

	before(async () => {
		pinServer = createMockServer({ buildDir, role: 'admin' });
		await new Promise((resolve) => pinServer.listen(0, '127.0.0.1', resolve));
		pinBase = `http://127.0.0.1:${pinServer.address().port}`;
	});

	after(() => {
		pinServer.close();
	});

	it('serves the unterwegs range without subnets and two pinned client ids', async () => {
		const { views } = (await (await fetch(`${pinBase}/api/v1/policy/views`)).json()).data;
		const unterwegs = views.find((view) => view.id === 'unterwegs');
		assert.deepEqual(unterwegs, {
			id: 'unterwegs',
			is_default: false,
			subnets: [],
			nodes: [],
			profile: 'default',
		});
		const ids = await pinnedIds();
		assert.equal(ids.find((entry) => entry.id === 'iphone-k7q2x9').view, 'unterwegs');
		assert.equal(ids.find((entry) => entry.id === 'pixel-8-jonas').view, 'unterwegs');
		assert.equal(ids.find((entry) => entry.id === 'macbook-r4t8vn').view, null);
	});

	it('pins on create and on update, and null clears the pin', async () => {
		const created = await send('/api/v1/policy/client-ids', 'POST', {
			id: 'pin-test-0001',
			view: 'unterwegs',
		});
		assert.equal(created.status, 200);
		assert.equal((await pinnedIds()).find((e) => e.id === 'pin-test-0001').view, 'unterwegs');

		const cleared = await send('/api/v1/policy/client-ids/pin-test-0001', 'PUT', { view: null });
		assert.equal(cleared.status, 200);
		assert.equal((await pinnedIds()).find((e) => e.id === 'pin-test-0001').view, null);

		const kept = await send('/api/v1/policy/client-ids/pin-test-0001', 'PUT', {
			view: 'unterwegs',
		});
		assert.equal(kept.status, 200);
		const renamed = await send('/api/v1/policy/client-ids/pin-test-0001', 'PUT', {
			label: 'Test Pin',
		});
		assert.equal(renamed.status, 200);
		assert.equal((await pinnedIds()).find((e) => e.id === 'pin-test-0001').view, 'unterwegs');
	});

	it('refuses an unknown view with field view', async () => {
		const response = await send('/api/v1/policy/client-ids/pixel-8-jonas', 'PUT', {
			view: 'no-such-range',
		});
		assert.equal(response.status, 400);
		const { error } = await response.json();
		assert.equal(error.code, 'policy.config.invalid');
		assert.deepEqual(error.params, { reason: 'view_unknown', field: 'view' });
	});

	it('refuses to delete a range that a client id is pinned to, naming the ids', async () => {
		const response = await fetch(`${pinBase}/api/v1/policy/views/unterwegs`, {
			method: 'DELETE',
			headers,
		});
		assert.equal(response.status, 400);
		const { error } = await response.json();
		assert.equal(error.code, 'policy.config.invalid');
		assert.equal(error.params.reason, 'view_in_use');
		assert.equal(error.params.view, 'unterwegs');
		assert.deepEqual(error.params.client_ids, ['iphone-k7q2x9', 'pixel-8-jonas', 'pin-test-0001']);
	});

	it('deletes a range once no client id is pinned to it', async () => {
		for (const id of ['iphone-k7q2x9', 'pixel-8-jonas', 'pin-test-0001']) {
			const cleared = await send(`/api/v1/policy/client-ids/${id}`, 'PUT', { view: null });
			assert.equal(cleared.status, 200);
		}
		const deleted = await fetch(`${pinBase}/api/v1/policy/views/unterwegs`, {
			method: 'DELETE',
			headers,
		});
		assert.equal(deleted.status, 200);
	});

	it('marks ten newest roaming queries as client-id selections with the label', async () => {
		let roaming = [];
		for (let offset = 0; offset < 2500; offset += 200) {
			const response = await fetch(`${pinBase}/api/v1/query-log?limit=200&offset=${offset}`);
			const { queries } = (await response.json()).data;
			roaming.push(...queries.filter((q) => q.selection.cause === 'client_id'));
		}
		assert.equal(roaming.length, 10);
		for (const record of roaming) {
			assert.equal(record.view_id, 'unterwegs');
			assert.equal(record.protocol, 'doh');
			assert.equal(record.client.source, 'client_id');
			assert.ok(['iPhone von Anna', 'Pixel 8 Jonas'].includes(record.client.display_name));
		}
	});
});
