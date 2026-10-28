// Boots the mock on an ephemeral 127.0.0.1 port and checks the fake control-api contract the UI
// relies on. Run with `pnpm test` (node --test). No network access beyond loopback.

import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
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

describe('mock control-api', () => {
	it('reports the signed-in principal and its CSRF token', async () => {
		const response = await fetch(`${base}/api/v1/auth/me`);
		assert.equal(response.status, 200);
		const body = await response.json();
		assert.equal(body.data.role, 'admin');
		assert.equal(body.data.actor_type, 'user');
		assert.equal(body.data.csrf_token, MOCK_CSRF);
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
