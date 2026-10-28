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
