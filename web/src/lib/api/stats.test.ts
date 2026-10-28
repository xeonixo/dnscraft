import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { settle } from './result';
import {
	flushCache,
	getReadiness,
	getTopDomains,
	periodQuery,
	pauseFilterSet,
	type Period,
} from './stats';
import { endSession, setPrincipal } from '$lib/auth/state.svelte';

const json = (status: number, body: unknown): Response =>
	new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});

let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;

beforeEach(() => {
	fetchMock = vi.fn<typeof fetch>();
	vi.stubGlobal('fetch', fetchMock);
	endSession();
	setPrincipal({ role: 'admin', actorId: 'alice', actorType: 'user', csrfToken: 'tok-1' });
});

afterEach(() => {
	vi.unstubAllGlobals();
});

describe('periodQuery', () => {
	const now = new Date('2026-10-28T12:00:00.000Z');

	it.each([
		['24h', 1],
		['7d', 7],
		['30d', 30],
		['1y', 365],
	] as [Period, number][])('covers %s ending now', (period, days) => {
		const params = new URLSearchParams(periodQuery(period, now));
		expect(params.get('to')).toBe('2026-10-28T12:00:00.000Z');
		const span = Date.parse(params.get('to') ?? '') - Date.parse(params.get('from') ?? '');
		expect(span).toBe(days * 86_400_000);
	});
});

describe('readiness', () => {
	it('is ready on a 200 from the root readyz path', async () => {
		fetchMock.mockResolvedValueOnce(json(200, { data: { ready: true } }));
		await expect(getReadiness()).resolves.toEqual({ ready: true, modules: [] });
		expect(fetchMock.mock.calls[0]?.[0]).toBe('/readyz');
	});

	it('reads the starting modules from a 503 not_ready answer', async () => {
		fetchMock.mockResolvedValueOnce(
			json(503, { error: { code: 'control_api.not_ready', params: { modules: ['resolver'] } } }),
		);
		await expect(getReadiness()).resolves.toEqual({ ready: false, modules: ['resolver'] });
	});
});

describe('settle', () => {
	it('maps 404 to unavailable and keeps other failures as errors', async () => {
		fetchMock.mockResolvedValueOnce(
			json(404, { error: { code: 'control_api.not_found', params: {} } }),
		);
		await expect(settle(getTopDomains('24h', 10))).resolves.toEqual({
			kind: 'unavailable',
			code: 'control_api.not_found',
		});

		fetchMock.mockResolvedValueOnce(json(500, { error: { code: 'control_api.internal' } }));
		await expect(settle(getTopDomains('24h', 10))).resolves.toEqual({
			kind: 'error',
			code: 'control_api.internal',
			params: {},
		});
	});

	it('unwraps the data of a success', async () => {
		fetchMock.mockResolvedValueOnce(json(200, { data: { domains: [] } }));
		await expect(settle(getTopDomains('7d', 5))).resolves.toEqual({ kind: 'ok', data: [] });
		expect(fetchMock.mock.calls[0]?.[0]).toMatch(/\/api\/v1\/stats\/top_domains\?from=.*&limit=5$/);
	});
});

describe('mutations', () => {
	it('posts the pause body to the filtering endpoint with the CSRF header', async () => {
		fetchMock.mockResolvedValueOnce(
			json(200, { data: { filter_set_id: 'default', paused_until: '2026-10-28T12:05:00Z' } }),
		);
		await pauseFilterSet('PT5M');
		const init = fetchMock.mock.calls[0]?.[1] as RequestInit;
		expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/v1/filtering/pause');
		expect(init.method).toBe('POST');
		expect(JSON.parse(String(init.body))).toEqual({ filter_set_id: 'default', duration: 'PT5M' });
		expect((init.headers as Record<string, string>)['X-CSRF-Token']).toBe('tok-1');
	});

	it('sends an empty body for a whole-cache flush and the domain otherwise', async () => {
		fetchMock.mockResolvedValueOnce(
			json(200, { data: { scope: 'all', domain: null, evicted: 9 } }),
		);
		fetchMock.mockResolvedValueOnce(
			json(200, { data: { scope: 'domain', domain: 'example.com', evicted: 2 } }),
		);
		await flushCache(null);
		await flushCache('example.com');
		expect(JSON.parse(String((fetchMock.mock.calls[0]?.[1] as RequestInit).body))).toEqual({});
		expect(JSON.parse(String((fetchMock.mock.calls[1]?.[1] as RequestInit).body))).toEqual({
			domain: 'example.com',
		});
	});
});
