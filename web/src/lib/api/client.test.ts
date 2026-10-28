import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError, CSRF_HEADER, del, get, getMe, post, put } from './client';
import { loginLocal, oidcAuthorizeUrl } from './auth';
import { auth, endSession, setPrincipal } from '$lib/auth/state.svelte';

const json = (status: number, body: unknown): Response =>
	new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});
const ok = (data: unknown): Response => json(200, { data });
const fail = (status: number, code: string, params?: Record<string, unknown>): Response =>
	json(status, params ? { error: { code, params } } : { error: { code } });
const csrfRefresh = (token: string): Response =>
	ok({ role: 'admin', actor_id: 'alice', actor_type: 'user', csrf_token: token });

let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;

/** The init object of the n-th fetch call (0-based). */
function initOf(call: number): RequestInit {
	return fetchMock.mock.calls[call]?.[1] as RequestInit;
}

function headerOf(call: number, name: string): string | undefined {
	return (initOf(call).headers as Record<string, string>)[name];
}

function methodsCalled(): string[] {
	return fetchMock.mock.calls.map((call) => (call[1] as RequestInit).method ?? 'GET');
}

beforeEach(() => {
	fetchMock = vi.fn<typeof fetch>();
	vi.stubGlobal('fetch', fetchMock);
	endSession();
	setPrincipal({ role: 'admin', actorId: 'alice', actorType: 'user', csrfToken: 'tok-1' });
});

afterEach(() => {
	vi.unstubAllGlobals();
});

describe('envelope parsing', () => {
	it('returns the data of a success envelope from the API base', async () => {
		fetchMock.mockResolvedValueOnce(ok({ status: 'ready' }));
		await expect(get('/status')).resolves.toEqual({ status: 'ready' });
		expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/v1/status');
		expect(initOf(0).credentials).toBe('include');
		expect(headerOf(0, 'Accept')).toBe('application/json');
	});

	it('raises an ApiError with status, code and params for an error envelope', async () => {
		fetchMock.mockResolvedValueOnce(fail(409, 'control_api.config.version', { current: 4 }));
		const error = await get('/config').catch((e: unknown) => e);
		expect(error).toBeInstanceOf(ApiError);
		expect(error).toMatchObject({
			status: 409,
			code: 'control_api.config.version',
			params: { current: 4 },
		});
	});

	it('treats a non-JSON success body as client.malformed', async () => {
		fetchMock.mockResolvedValueOnce(new Response('<html>proxy</html>', { status: 200 }));
		await expect(get('/status')).rejects.toMatchObject({ code: 'client.malformed', status: 200 });
	});

	it('treats a success body without data as client.malformed', async () => {
		fetchMock.mockResolvedValueOnce(json(200, { result: 1 }));
		await expect(get('/status')).rejects.toMatchObject({ code: 'client.malformed' });
	});

	it('treats an error body without a code as client.malformed and keeps the status', async () => {
		fetchMock.mockResolvedValueOnce(json(500, { error: { params: {} } }));
		await expect(get('/status')).rejects.toMatchObject({
			code: 'client.malformed',
			status: 500,
		});
	});

	it('maps a failed fetch to client.network with status 0', async () => {
		fetchMock.mockRejectedValueOnce(new TypeError('Failed to fetch'));
		await expect(get('/status')).rejects.toMatchObject({ code: 'client.network', status: 0 });
	});
});

describe('request headers', () => {
	it('sends no CSRF header on GET', async () => {
		fetchMock.mockResolvedValueOnce(ok({}));
		await get('/status');
		expect(headerOf(0, CSRF_HEADER)).toBeUndefined();
	});

	it.each([
		['POST', () => post('/filtering/custom-rules', { body: { domain: 'a.test' } })],
		['PUT', () => put('/config', { body: { a: 1 } })],
		['DELETE', () => del('/auth/tokens/1')],
	])('sends the CSRF token and a JSON content type on %s', async (method, call) => {
		fetchMock.mockResolvedValueOnce(ok({}));
		await call();
		expect(initOf(0).method).toBe(method);
		expect(headerOf(0, CSRF_HEADER)).toBe('tok-1');
		expect(headerOf(0, 'Content-Type')).toBe('application/json');
	});

	it('sends If-Match and an Idempotency-Key when given', async () => {
		fetchMock.mockResolvedValueOnce(ok({}));
		await put('/config', { body: {}, ifMatch: '"3"', idempotencyKey: 'key-1' });
		expect(headerOf(0, 'If-Match')).toBe('"3"');
		expect(headerOf(0, 'Idempotency-Key')).toBe('key-1');
	});

	it('generates an Idempotency-Key when asked', async () => {
		fetchMock.mockResolvedValueOnce(ok({}));
		await post('/config/validate', { body: {}, idempotencyKey: true });
		expect(headerOf(0, 'Idempotency-Key')).toMatch(/^[0-9a-f-]{36}$/);
	});

	it('leaves If-Match and Idempotency-Key off when not given', async () => {
		fetchMock.mockResolvedValueOnce(ok({}));
		await post('/resolver/cache/flush', { body: {} });
		expect(headerOf(0, 'If-Match')).toBeUndefined();
		expect(headerOf(0, 'Idempotency-Key')).toBeUndefined();
	});
});

describe('CSRF refresh', () => {
	it('retries a mutation once after a 403 CSRF with the refreshed token', async () => {
		fetchMock
			.mockResolvedValueOnce(fail(403, 'control_api.auth.csrf'))
			.mockResolvedValueOnce(csrfRefresh('tok-2'))
			.mockResolvedValueOnce(ok({ done: true }));

		await expect(post('/config/validate', { body: {}, idempotencyKey: true })).resolves.toEqual({
			done: true,
		});
		expect(methodsCalled()).toEqual(['POST', 'GET', 'POST']);
		expect(headerOf(2, CSRF_HEADER)).toBe('tok-2');
		// The retry reuses the idempotency key of the first attempt.
		expect(headerOf(2, 'Idempotency-Key')).toBe(headerOf(0, 'Idempotency-Key'));
	});

	it('gives up after one retry, ends the session and does not loop', async () => {
		fetchMock
			.mockResolvedValueOnce(fail(403, 'control_api.auth.csrf'))
			.mockResolvedValueOnce(csrfRefresh('tok-2'))
			.mockResolvedValueOnce(fail(403, 'control_api.auth.csrf'));

		await expect(put('/config', { body: {} })).rejects.toMatchObject({
			code: 'control_api.auth.csrf',
		});
		const mutations = methodsCalled().filter((method) => method === 'PUT');
		expect(mutations).toHaveLength(2);
		expect(auth.status).toBe('anonymous');
		expect(auth.csrfToken).toBeNull();
	});

	it('stops without a second attempt when the refresh itself fails', async () => {
		fetchMock
			.mockResolvedValueOnce(fail(403, 'control_api.auth.csrf'))
			.mockResolvedValueOnce(fail(401, 'control_api.auth.session_expired'));

		await expect(del('/auth/tokens/1')).rejects.toMatchObject({
			code: 'control_api.auth.csrf',
		});
		expect(methodsCalled().filter((method) => method === 'DELETE')).toHaveLength(1);
		expect(auth.status).toBe('anonymous');
	});
});

describe('401 handling', () => {
	it('clears the session and remembers the route for after sign-in', async () => {
		vi.stubGlobal('location', { pathname: '/query-log', search: '?range=24h' });
		fetchMock.mockResolvedValueOnce(fail(401, 'control_api.auth.session_expired'));

		await expect(get('/query-log')).rejects.toMatchObject({ status: 401 });
		expect(auth.status).toBe('anonymous');
		expect(auth.csrfToken).toBeNull();
		expect(auth.returnTo).toBe('/query-log?range=24h');
	});

	it('clears the session on an unreadable 401 as well', async () => {
		fetchMock.mockResolvedValueOnce(new Response('Unauthorized', { status: 401 }));
		await expect(get('/config')).rejects.toMatchObject({ status: 401 });
		expect(auth.status).toBe('anonymous');
	});

	it('does not clear the session for a public endpoint', async () => {
		fetchMock.mockResolvedValueOnce(fail(401, 'control_api.auth.local'));
		await expect(loginLocal('admin', 'wrong')).rejects.toMatchObject({
			code: 'control_api.auth.local',
		});
		expect(auth.status).toBe('authenticated');
	});

	it('never remembers the login route as a return target', async () => {
		vi.stubGlobal('location', { pathname: '/login', search: '' });
		fetchMock.mockResolvedValueOnce(fail(401, 'control_api.auth.unauthenticated'));
		await expect(get('/auth/me')).rejects.toBeInstanceOf(ApiError);
		expect(auth.returnTo).toBeNull();
	});
});

describe('auth endpoints', () => {
	it('maps the auth/me principal to the store shape', async () => {
		fetchMock.mockResolvedValueOnce(
			ok({ role: 'viewer', actor_id: 'bob', actor_type: 'token', csrf_token: null }),
		);
		await expect(getMe()).resolves.toEqual({
			role: 'viewer',
			actorId: 'bob',
			actorType: 'token',
			csrfToken: null,
		});
	});

	it('rejects an unknown role in auth/me as malformed', async () => {
		fetchMock.mockResolvedValueOnce(
			ok({ role: 'owner', actor_id: 'x', actor_type: 'user', csrf_token: null }),
		);
		await expect(getMe()).rejects.toMatchObject({ code: 'client.malformed' });
	});

	it('refuses an http authorization URL from the server', async () => {
		fetchMock.mockResolvedValueOnce(
			ok({ authorization_url: 'http://id.example.com/authorize', state: 's' }),
		);
		await expect(oidcAuthorizeUrl()).rejects.toMatchObject({ code: 'client.malformed' });
	});

	it('returns an https authorization URL unchanged', async () => {
		fetchMock.mockResolvedValueOnce(
			ok({ authorization_url: 'https://id.example.com/authorize?x=1', state: 's' }),
		);
		await expect(oidcAuthorizeUrl()).resolves.toBe('https://id.example.com/authorize?x=1');
	});
});
