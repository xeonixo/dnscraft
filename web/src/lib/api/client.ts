import type { Role } from '$lib/nav';
import { markSessionLost, setPrincipal, auth, type SessionPrincipal } from '$lib/auth/state.svelte';
import { CLIENT_MALFORMED, CLIENT_NETWORK, CSRF_CODE } from './error-codes';

/** A failed call: the HTTP status (0 when no valid HTTP response exists), the stable code and params. */
export class ApiError extends Error {
	readonly status: number;
	readonly code: string;
	readonly params: Record<string, unknown>;

	constructor(status: number, code: string, params: Record<string, unknown> = {}) {
		super(code);
		this.name = 'ApiError';
		this.status = status;
		this.code = code;
		this.params = params;
	}
}

export type Method = 'GET' | 'POST' | 'PUT' | 'DELETE';

export interface RequestOptions {
	body?: unknown;
	/** Sent as If-Match; the caller formats the value (for example the observed config version). */
	ifMatch?: string;
	/** A key string, or `true` to generate one. The same key is reused when the CSRF retry runs. */
	idempotencyKey?: string | true;
	/** Login and the OIDC start. A 401 there is the answer to the request, not a lost session. */
	public?: boolean;
	/** The path is absolute from the origin (for example `/readyz`), not under `/api/v1`. */
	root?: boolean;
	signal?: AbortSignal;
}

export const CSRF_HEADER = 'X-CSRF-Token';
const API_BASE = '/api/v1';

export function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Path and query of the current page, or null outside a browser. */
function currentRoute(): string | null {
	const location = globalThis.location as Location | undefined;
	return location ? `${location.pathname}${location.search}` : null;
}

interface Settled {
	status: number;
	ok: boolean;
	body: unknown;
}

async function send(
	method: Method,
	path: string,
	options: RequestOptions,
	idempotencyKey: string | undefined,
): Promise<Response> {
	const headers: Record<string, string> = { Accept: 'application/json' };
	if (method !== 'GET') {
		headers['Content-Type'] = 'application/json';
		if (auth.csrfToken) headers[CSRF_HEADER] = auth.csrfToken;
	}
	if (options.ifMatch !== undefined) headers['If-Match'] = options.ifMatch;
	if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;

	try {
		return await fetch((options.root ? '' : API_BASE) + path, {
			method,
			headers,
			credentials: 'include',
			signal: options.signal,
			body: options.body === undefined ? undefined : JSON.stringify(options.body),
		});
	} catch (cause) {
		if (options.signal?.aborted) throw cause;
		throw new ApiError(0, CLIENT_NETWORK);
	}
}

async function settle(response: Response): Promise<Settled> {
	let body: unknown;
	try {
		body = JSON.parse(await response.text());
	} catch {
		body = undefined;
	}
	return { status: response.status, ok: response.ok, body };
}

function envelopeData(settled: Settled): unknown {
	if (isRecord(settled.body) && 'data' in settled.body) return settled.body.data;
	throw new ApiError(settled.status, CLIENT_MALFORMED);
}

function envelopeError(settled: Settled): ApiError {
	const { body, status } = settled;
	if (isRecord(body) && isRecord(body.error) && typeof body.error.code === 'string') {
		if (body.error.code.length > 0) {
			const params = isRecord(body.error.params) ? body.error.params : {};
			return new ApiError(status, body.error.code, params);
		}
	}
	return new ApiError(status, CLIENT_MALFORMED);
}

/** Refreshes the CSRF token from `GET /auth/me`. False when the refresh itself failed. */
async function refreshCsrfToken(): Promise<boolean> {
	try {
		setPrincipal(await getMe());
		return auth.csrfToken !== null;
	} catch {
		return false;
	}
}

/**
 * One API call. Success returns the envelope's `data`; every failure is an ApiError.
 * A 403 `control_api.auth.csrf` on a mutation refreshes the token and retries exactly once; a second
 * CSRF failure ends the session so the user signs in again instead of looping.
 */
export async function request<T>(
	method: Method,
	path: string,
	options: RequestOptions = {},
): Promise<T> {
	const idempotencyKey =
		options.idempotencyKey === true ? globalThis.crypto.randomUUID() : options.idempotencyKey;
	let csrfRetried = false;

	for (;;) {
		const settled = await settle(await send(method, path, options, idempotencyKey));
		if (settled.status === 401 && !options.public) markSessionLost(currentRoute());
		if (settled.ok) return envelopeData(settled) as T;

		const error = envelopeError(settled);
		if (error.code === CSRF_CODE && method !== 'GET' && !csrfRetried) {
			csrfRetried = true;
			if (await refreshCsrfToken()) continue;
		}
		if (error.code === CSRF_CODE && method !== 'GET') markSessionLost(currentRoute());
		throw error;
	}
}

export const get = <T>(path: string, options?: RequestOptions): Promise<T> =>
	request<T>('GET', path, options);
export const post = <T>(path: string, options?: RequestOptions): Promise<T> =>
	request<T>('POST', path, options);
export const put = <T>(path: string, options?: RequestOptions): Promise<T> =>
	request<T>('PUT', path, options);
export const del = <T>(path: string, options?: RequestOptions): Promise<T> =>
	request<T>('DELETE', path, options);

/** Shape of a cookie session from `GET /auth/me`, local login or OIDC callback. Unknown shapes are malformed. */
export function parseSession(data: unknown): Omit<SessionPrincipal, 'actorType'> {
	if (!isRecord(data)) throw new ApiError(0, CLIENT_MALFORMED);
	const { role, actor_id: actorId, csrf_token: csrfToken } = data;
	if (role !== 'viewer' && role !== 'admin') throw new ApiError(0, CLIENT_MALFORMED);
	if (typeof actorId !== 'string') throw new ApiError(0, CLIENT_MALFORMED);
	if (csrfToken !== null && typeof csrfToken !== 'string') {
		throw new ApiError(0, CLIENT_MALFORMED);
	}
	return { role: role as Role, actorId, csrfToken };
}

/** `GET /api/v1/auth/me`: the current principal and its CSRF token. */
export async function getMe(): Promise<SessionPrincipal> {
	const data = await get<unknown>('/auth/me');
	if (!isRecord(data) || typeof data.actor_type !== 'string') {
		throw new ApiError(0, CLIENT_MALFORMED);
	}
	return { ...parseSession(data), actorType: data.actor_type };
}
