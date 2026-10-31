import type { SessionPrincipal } from '$lib/auth/state.svelte';
import { ApiError, isRecord, parseSession, post, get, put, request } from './client';
import { CLIENT_MALFORMED } from './error-codes';

/** Break-glass login. The password travels only in the request body and is never retained here. */
export async function loginLocal(username: string, password: string): Promise<SessionPrincipal> {
	const data = await post<unknown>('/auth/local/login', {
		body: { username, password },
		public: true,
	});
	// Local logins are always user sessions; the login response carries no actor_type.
	return { ...parseSession(data), actorType: 'user' };
}

export async function logoutRequest(): Promise<void> {
	await request<unknown>('POST', '/auth/logout');
}

/** Public: whether SSO is currently enabled on the control API. */
export async function oidcStatusPublic(): Promise<{ enabled: boolean }> {
	const data = await get<unknown>('/auth/oidc/status', { public: true });
	if (!isRecord(data) || typeof data.enabled !== 'boolean') {
		throw new ApiError(0, CLIENT_MALFORMED);
	}
	return { enabled: data.enabled };
}

/** Admin view of live OIDC settings (never includes the client secret). */
export interface OidcStatus {
	enabled: boolean;
	has_client_secret: boolean;
	issuer: string;
	client_id: string;
	admin_group: string;
	groups_claim: string;
	token_skew_seconds: number;
	callback_path: string;
}

export async function getOidcStatus(): Promise<OidcStatus> {
	const data = await get<unknown>('/auth/oidc/status');
	if (!isRecord(data) || typeof data.enabled !== 'boolean') {
		throw new ApiError(0, CLIENT_MALFORMED);
	}
	return {
		enabled: data.enabled,
		has_client_secret: data.has_client_secret === true,
		issuer: typeof data.issuer === 'string' ? data.issuer : '',
		client_id: typeof data.client_id === 'string' ? data.client_id : '',
		admin_group: typeof data.admin_group === 'string' ? data.admin_group : '',
		groups_claim: typeof data.groups_claim === 'string' ? data.groups_claim : 'groups',
		token_skew_seconds: typeof data.token_skew_seconds === 'number' ? data.token_skew_seconds : 30,
		callback_path:
			typeof data.callback_path === 'string' ? data.callback_path : '/api/v1/auth/oidc/callback',
	};
}

/** Write-only OIDC client secret. Pass `null` to clear. */
export async function putOidcClientSecret(
	client_secret: string | null,
): Promise<{ updated: boolean; has_client_secret: boolean; enabled: boolean }> {
	const data = await put<unknown>('/auth/oidc/client-secret', {
		body: { client_secret },
	});
	if (!isRecord(data) || typeof data.updated !== 'boolean') {
		throw new ApiError(0, CLIENT_MALFORMED);
	}
	return {
		updated: data.updated,
		has_client_secret: data.has_client_secret === true,
		enabled: data.enabled === true,
	};
}

/**
 * The provider URL for the OIDC login. Only https authorization URLs are followed
 * (Authentik always serves TLS).
 */
export async function oidcAuthorizeUrl(returnTo?: string | null): Promise<string> {
	const params = new URLSearchParams();
	if (returnTo) params.set('return_to', returnTo);
	const query = params.toString();
	const path = `/auth/oidc/authorize-url${query ? `?${query}` : ''}`;
	const data = await get<unknown>(path, { public: true });
	const url = isRecord(data) ? data.authorization_url : undefined;
	if (typeof url !== 'string' || !isHttps(url)) throw new ApiError(0, CLIENT_MALFORMED);
	return url;
}

function isHttps(url: string): boolean {
	try {
		return new URL(url).protocol === 'https:';
	} catch {
		return false;
	}
}
