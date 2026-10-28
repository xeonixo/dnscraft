import type { SessionPrincipal } from '$lib/auth/state.svelte';
import { ApiError, isRecord, parseSession, post, get, request } from './client';
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

/**
 * The provider URL for the OIDC login. The backend has no `return_to` parameter, so the return
 * route stays in client memory. Only https URLs are followed.
 */
export async function oidcAuthorizeUrl(): Promise<string> {
	const data = await get<unknown>('/auth/oidc/authorize-url', { public: true });
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
