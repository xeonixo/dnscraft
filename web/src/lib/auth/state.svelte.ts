import type { Role } from '$lib/nav';
import { isPublicPath } from './public-routes';

// Session state lives in memory only: never in localStorage or sessionStorage. The session cookie
// is HttpOnly and invisible here; the CSRF token is the only credential-like value in JavaScript.

export type AuthStatus = 'unknown' | 'authenticated' | 'anonymous';

export interface SessionPrincipal {
	role: Role;
	actorId: string;
	actorType: string;
	csrfToken: string | null;
}

interface AuthState {
	status: AuthStatus;
	role: Role;
	actorId: string;
	actorType: string;
	csrfToken: string | null;
	/** Error code of a failed boot load (offline, server error). Null otherwise. */
	loadErrorCode: string | null;
	/** Same-origin route to restore after sign-in. */
	returnTo: string | null;
}

export const auth = $state<AuthState>({
	status: 'unknown',
	role: 'viewer',
	actorId: '',
	actorType: '',
	csrfToken: null,
	loadErrorCode: null,
	returnTo: null,
});

export function setPrincipal(principal: SessionPrincipal): void {
	auth.status = 'authenticated';
	auth.role = principal.role;
	auth.actorId = principal.actorId;
	auth.actorType = principal.actorType;
	auth.csrfToken = principal.csrfToken;
	auth.loadErrorCode = null;
}

export function setLoadError(code: string | null): void {
	auth.loadErrorCode = code;
}

function clearPrincipal(): void {
	auth.status = 'anonymous';
	auth.role = 'viewer';
	auth.actorId = '';
	auth.actorType = '';
	auth.csrfToken = null;
}

function pathnameOf(route: string): string {
	const [pathname = ''] = route.split('?');
	return pathname;
}

/**
 * Drops the session after a 401 or a failed CSRF retry, remembering the route the user was on.
 * Public routes are never remembered (returning to the login screen is not a destination).
 */
export function markSessionLost(route: string | null): void {
	clearPrincipal();
	if (route && !isPublicPath(pathnameOf(route))) auth.returnTo = route;
}

/** Ends the session on purpose (sign-out): nothing is remembered for after sign-in. */
export function endSession(): void {
	clearPrincipal();
	auth.returnTo = null;
}

/** The remembered route, validated as a same-origin path, consumed once. */
export function takeReturnTo(): string | null {
	const target = auth.returnTo;
	auth.returnTo = null;
	if (!target || !target.startsWith('/') || target.startsWith('//')) return null;
	return isPublicPath(pathnameOf(target)) ? null : target;
}
