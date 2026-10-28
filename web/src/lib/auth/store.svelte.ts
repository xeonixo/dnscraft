import { ApiError, getMe } from '$lib/api/client';
import { loginLocal as requestLocalLogin, logoutRequest } from '$lib/api/auth';
import { CLIENT_NETWORK } from '$lib/api/error-codes';
import { endSession, setLoadError, setPrincipal } from './state.svelte';

/**
 * Boot check: loads the principal. A 401 leaves the anonymous state (set by the client), so the
 * layout moves to the login route. Other failures keep the status unknown and record the code.
 */
export async function loadMe(): Promise<void> {
	setLoadError(null);
	try {
		setPrincipal(await getMe());
	} catch (error) {
		if (error instanceof ApiError && error.status === 401) return;
		setLoadError(error instanceof ApiError ? error.code : CLIENT_NETWORK);
	}
}

/** Break-glass sign-in; the caller decides where to go next. */
export async function loginLocal(username: string, password: string): Promise<void> {
	setPrincipal(await requestLocalLogin(username, password));
}

/** Revokes the server session, then clears the local state either way. */
export async function logout(): Promise<void> {
	try {
		await logoutRequest();
	} catch {
		// The local session ends even when the server call fails; the cookie then expires server-side.
	}
	endSession();
}
