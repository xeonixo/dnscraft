import { ApiError } from './client';
import { CLIENT_MALFORMED } from './error-codes';

/** Outcome of one read as a screen sees it. `unavailable` is a valid answer, not a failure. */
export type Result<T> =
	| { kind: 'loading' }
	| { kind: 'ok'; data: T }
	| { kind: 'unavailable'; code: string }
	| { kind: 'error'; code: string; params: Record<string, unknown> };

/** Control-api code for "resource exists in the API but this node does not run it". */
export const NOT_READY_CODE = 'control_api.not_ready';

/** Stable code and params of any thrown value; anything that is not an ApiError is malformed. */
export function failureOf(cause: unknown): { code: string; params: Record<string, unknown> } {
	if (cause instanceof ApiError) return { code: cause.code, params: cause.params };
	return { code: CLIENT_MALFORMED, params: {} };
}

/**
 * Resolves a read into a Result without throwing. 404 (feature absent) and 503 not_ready are
 * `unavailable`; everything else is an `error` that the caller may retry.
 */
export async function settle<T>(task: Promise<T>): Promise<Result<T>> {
	try {
		return { kind: 'ok', data: await task };
	} catch (cause) {
		if (cause instanceof ApiError && (cause.status === 404 || cause.code === NOT_READY_CODE)) {
			return { kind: 'unavailable', code: cause.code };
		}
		return { kind: 'error', ...failureOf(cause) };
	}
}
