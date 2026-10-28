/** Wide layout (table and inline filters) from this width, as in SPEC-web-ui § Responsive structure. */
export const WIDE_QUERY = '(min-width: 64rem)';

/** Whether a media query matches now. Without matchMedia (tests, old engines) the answer is no. */
export function mediaMatches(query: string): boolean {
	try {
		return globalThis.matchMedia?.(query).matches ?? false;
	} catch {
		return false;
	}
}
