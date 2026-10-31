import { resolve } from '$app/paths';

// Saved filters and the last-used filter are per-viewer conveniences in browser storage; every
// access is guarded because storage can be blocked or full.

export interface SavedFilter {
	name: string;
	/** Canonical URL query string (no leading `?`), as written by `toSearchParams`. */
	search: string;
}

export const SAVED_KEY = 'dnscraft_querylog_saved';
export const LAST_KEY = 'dnscraft_querylog_last';

export function readSaved(): SavedFilter[] {
	try {
		const raw: unknown = JSON.parse(globalThis.localStorage?.getItem(SAVED_KEY) ?? '[]');
		return Array.isArray(raw)
			? raw.filter((x) => typeof x?.name === 'string' && typeof x?.search === 'string')
			: [];
	} catch {
		return [];
	}
}

export function writeSaved(list: SavedFilter[]): void {
	try {
		globalThis.localStorage?.setItem(SAVED_KEY, JSON.stringify(list));
	} catch {
		// Not persisted: the list lasts until the next load.
	}
}

/** Adds a filter, replacing one of the same name. */
export function withSaved(list: SavedFilter[], item: SavedFilter): SavedFilter[] {
	return [...list.filter((x) => x.name !== item.name), item];
}

/** The filters the list page last showed, so "back" from a detail page returns to them. */
export function readLast(): string {
	try {
		return globalThis.sessionStorage?.getItem(LAST_KEY) ?? '';
	} catch {
		return '';
	}
}

export function writeLast(search: string): void {
	try {
		globalThis.sessionStorage?.setItem(LAST_KEY, search);
	} catch {
		// Back then opens the unfiltered list.
	}
}

/** Link to the list page with the given filters. */
export function listHref(search: string): string {
	return search === '' ? resolve('/query-log') : resolve(`/query-log?${search}`);
}
