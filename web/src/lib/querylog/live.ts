import type { QueryPage, QueryRecord } from '$lib/api/query-log';
import type { Draft } from './filters';

/** Client-side cap for the live head (WX2). */
export const LIVE_CAP = 500;

/** Close the stream after the tab stays hidden this long (WX2). */
export const HIDDEN_CLOSE_MS = 60_000;

/** Stream URL query: same filters as the list, without paging or sort. */
export function streamParams(listParams: URLSearchParams): URLSearchParams {
	const params = new URLSearchParams(listParams);
	params.delete('limit');
	params.delete('offset');
	params.delete('order');
	params.delete('order_by');
	return params;
}

/** Same-origin SSE path for the current list filters. */
export function streamHref(listParams: URLSearchParams): string {
	const search = streamParams(listParams).toString();
	return `/api/v1/query-log/stream${search === '' ? '' : `?${search}`}`;
}

/**
 * True when live rows belong at the top of the current page: first page, newest first.
 * Deeper pages and other sorts keep the stream for `lagged` only.
 */
export function isLiveHead(draft: Pick<Draft, 'offset' | 'order_by' | 'order'>): boolean {
	const atStart = draft.offset === '' || draft.offset === '0';
	const byTime = draft.order_by === '' || draft.order_by === 'time';
	const newestFirst = draft.order === '' || draft.order === 'desc';
	return atStart && byTime && newestFirst;
}

/**
 * Prepends newly streamed rows (oldest→newest in `rows`) onto the page, de-duplicated by id,
 * capped at `cap`. Newest stay at the front.
 */
export function mergeLivePage(
	page: QueryPage,
	rows: readonly QueryRecord[],
	cap: number = LIVE_CAP,
): QueryPage {
	if (rows.length === 0) return page;
	const seen = new Set(page.queries.map((row) => row.id));
	const added: QueryRecord[] = [];
	for (let i = rows.length - 1; i >= 0; i--) {
		const row = rows[i]!;
		if (seen.has(row.id)) continue;
		seen.add(row.id);
		added.push(row);
	}
	if (added.length === 0) return page;
	return {
		...page,
		queries: [...added, ...page.queries].slice(0, cap),
	};
}
