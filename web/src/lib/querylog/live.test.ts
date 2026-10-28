import { describe, expect, it } from 'vitest';
import type { QueryPage, QueryRecord } from '$lib/api/query-log';
import { emptyDraft } from './filters';
import { isLiveHead, LIVE_CAP, mergeLivePage, streamHref, streamParams } from './live';

function row(id: string): QueryRecord {
	return {
		id,
		node_id: 'n1',
		listener_id: 'lan',
		protocol: 'udp53',
		source_ip: '192.0.2.1',
		source_ip_truncated: false,
		client_id: null,
		client: null,
		query: { name: `${id}.example`, type: 'A', class: 'IN' },
		view_id: 'lan',
		profile_id: 'default',
		selection: { cause: 'default' },
		steps: [],
		answer_source: 'upstream',
		filter: null,
		dnssec: null,
		forward_zone: null,
		rcode: 'NOERROR',
		answer_size: 0,
		timings: { select_us: 0, filter_us: 0, resolve_us: 0, total_us: 1 },
		time: '2026-01-01T00:00:00Z',
	};
}

function page(ids: string[]): QueryPage {
	return { queries: ids.map(row), has_more: false, next_offset: null };
}

describe('streamParams / streamHref', () => {
	it('drops paging and sort, keeps filters', () => {
		const list = new URLSearchParams(
			'domain_substr=ads&limit=50&offset=100&order=asc&order_by=domain&protocol=doh',
		);
		expect(streamParams(list).toString()).toBe('domain_substr=ads&protocol=doh');
		expect(streamHref(list)).toBe('/api/v1/query-log/stream?domain_substr=ads&protocol=doh');
	});

	it('is a bare path with no filters', () => {
		expect(streamHref(new URLSearchParams())).toBe('/api/v1/query-log/stream');
	});
});

describe('isLiveHead', () => {
	it('is true for the default first page', () => {
		expect(isLiveHead(emptyDraft())).toBe(true);
	});

	it('is false when offset, order or order_by leave the live head', () => {
		expect(isLiveHead({ ...emptyDraft(), offset: '50' })).toBe(false);
		expect(isLiveHead({ ...emptyDraft(), order: 'asc' })).toBe(false);
		expect(isLiveHead({ ...emptyDraft(), order_by: 'domain' })).toBe(false);
	});
});

describe('mergeLivePage', () => {
	it('prepends newest-first and skips duplicates', () => {
		const next = mergeLivePage(page(['a', 'b']), [row('b'), row('c'), row('d')]);
		expect(next.queries.map((q) => q.id)).toEqual(['d', 'c', 'a', 'b']);
	});

	it('caps at LIVE_CAP', () => {
		const existing = page(Array.from({ length: LIVE_CAP }, (_, i) => `old-${i}`));
		const next = mergeLivePage(existing, [row('new')]);
		expect(next.queries).toHaveLength(LIVE_CAP);
		expect(next.queries[0]?.id).toBe('new');
		expect(next.queries.at(-1)?.id).toBe(`old-${LIVE_CAP - 2}`);
	});
});
