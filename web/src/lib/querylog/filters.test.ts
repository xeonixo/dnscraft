import { describe, expect, it } from 'vitest';
import {
	FILTER_KEYS,
	activeGroups,
	toApiParams,
	draftFromSearch,
	emptyDraft,
	fieldForReason,
	localToRfc3339,
	pageOf,
	patchDraft,
	rfc3339ToLocal,
	toSearchParams,
	validateDraft,
	type Draft,
} from './filters';

function draftOf(query: string): Draft {
	return draftFromSearch(new URLSearchParams(query));
}

describe('URL to draft to URL round trip', () => {
	it('keeps every documented parameter across a round trip', () => {
		const query =
			'from=2026-10-27T10:00:00Z&to=2026-10-27T12:00:00Z&node_id=node1&client_id=iphone-k7q2x9' +
			'&client_name_substr=phone&domain=ads.example.com&domain_substr=example&protocol=doh' +
			'&view_id=lan&profile_id=default&status=blocked&only_blocked=true&only_with_clients=true' +
			'&order_by=domain&order=asc&limit=200&offset=400';
		const first = toSearchParams(draftOf(query));
		const second = toSearchParams(draftFromSearch(first));
		expect(second.toString()).toBe(first.toString());
		expect(Object.fromEntries(first)).toEqual(Object.fromEntries(new URLSearchParams(query)));
	});

	it('drops empty values and defaults so the link stays short', () => {
		const params = toSearchParams(
			draftOf('domain=&order_by=time&order=desc&limit=50&offset=0&only_blocked=false'),
		);
		expect(params.toString()).toBe('');
	});

	it('normalises boolean spellings to true and omits false', () => {
		expect(toSearchParams(draftOf('only_blocked=1')).get('only_blocked')).toBe('true');
		expect(toSearchParams(draftOf('only_blocked=0')).has('only_blocked')).toBe(false);
	});

	it('ignores parameters the API does not define', () => {
		const draft = draftOf('evil=1&domain=a.example');
		expect(Object.keys(draft)).toEqual([...FILTER_KEYS]);
		expect(toSearchParams(draft).toString()).toBe('domain=a.example');
	});
});

describe('validateDraft', () => {
	it('accepts an empty draft', () => {
		expect(validateDraft(emptyDraft())).toEqual({});
	});

	it('flags unknown enum values on the offending field only', () => {
		const errors = validateDraft({ ...emptyDraft(), protocol: 'udp', status: 'blocked' });
		expect(errors).toEqual({ protocol: 'control_api.query_log.invalid' });
	});

	it('flags timestamps that are not RFC 3339 and a range that ends before it starts', () => {
		expect(validateDraft({ ...emptyDraft(), from: 'yesterday' })).toEqual({
			from: 'control_api.query_log.invalid',
		});
		const reversed = validateDraft({
			...emptyDraft(),
			from: '2026-10-27T12:00:00Z',
			to: '2026-10-27T10:00:00Z',
		});
		expect(reversed).toEqual({ from: 'control_api.query_log.invalid' });
	});

	it('checks paging and booleans', () => {
		expect(validateDraft({ ...emptyDraft(), limit: '0' })).toEqual({
			limit: 'control_api.query_log.invalid',
		});
		expect(validateDraft({ ...emptyDraft(), offset: '-1' })).toEqual({
			offset: 'control_api.query_log.invalid',
		});
		expect(validateDraft({ ...emptyDraft(), only_blocked: 'maybe' })).toEqual({
			only_blocked: 'control_api.query_log.invalid',
		});
	});
});

describe('patchDraft and counts', () => {
	it('starts again at the first page when a filter changes', () => {
		const paged = draftOf('offset=300&limit=50');
		expect(patchDraft(paged, { domain_substr: 'x' }).offset).toBe('');
		expect(patchDraft(paged, { offset: '350' }).offset).toBe('350');
	});

	it('counts narrowing filters but not sorting or paging', () => {
		expect(activeGroups(draftOf('order_by=domain&limit=100&offset=50'))).toEqual([]);
		expect(
			activeGroups(draftOf('domain=a.example&only_blocked=true&order=asc')).map((g) => g.id),
		).toEqual(['domain', 'only_blocked']);
	});

	it('reads the page size and offset with defaults', () => {
		expect(pageOf(emptyDraft())).toEqual({ limit: 50, offset: 0 });
		expect(pageOf(draftOf('limit=25&offset=75'))).toEqual({ limit: 25, offset: 75 });
	});
});

describe('fieldForReason', () => {
	it('maps the backticked parameter the API names', () => {
		expect(fieldForReason('`from` must not be after `to`')).toBe('from');
		expect(fieldForReason('`protocol` must be one of udp53, tcp53')).toBe('protocol');
	});

	it('maps pagination reasons that name a bare parameter', () => {
		expect(fieldForReason('limit must be at least 1, got `0`')).toBe('limit');
	});

	it('returns null when no filter is named', () => {
		expect(fieldForReason('something else entirely')).toBeNull();
	});
});

describe('local date conversion', () => {
	it('round-trips a wall-clock value through UTC', () => {
		const local = '2026-10-27T14:30';
		expect(rfc3339ToLocal(localToRfc3339(local))).toBe(local);
	});

	it('returns empty strings for empty or invalid input', () => {
		expect(localToRfc3339('')).toBe('');
		expect(localToRfc3339('not a date')).toBe('');
		expect(rfc3339ToLocal('nope')).toBe('');
	});
});

describe('period and API parameters', () => {
	const now = new Date('2026-10-27T12:00:00Z');

	it('turns a preset into a from relative to now and drops the URL-only period', () => {
		const params = toApiParams(draftOf('period=7d'), now);
		expect(params.has('period')).toBe(false);
		expect(params.get('from')).toBe('2026-10-20T12:00:00.000Z');
		expect(params.has('to')).toBe(false);
	});

	it('uses the 24 h default when no period and no explicit range is given', () => {
		const params = toApiParams(draftOf(''), now);
		expect(params.get('from')).toBe(new Date(now.getTime() - 86_400_000).toISOString());
		expect(toApiParams(draftOf('from=2026-10-26T00:00:00Z'), now).get('from')).toBe(
			'2026-10-26T00:00:00Z',
		);
	});

	it('turns the short presets into minutes-wide windows', () => {
		expect(toApiParams(draftOf('period=15m'), now).get('from')).toBe(
			new Date(now.getTime() - 15 * 60_000).toISOString(),
		);
		expect(toApiParams(draftOf('period=1h'), now).get('from')).toBe(
			new Date(now.getTime() - 3_600_000).toISOString(),
		);
	});

	it('sends an explicit from and to only for a custom period', () => {
		const params = toApiParams(
			draftOf('period=custom&from=2026-10-26T00:00:00Z&to=2026-10-27T00:00:00Z'),
			now,
		);
		expect(params.get('from')).toBe('2026-10-26T00:00:00Z');
		expect(params.get('to')).toBe('2026-10-27T00:00:00Z');
	});

	it('rejects an unknown period', () => {
		expect(validateDraft(draftOf('period=1y'))).toEqual({
			period: 'control_api.query_log.invalid',
		});
	});
});
