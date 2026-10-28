// Query-log filter state. The URL is the source of truth: a draft (every value a string, named as
// the API parameter) is read from `?key=value` pairs and written back with the same names. Empty
// and default values are left out, so a bookmarked link stays short.
//
// `period` is URL-only: a preset (24h, 7d, 30d) is sent to the API as a `from` computed at request
// time. Only `custom` keeps the explicit `from`/`to` pair.

export const PROTOCOLS = ['udp53', 'tcp53', 'dot', 'doh', 'doq'] as const;
export const STATUSES = ['allowed', 'blocked', 'dnssec_bogus', 'servfail'] as const;
export const ORDER_BY = ['time', 'client', 'domain', 'rcode'] as const;
export const ORDERS = ['asc', 'desc'] as const;
/** Page sizes offered in the form; the URL may carry any positive value. */
export const PAGE_SIZES = ['25', '50', '100', '200'] as const;
export const PERIODS = ['24h', '7d', '30d', 'custom'] as const;

const PERIOD_DAYS: Record<string, number> = { '24h': 1, '7d': 7, '30d': 30 };

export const DEFAULT_LIMIT = '50';

/** Every filter and paging parameter of `GET /api/v1/query-log`, plus the URL-only `period`. */
export const FILTER_KEYS = [
	'period',
	'from',
	'to',
	'node_id',
	'client_id',
	'client_name_substr',
	'domain',
	'domain_substr',
	'protocol',
	'view_id',
	'profile_id',
	'status',
	'only_blocked',
	'only_with_clients',
	'order_by',
	'order',
	'limit',
	'offset',
] as const;

export type FilterKey = (typeof FILTER_KEYS)[number];
export type Draft = Record<FilterKey, string>;
/** Field key to the stable error code shown on that field. */
export type FieldErrors = Partial<Record<FilterKey, string>>;

export const INVALID_CODE = 'control_api.query_log.invalid';

/** The filters a user removes as one tag. Sorting and paging are not filters. */
export const FILTER_GROUPS: { id: string; keys: FilterKey[] }[] = [
	{ id: 'period', keys: ['period', 'from', 'to'] },
	{ id: 'domain', keys: ['domain'] },
	{ id: 'domain_substr', keys: ['domain_substr'] },
	{ id: 'client_id', keys: ['client_id'] },
	{ id: 'client_name_substr', keys: ['client_name_substr'] },
	{ id: 'node_id', keys: ['node_id'] },
	{ id: 'view_id', keys: ['view_id'] },
	{ id: 'profile_id', keys: ['profile_id'] },
	{ id: 'protocol', keys: ['protocol'] },
	{ id: 'status', keys: ['status'] },
	{ id: 'only_blocked', keys: ['only_blocked'] },
	{ id: 'only_with_clients', keys: ['only_with_clients'] },
];

const DEFAULTS: Partial<Record<FilterKey, string>> = {
	order_by: 'time',
	order: 'desc',
	limit: DEFAULT_LIMIT,
	offset: '0',
	only_blocked: 'false',
	only_with_clients: 'false',
};

const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:\d{2})$/;
const BOOLEAN_TRUE = ['true', '1'];
const BOOLEAN_FALSE = ['false', '0'];

export function emptyDraft(): Draft {
	return Object.fromEntries(FILTER_KEYS.map((key) => [key, ''])) as Draft;
}

/** Reads the draft from URL parameters; unknown parameters are ignored. */
export function draftFromSearch(search: URLSearchParams): Draft {
	const draft = emptyDraft();
	for (const key of FILTER_KEYS) draft[key] = (search.get(key) ?? '').trim();
	return draft;
}

/** Client-side checks that mirror the API rules, so most mistakes show inline before a request. */
export function validateDraft(draft: Draft): FieldErrors {
	const errors: FieldErrors = {};
	const bad = (key: FilterKey): void => {
		errors[key] = INVALID_CODE;
	};

	if (draft.period !== '' && !(PERIODS as readonly string[]).includes(draft.period)) {
		bad('period');
	}
	for (const key of ['from', 'to'] as const) {
		const value = draft[key];
		if (value !== '' && (!RFC3339.test(value) || Number.isNaN(Date.parse(value)))) bad(key);
	}
	if (!errors.from && !errors.to && draft.from !== '' && draft.to !== '') {
		if (Date.parse(draft.from) > Date.parse(draft.to)) bad('from');
	}
	if (draft.protocol !== '' && !(PROTOCOLS as readonly string[]).includes(draft.protocol)) {
		bad('protocol');
	}
	if (draft.status !== '' && !(STATUSES as readonly string[]).includes(draft.status)) bad('status');
	if (!(ORDER_BY as readonly string[]).includes(draft.order_by || 'time')) bad('order_by');
	if (!(ORDERS as readonly string[]).includes(draft.order || 'desc')) bad('order');
	for (const key of ['only_blocked', 'only_with_clients'] as const) {
		const value = draft[key];
		if (value !== '' && ![...BOOLEAN_TRUE, ...BOOLEAN_FALSE].includes(value)) bad(key);
	}
	if (draft.limit !== '' && !(/^\d+$/.test(draft.limit) && Number(draft.limit) >= 1)) bad('limit');
	if (draft.offset !== '' && !/^\d+$/.test(draft.offset)) bad('offset');
	return errors;
}

/** Canonical URL parameters for a draft: empty and default values are omitted. */
export function toSearchParams(draft: Draft): URLSearchParams {
	const params = new URLSearchParams();
	for (const key of FILTER_KEYS) {
		let value = draft[key].trim();
		if (key === 'only_blocked' || key === 'only_with_clients') {
			value = BOOLEAN_TRUE.includes(value) ? 'true' : '';
		}
		if (value === '' || value === DEFAULTS[key]) continue;
		params.set(key, value);
	}
	return params;
}

/**
 * Parameters for the API (list and export): `period` becomes a `from` relative to `now`, and
 * `from`/`to` are sent only for a custom period.
 */
export function toApiParams(draft: Draft, now: Date = new Date()): URLSearchParams {
	const params = toSearchParams(draft);
	params.delete('period');
	const days = PERIOD_DAYS[draft.period];
	if (days !== undefined) {
		params.delete('to');
		params.set('from', new Date(now.getTime() - days * 86_400_000).toISOString());
	}
	return params;
}

/** A new draft with `patch` applied. Changing any filter starts again at the first page. */
export function patchDraft(draft: Draft, patch: Partial<Draft>): Draft {
	const next: Draft = { ...draft, ...patch };
	if (!('offset' in patch)) next.offset = '';
	return next;
}

/** Whether a filter group narrows the result. */
export function isGroupActive(draft: Draft, keys: readonly FilterKey[]): boolean {
	return keys.some((key) => {
		const value = draft[key];
		if (key === 'only_blocked' || key === 'only_with_clients') return BOOLEAN_TRUE.includes(value);
		return value !== '';
	});
}

/** The filter groups a draft has active, in display order. */
export function activeGroups(draft: Draft): { id: string; keys: FilterKey[] }[] {
	return FILTER_GROUPS.filter((group) => isGroupActive(draft, group.keys));
}

/** Numeric page size and offset as the API reads them (defaults when empty). */
export function pageOf(draft: Draft): { limit: number; offset: number } {
	return {
		limit: draft.limit === '' ? Number(DEFAULT_LIMIT) : Number(draft.limit),
		offset: draft.offset === '' ? 0 : Number(draft.offset),
	};
}

/** Maps an API reason such as "`from` must not be after `to`" to the filter it names. */
export function fieldForReason(reason: string): FilterKey | null {
	const quoted = /`([a-z_]+)`/.exec(reason)?.[1];
	if (quoted && (FILTER_KEYS as readonly string[]).includes(quoted)) return quoted as FilterKey;
	const word = [...FILTER_KEYS]
		.sort((a, b) => b.length - a.length)
		.find((key) => new RegExp(`\\b${key}\\b`).test(reason));
	return word ?? null;
}

/** A `datetime-local` value (wall clock, no zone) as an RFC 3339 UTC instant; '' when invalid. */
export function localToRfc3339(local: string): string {
	if (local === '') return '';
	const instant = new Date(local);
	return Number.isNaN(instant.getTime()) ? '' : instant.toISOString();
}

/** An RFC 3339 instant as a `datetime-local` value in the local zone; '' when invalid. */
export function rfc3339ToLocal(value: string): string {
	const instant = new Date(value);
	if (value === '' || Number.isNaN(instant.getTime())) return '';
	const pad = (n: number): string => String(n).padStart(2, '0');
	return (
		`${instant.getFullYear()}-${pad(instant.getMonth() + 1)}-${pad(instant.getDate())}` +
		`T${pad(instant.getHours())}:${pad(instant.getMinutes())}`
	);
}
