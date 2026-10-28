import { get, post } from './client';

// Typed reads and the temporary-allow write for the query log. Shapes follow
// crates/dnscraft-api/src/query_log.rs (record JSON), query_log_routes.rs (list envelope) and
// mcp_endpoints.rs (temporary allows). Only fields the UI renders are declared.

export type Protocol = 'udp53' | 'tcp53' | 'dot' | 'doh' | 'doq';
export type TempAllowDuration = 'PT5M' | 'PT15M' | 'PT1H';

export interface QueryClient {
	id: string;
	display_name: string;
	source: string;
	macs: string[];
	vlan_id: number | null;
	vlan_name: string | null;
	local_domain: string | null;
}

/** One ordered decision step. `stage` and `verdict` are stable identifiers; the rest is per stage. */
export interface DecisionStep {
	stage: string;
	verdict: string;
	[detail: string]: unknown;
}

export interface FilterHit {
	reason: string;
	block_mode: string | null;
	rule_text: string | null;
	list_id: string | null;
	important: boolean;
}

export interface QueryRecord {
	id: string;
	node_id: string;
	listener_id: string;
	protocol: Protocol;
	source_ip: string;
	source_ip_truncated: boolean;
	client_id: string | null;
	client: QueryClient | null;
	query: { name: string; type: string; class: string };
	view_id: string;
	profile_id: string;
	filter_set?: string;
	/** `client_id`: the request was pinned to a Netzbereich through its Client ID (no subnet matched). */
	selection: { cause: 'subnet' | 'default' | 'client_id'; prefix?: string };
	steps: DecisionStep[];
	answer_source: string;
	filter: FilterHit | null;
	dnssec: string | null;
	forward_zone: string | null;
	rcode: string;
	answer_size: number;
	timings: { select_us: number; filter_us: number; resolve_us: number; total_us: number };
	time: string;
}

export interface QueryPage {
	queries: QueryRecord[];
	has_more: boolean;
	next_offset: number | null;
}

export interface TempAllowBody {
	domain: string;
	include_subdomains: boolean;
	duration: TempAllowDuration;
	filter_set_id?: string;
}

export interface TempAllowResult {
	domain: string;
	include_subdomains: boolean;
	created_at: string;
	expires_at: string;
	filter_set_id: string;
}

/** `GET /api/v1/query-log` with the canonical parameters from `toSearchParams`. */
export const listQueryLog = (query: URLSearchParams): Promise<QueryPage> =>
	get<QueryPage>(`/query-log?${query.toString()}`);

export const getQueryRecord = (id: string): Promise<QueryRecord> =>
	get<QueryRecord>(`/query-log/${encodeURIComponent(id)}`);

/**
 * Same-origin export link for the current filters. Paging is dropped (the export covers the whole
 * filtered set). The link is a plain GET: no token and no body are involved.
 */
export function exportHref(format: 'ndjson' | 'csv', query: URLSearchParams): string {
	const params = new URLSearchParams(query);
	params.delete('limit');
	params.delete('offset');
	const search = params.toString();
	return `/api/v1/query-log/export.${format}${search === '' ? '' : `?${search}`}`;
}

/** Admin. Allows one domain for a fixed duration; the server audits it. */
export const allowTemporarily = (body: TempAllowBody): Promise<TempAllowResult> =>
	post<TempAllowResult>('/filtering/temporary-allows', { body });
