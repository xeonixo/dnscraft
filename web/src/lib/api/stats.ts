import { ApiError, get, post } from './client';
import { NOT_READY_CODE } from './result';

// Typed reads and writes for the dashboard. Only the fields the UI renders are declared; shapes
// follow the handlers in crates/dnscraft-api (stats_routes.rs, resolver_routes.rs, router.rs).

export type TlsMode = 'acme' | 'manual' | 'self_signed';
export type Period = '24h' | '7d' | '30d' | '1y';
export type PauseDuration = 'PT5M' | 'PT15M' | 'PT1H';
export type UpstreamState = 'up' | 'degraded' | 'down' | 'unknown';

/** Filter set the pause and resume endpoints default to when no id is sent. */
export const FILTER_SET = 'default';

export const PERIODS: readonly Period[] = ['24h', '7d', '30d', '1y'];

const DAY_MS = 86_400_000;
const PERIOD_MS: Record<Period, number> = {
	'24h': DAY_MS,
	'7d': 7 * DAY_MS,
	'30d': 30 * DAY_MS,
	'1y': 365 * DAY_MS,
};

export interface StatusData {
	version: string;
	ready: boolean;
	modules_not_ready: string[];
	tls_mode?: TlsMode;
	tls_fingerprint?: string;
	tls?: { identifiers?: string[] };
}

export interface Readiness {
	ready: boolean;
	modules: string[];
}

export interface StatsOverview {
	source: 'raw' | 'rollup';
	total: number;
	allowed: number;
	blocked: number;
	allowed_ratio: number;
	query_log_dropped: number;
	by_answer_source: Record<string, number>;
}

export interface TopDomain {
	domain: string;
	queries: number;
	blocked: number;
}

export interface TopClient {
	client_id: string;
	client_name: string;
	queries: number;
	blocked: number;
}

export interface CacheStats {
	hits: number;
	misses: number;
	hit_ratio: number;
}

export interface Upstream {
	name: string;
	kind: 'forward_target' | 'recursion';
	zone: string | null;
	protocol: string;
	state: UpstreamState;
	rtt_ms: { p50: number; p95: number } | null;
	success_rate: number | null;
	samples: number;
	last_error: { code: string } | null;
	last_checked: string | null;
}

export interface UpstreamsData {
	window_seconds: number;
	items: Upstream[];
}

export interface FlushResult {
	scope: 'all' | 'domain';
	domain: string | null;
	evicted: number;
}

export interface PauseResult {
	filter_set_id: string;
	paused_until: string;
}

/** `from` and `to` as RFC 3339 instants for the period ending at `now`. */
export function periodQuery(period: Period, now: Date = new Date()): string {
	const to = now.getTime();
	const from = to - PERIOD_MS[period];
	return new URLSearchParams({
		from: new Date(from).toISOString(),
		to: new Date(to).toISOString(),
	}).toString();
}

export const getStatus = (): Promise<StatusData> => get<StatusData>('/status');

/** `GET /readyz` is outside `/api/v1`. A 503 `not_ready` is an answer with the starting modules. */
export async function getReadiness(): Promise<Readiness> {
	try {
		await get<unknown>('/readyz', { root: true, public: true });
		return { ready: true, modules: [] };
	} catch (cause) {
		if (cause instanceof ApiError && cause.code === NOT_READY_CODE) {
			const modules = cause.params.modules;
			return {
				ready: false,
				modules: Array.isArray(modules)
					? modules.filter((item): item is string => typeof item === 'string')
					: [],
			};
		}
		throw cause;
	}
}

export const getOverview = (period: Period, now?: Date): Promise<StatsOverview> =>
	get<StatsOverview>(`/stats/overview?${periodQuery(period, now)}`);

export const getTopDomains = (period: Period, limit: number, now?: Date): Promise<TopDomain[]> =>
	get<{ domains: TopDomain[] }>(
		`/stats/top_domains?${periodQuery(period, now)}&limit=${limit}`,
	).then((data) => data.domains);

export const getTopClients = (period: Period, limit: number, now?: Date): Promise<TopClient[]> =>
	get<{ clients: TopClient[] }>(
		`/stats/top_clients?${periodQuery(period, now)}&limit=${limit}`,
	).then((data) => data.clients);

export const getCacheStats = (period: Period, now?: Date): Promise<CacheStats> =>
	get<CacheStats>(`/stats/cache?${periodQuery(period, now)}`);

export const getUpstreams = (): Promise<UpstreamsData> => get<UpstreamsData>('/resolver/upstreams');

/** Admin. An absent domain flushes the whole cache; a domain also removes everything below it. */
export const flushCache = (domain: string | null): Promise<FlushResult> =>
	post<FlushResult>('/resolver/cache/flush', { body: domain === null ? {} : { domain } });

/** Admin. Pauses blocking on one filter set for a fixed duration; audited by the server. */
export const pauseFilterSet = (duration: PauseDuration): Promise<PauseResult> =>
	post<PauseResult>('/filtering/pause', {
		body: { filter_set_id: FILTER_SET, duration },
	});
