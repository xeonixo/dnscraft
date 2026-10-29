// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import LiveRegion from '$lib/components/LiveRegion.svelte';
import Page from './+page.svelte';
import { endSession, setPrincipal } from '$lib/auth/state.svelte';
import { live } from '$lib/live.svelte';
import { m } from '$lib/paraglide/messages';

const json = (status: number, body: unknown): Response =>
	new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});
const ok = (data: unknown): Response => json(200, { data });
const fail = (status: number, code: string, params?: Record<string, unknown>): Response =>
	json(status, params ? { error: { code, params } } : { error: { code } });

type Handler = (init: RequestInit) => Response;

const status = { version: '0.9.0', ready: true, modules_not_ready: [], tls_mode: 'acme' };
const overview = {
	source: 'raw',
	total: 1000,
	allowed: 800,
	blocked: 200,
	allowed_ratio: 0.8,
	query_log_dropped: 0,
	by_answer_source: { resolver: 900, filter_block: 100 },
};
const topDomains = {
	domains: [
		{ domain: 'www.example.com', queries: 500, blocked: 0 },
		{ domain: 'ads.example.com', queries: 120, blocked: 120 },
	],
};
const topClients = {
	clients: [{ client_id: '192.0.2.11', client_name: 'iPhone', queries: 600, blocked: 50 }],
};
const cache = { hits: 600, misses: 400, hit_ratio: 0.6 };
const upstreams = {
	window_seconds: 300,
	items: [
		{
			name: 'dns.quad9.net',
			kind: 'forward_target',
			zone: '.',
			protocol: 'dot',
			state: 'up',
			rtt_ms: { p50: 18, p95: 41 },
			success_rate: 0.9997,
			samples: 40,
			last_error: null,
			last_checked: null,
		},
		{
			name: 'recursion',
			kind: 'recursion',
			zone: null,
			protocol: 'udp',
			state: 'degraded',
			rtt_ms: null,
			success_rate: 0.9,
			samples: 0,
			last_error: { code: 'resolver.timeout' },
			last_checked: null,
		},
	],
};

let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;
let handlers: Record<string, Handler>;

/** Routes by method and path; an unknown path answers the documented 404. */
function serve(overrides: Record<string, Handler> = {}): void {
	handlers = {
		'GET /api/v1/status': () => ok(status),
		'GET /readyz': () => ok({ ready: true }),
		'GET /api/v1/stats/overview': () => ok(overview),
		'GET /api/v1/stats/top_domains': () => ok(topDomains),
		'GET /api/v1/stats/top_clients': () => ok(topClients),
		'GET /api/v1/stats/cache': () => ok(cache),
		'GET /api/v1/resolver/upstreams': () => ok(upstreams),
		...overrides,
	};
	fetchMock.mockImplementation(async (input, init) => {
		const url = String(input);
		const method = init?.method ?? 'GET';
		const path = url.split('?')[0];
		const handler = handlers[`${method} ${path}`];
		return handler ? handler(init ?? {}) : fail(404, 'control_api.not_found');
	});
}

function callsTo(method: string, path: string): RequestInit[] {
	return fetchMock.mock.calls
		.filter(([url, init]) => (init?.method ?? 'GET') === method && String(url).startsWith(path))
		.map(([, init]) => init as RequestInit);
}

beforeEach(() => {
	fetchMock = vi.fn<typeof fetch>();
	vi.stubGlobal('fetch', fetchMock);
	endSession();
	setPrincipal({ role: 'admin', actorId: 'alice', actorType: 'user', csrfToken: 'tok-1' });
});

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
	vi.useRealTimers();
});

describe('dashboard tiles and panels', () => {
	it('shows the cluster summary when status includes cluster', async () => {
		serve({
			'GET /api/v1/status': () =>
				ok({
					...status,
					cluster: {
						role: 'master',
						master_reachable: true,
						applied_version: 3,
						lag: 0,
						queue_depth: 0,
						last_sync: null,
						degraded_nodes: 0,
					},
				}),
		});
		render(Page);

		expect(await screen.findByText(m.dashboard_cluster_header())).toBeInTheDocument();
		expect(screen.getByText(m.sidebar_node_master())).toBeInTheDocument();
		expect(screen.getByRole('link', { name: m.dashboard_cluster_open() })).toHaveAttribute(
			'href',
			'/cluster',
		);
	});

	it('renders the headline tiles with text and tone labels', async () => {
		serve();
		render(Page);

		expect(await screen.findByText('1,000')).toBeInTheDocument();
		expect(screen.getByText('800')).toBeInTheDocument();
		expect(screen.getByText('200')).toBeInTheDocument();
		// The block rate is the secondary text of the only accented tile.
		expect(screen.getByText('20% of all queries')).toBeInTheDocument();
		expect(screen.queryByText('80% of all queries')).toBeNull();
	});

	it('summarises health as a count of problems and names them', async () => {
		serve();
		render(Page);

		// The recursion upstream is degraded in the default fixture.
		expect(await screen.findByText('1 problem')).toBeInTheDocument();
		expect(screen.getByText('Recursion: Degraded')).toBeInTheDocument();
	});

	it('says All OK, names the reachable upstreams and folds their numbers when all are up', async () => {
		serve({
			'GET /api/v1/resolver/upstreams': () => ok({ ...upstreams, items: [upstreams.items[0]] }),
		});
		render(Page);

		expect(await screen.findByText('All OK')).toBeInTheDocument();
		expect(screen.getByText('All upstreams reachable (1)')).toBeInTheDocument();
		// No upstream card while everything is fine.
		expect(screen.queryByRole('heading', { name: 'Upstreams' })).toBeNull();
		const details = screen.getByText('Upstream details').closest('details');
		expect(details).not.toHaveAttribute('open');
		expect(within(details as HTMLElement).getByText('dns.quad9.net')).toBeInTheDocument();
		expect(within(details as HTMLElement).getByText('p50 18 ms · p95 41 ms')).toBeInTheDocument();
		expect(
			within(details as HTMLElement).getByText(m.dashboard_upstreams_footer({ minutes: '5' })),
		).toBeInTheDocument();
	});

	it('hides the success rate of an upstream without measurements', async () => {
		serve();
		render(Page);

		expect(await screen.findByText('No measurements yet')).toBeInTheDocument();
		expect(screen.queryByText('Success rate 90%')).toBeNull();
		expect(screen.getByText('Success rate 100%')).toBeInTheDocument();
	});

	it('lists only the affected upstream in the card and folds the healthy ones', async () => {
		serve();
		render(Page);

		const heading = await screen.findByRole('heading', { name: 'Upstreams' });
		const section = heading.closest('section') as HTMLElement;
		expect(within(section).getByText('Recursion')).toBeInTheDocument();
		expect(within(section).getByText('Degraded')).toBeInTheDocument();
		expect(within(section).getByText('Last error: resolver.timeout')).toBeInTheDocument();
		expect(
			within(section).getByText(m.dashboard_upstreams_footer({ minutes: '5' })),
		).toBeInTheDocument();

		// The healthy upstream sits behind a collapsed disclosure with its latency and success rate.
		const folded = within(section).getByText('+1 more OK').closest('details') as HTMLElement;
		expect(folded).not.toHaveAttribute('open');
		expect(within(folded).getByText('dns.quad9.net')).toBeInTheDocument();
		expect(within(folded).getByText('p50 18 ms · p95 41 ms')).toBeInTheDocument();
		expect(within(folded).getByText('Success rate 100%')).toBeInTheDocument();
		expect(within(folded).queryByText('Recursion')).toBeNull();
		expect(screen.queryByText('Upstream details')).toBeNull();
	});

	it('shows the cache hit ratio and the top lists', async () => {
		serve();
		render(Page);

		expect((await screen.findAllByText('60%')).length).toBeGreaterThan(0);
		expect(screen.getByText('www.example.com')).toBeInTheDocument();
		expect(screen.getByText('iPhone')).toBeInTheDocument();
		// Listed in both the top domains and the top blocked domains lists.
		expect(screen.getAllByText('ads.example.com')).toHaveLength(2);
	});

	it('renders a domain with markup as inert text', async () => {
		serve({
			'GET /api/v1/stats/top_domains': () =>
				ok({ domains: [{ domain: '<script>alert(1)</script>', queries: 3, blocked: 3 }] }),
		});
		const { container } = render(Page);

		expect(await screen.findAllByText('<script>alert(1)</script>')).not.toHaveLength(0);
		expect(container.querySelector('script')).toBeNull();
	});

	it('shows the unavailable state for a 404 and keeps the other panels', async () => {
		serve({
			'GET /api/v1/stats/overview': () => fail(404, 'control_api.not_found'),
		});
		render(Page);

		expect(await screen.findByText(m.dashboard_unavailable_title())).toBeInTheDocument();
		expect(screen.queryByText('1,000')).toBeNull();
		expect(screen.getByText('www.example.com')).toBeInTheDocument();
	});

	it('shows the error notice with its code when a read fails', async () => {
		serve({
			'GET /api/v1/stats/cache': () => fail(500, 'control_api.internal'),
		});
		render(Page);

		expect(await screen.findByText(m.error_control_api_internal())).toBeInTheDocument();
		expect(screen.getByText('control_api.internal')).toBeInTheDocument();
	});

	it('refetches the selected range when the period changes', async () => {
		serve();
		const user = userEvent.setup();
		render(Page);
		await screen.findByText('1,000');

		await user.click(screen.getByRole('radio', { name: '7 d' }));
		await waitFor(() => {
			const overviewUrls = fetchMock.mock.calls
				.map(([url]) => String(url))
				.filter((url) => url.includes('/stats/overview'));
			expect(overviewUrls.some((url) => url.includes('from='))).toBe(true);
		});
		const last = fetchMock.mock.calls
			.map(([url]) => String(url))
			.filter((url) => url.includes('/stats/overview'))
			.at(-1);
		const params = new URLSearchParams(last?.split('?')[1]);
		const span = Date.parse(params.get('to') ?? '') - Date.parse(params.get('from') ?? '');
		expect(span).toBe(7 * 86_400_000);
	});
});

describe('self-signed bootstrap banner', () => {
	it('is shown with the fingerprint while the certificate is self-signed', async () => {
		serve({
			'GET /api/v1/status': () =>
				ok({
					...status,
					tls_mode: 'self_signed',
					tls_fingerprint: '3a9c7f11de42',
					tls: { identifiers: ['node1.dns.example.com'] },
				}),
		});
		render(Page);

		expect(await screen.findByText(m.dashboard_selfsigned_title())).toBeInTheDocument();
		expect(screen.getByText('3A:9C:7F:11:DE:42')).toBeInTheDocument();
		expect(screen.getByRole('link', { name: m.dashboard_tls_link() })).toHaveAttribute(
			'href',
			'/tls',
		);
	});

	it('is hidden for an ACME certificate', async () => {
		serve();
		render(Page);

		await screen.findByText('1,000');
		expect(screen.queryByText(m.dashboard_selfsigned_title())).toBeNull();
	});
});

describe('contextual admin actions', () => {
	beforeEach(() => {
		// The polite region lives in the root layout; the page tests mount it next to the screen.
		render(LiveRegion);
	});

	it('shows no pause or cache controls to a viewer', async () => {
		endSession();
		setPrincipal({ role: 'viewer', actorId: 'bob', actorType: 'user', csrfToken: null });
		serve();
		render(Page);

		await screen.findByText('1,000');
		expect(screen.queryByRole('button', { name: /Pause filtering/ })).toBeNull();
		expect(screen.queryByRole('button', { name: m.dashboard_cache_clear() })).toBeNull();
	});

	it('shows the pause and cache controls to an admin', async () => {
		serve();
		render(Page);

		await screen.findByText('1,000');
		expect(
			screen.getByRole('button', { name: m.dashboard_pause_title({ duration: '5 minutes' }) }),
		).toBeInTheDocument();
		const clear = screen.getByRole('button', { name: m.dashboard_cache_clear() });
		expect(clear).toHaveTextContent(m.dashboard_cache_clear_short());
	});

	it('confirms a pause in a sheet, posts the body with the CSRF header and announces it', async () => {
		serve({
			'POST /api/v1/filtering/pause': () =>
				ok({ filter_set_id: 'default', paused_until: '2026-10-28T12:05:00Z' }),
		});
		const user = userEvent.setup();
		render(Page);
		await screen.findByText('1,000');

		await user.click(
			screen.getByRole('button', { name: m.dashboard_pause_title({ duration: '5 minutes' }) }),
		);
		const dialog = screen.getByRole('dialog', {
			name: m.dashboard_pause_title({ duration: '5 minutes' }),
		});
		expect(within(dialog).getByText(/default/)).toBeInTheDocument();

		await user.click(within(dialog).getByRole('button', { name: m.dashboard_pause_confirm() }));

		await waitFor(() => expect(callsTo('POST', '/api/v1/filtering/pause')).toHaveLength(1));
		const [init] = callsTo('POST', '/api/v1/filtering/pause');
		expect(JSON.parse(String(init?.body))).toEqual({ filter_set_id: 'default', duration: 'PT5M' });
		expect((init?.headers as Record<string, string>)['X-CSRF-Token']).toBe('tok-1');
		expect(await screen.findByText(/Filtering paused until/)).toBeInTheDocument();
		expect(live.message).toMatch(/Filtering paused until/);
		expect(screen.queryByRole('dialog')).toBeNull();
	});

	it('keeps a banner with a resume button while a pause runs and resumes through the api', async () => {
		const until = new Date(Date.now() + 10 * 60_000).toISOString();
		serve({
			'GET /api/v1/filtering/mcp-rules': () =>
				ok({ pauses: [{ paused_until: until }], has_more: false, next_offset: null }),
			'POST /api/v1/filtering/resume': () => ok({ filter_set_id: 'default' }),
		});
		const user = userEvent.setup();
		render(Page);
		expect(await screen.findByText(m.dashboard_paused_title())).toBeInTheDocument();
		await user.click(screen.getByRole('button', { name: m.dashboard_resume() }));
		await waitFor(() => expect(callsTo('POST', '/api/v1/filtering/resume')).toHaveLength(1));
		await waitFor(() => expect(screen.queryByText(m.dashboard_paused_title())).toBeNull());
	});

	it('clears the whole cache from a sheet and announces the evicted count', async () => {
		serve({
			'POST /api/v1/resolver/cache/flush': () => ok({ scope: 'all', domain: null, evicted: 42 }),
		});
		const user = userEvent.setup();
		render(Page);
		await screen.findByText('1,000');

		await user.click(screen.getByRole('button', { name: m.dashboard_cache_clear() }));
		const dialog = screen.getByRole('dialog', { name: m.dashboard_cache_title() });
		await user.click(within(dialog).getByRole('button', { name: m.dashboard_cache_confirm() }));

		expect(
			await screen.findByText(m.dashboard_cache_success_all({ count: '42' })),
		).toBeInTheDocument();
		expect(JSON.parse(String(callsTo('POST', '/api/v1/resolver/cache/flush')[0]?.body))).toEqual(
			{},
		);
	});

	it('validates a single-domain flush before posting it', async () => {
		serve({
			'POST /api/v1/resolver/cache/flush': () =>
				ok({ scope: 'domain', domain: 'example.com', evicted: 3 }),
		});
		const user = userEvent.setup();
		render(Page);
		await screen.findByText('1,000');

		await user.click(screen.getByRole('button', { name: m.dashboard_cache_clear() }));
		const dialog = screen.getByRole('dialog', { name: m.dashboard_cache_title() });
		await user.click(within(dialog).getByRole('radio', { name: m.dashboard_cache_scope_domain() }));
		const input = within(dialog).getByRole('textbox', { name: m.dashboard_cache_domain_label() });

		await user.type(input, '*.example.com');
		await user.click(within(dialog).getByRole('button', { name: m.dashboard_cache_confirm() }));
		expect(await within(dialog).findByText(m.dashboard_cache_domain_invalid())).toBeInTheDocument();
		expect(callsTo('POST', '/api/v1/resolver/cache/flush')).toHaveLength(0);

		await user.clear(input);
		await user.type(input, 'Example.com.');
		await user.click(within(dialog).getByRole('button', { name: m.dashboard_cache_confirm() }));

		await waitFor(() => expect(callsTo('POST', '/api/v1/resolver/cache/flush')).toHaveLength(1));
		expect(JSON.parse(String(callsTo('POST', '/api/v1/resolver/cache/flush')[0]?.body))).toEqual({
			domain: 'example.com',
		});
		expect(
			await screen.findByText(
				m.dashboard_cache_success_domain({ domain: 'example.com', count: '3' }),
			),
		).toBeInTheDocument();
	});
});

describe('polling lifecycle', () => {
	it('polls the status every 30 seconds and stops when the page is destroyed', async () => {
		vi.useFakeTimers();
		serve();
		const view = render(Page);
		await vi.advanceTimersByTimeAsync(0);
		expect(callsTo('GET', '/api/v1/status')).toHaveLength(1);

		await vi.advanceTimersByTimeAsync(30_000);
		expect(callsTo('GET', '/api/v1/status')).toHaveLength(2);

		view.unmount();
		await vi.advanceTimersByTimeAsync(120_000);
		expect(callsTo('GET', '/api/v1/status')).toHaveLength(2);
	});
});
