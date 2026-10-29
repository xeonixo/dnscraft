// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import Page from './+page.svelte';
import type { QueryRecord } from '$lib/api/query-log';
import { endSession, setPrincipal } from '$lib/auth/state.svelte';
import { m } from '$lib/paraglide/messages';
import { TECHNICAL_KEY } from '$lib/querylog/density';

const nav = vi.hoisted(() => ({ goto: vi.fn() }));
const pageState = vi.hoisted(() => ({ url: new URL('http://localhost/query-log') }));
vi.mock('$app/navigation', () => nav);
vi.mock('$app/state', () => ({ page: pageState }));

/** Minimal EventSource so the always-on live effect does not throw in jsdom. */
class FakeEventSource {
	static instances: FakeEventSource[] = [];
	readonly url: string;
	onerror: ((ev: Event) => void) | null = null;
	onopen: ((ev: Event) => void) | null = null;
	private readonly listeners = new Map<string, Set<(event: MessageEvent<string>) => void>>();

	constructor(url: string) {
		this.url = url;
		FakeEventSource.instances.push(this);
	}

	addEventListener(type: string, listener: EventListenerOrEventListenerObject): void {
		const set = this.listeners.get(type) ?? new Set();
		set.add(listener as (event: MessageEvent<string>) => void);
		this.listeners.set(type, set);
	}

	close(): void {
		/* noop */
	}

	emit(type: string, data: string): void {
		const event = { data } as MessageEvent<string>;
		for (const listener of this.listeners.get(type) ?? []) listener(event);
	}
}

const json = (status: number, body: unknown): Response =>
	new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});
const ok = (data: unknown): Response => json(200, { data });
const fail = (status: number, code: string, params?: Record<string, unknown>): Response =>
	json(status, params ? { error: { code, params } } : { error: { code } });

type Handler = (url: URL) => Response;

let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;
let handlers: Record<string, Handler>;

function serve(overrides: Record<string, Handler> = {}): void {
	handlers = {
		'/api/v1/query-log': () => ok({ queries: [], has_more: false, next_offset: null }),
		'/api/v1/stats/overview': () =>
			ok({
				source: 'raw',
				total: 0,
				allowed: 0,
				blocked: 0,
				allowed_ratio: 0,
				query_log_dropped: 0,
				by_answer_source: {},
			}),
		...overrides,
	};
	fetchMock.mockImplementation(async (input) => {
		const url = new URL(String(input), 'http://localhost');
		const handler = handlers[url.pathname];
		return handler ? handler(url) : fail(404, 'control_api.not_found');
	});
}

/** The URLs the page requested, without their origin. */
function requested(path: string): string[] {
	return fetchMock.mock.calls
		.map(([input]) => new URL(String(input), 'http://localhost'))
		.filter((url) => url.pathname === path)
		.map((url) => `${url.pathname}${url.search}`);
}

function setUrl(query: string): void {
	pageState.url = new URL(`http://localhost/query-log${query ? `?${query}` : ''}`);
}

function setWide(wide: boolean): void {
	vi.stubGlobal('matchMedia', (query: string) => ({
		matches: wide && query.includes('64rem'),
		addEventListener: () => undefined,
		removeEventListener: () => undefined,
	}));
}

function record(id: string, overrides: Partial<QueryRecord> = {}): QueryRecord {
	return {
		id,
		node_id: 'node1',
		listener_id: 'lan-udp',
		protocol: 'doh',
		source_ip: '192.0.2.11',
		source_ip_truncated: true,
		client_id: 'iphone-k7q2x9',
		client: {
			id: 'c1',
			display_name: 'iPhone',
			source: 'unifi',
			macs: [],
			vlan_id: null,
			vlan_name: null,
			local_domain: null,
		},
		query: { name: 'ads.example.com', type: 'A', class: 'IN' },
		view_id: 'lan',
		profile_id: 'default',
		filter_set: 'default',
		selection: { cause: 'subnet', prefix: '192.0.2.0/24' },
		steps: [{ stage: 'filter_qname', verdict: 'blocked' }],
		answer_source: 'filter_block',
		filter: {
			reason: 'list',
			block_mode: 'nxdomain',
			rule_text: '||ads.example.com^',
			list_id: 'adguard',
			important: false,
		},
		dnssec: null,
		forward_zone: null,
		rcode: 'NXDOMAIN',
		answer_size: 0,
		timings: { select_us: 2000, filter_us: 8000, resolve_us: 0, total_us: 10000 },
		time: '2026-10-27T12:00:00.000000Z',
		...overrides,
	};
}

function pageOf(queries: QueryRecord[], extra: Record<string, unknown> = {}): Response {
	return ok({ queries, has_more: false, next_offset: null, ...extra });
}

beforeEach(() => {
	fetchMock = vi.fn<typeof fetch>();
	vi.stubGlobal('fetch', fetchMock);
	FakeEventSource.instances = [];
	vi.stubGlobal('EventSource', FakeEventSource);
	nav.goto.mockReset();
	endSession();
	setPrincipal({ role: 'admin', actorId: 'alice', actorType: 'user', csrfToken: 'tok' });
	localStorage.clear();
	setWide(false);
	setUrl('');
});

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

describe('filters and the URL', () => {
	it('loads the list with the parameters the URL holds', async () => {
		setUrl('domain_substr=ads&protocol=doh&limit=25');
		serve();
		render(Page);

		// No period in the URL means the default 24 h window, sent as a relative `from`.
		await waitFor(() =>
			expect(
				requested('/api/v1/query-log').some((url) =>
					url.startsWith('/api/v1/query-log?domain_substr=ads&protocol=doh&limit=25&from='),
				),
			).toBe(true),
		);
	});

	it('writes applied filters back to the URL with replaceState', async () => {
		setUrl('domain_substr=ads&protocol=doh&limit=25');
		serve();
		const user = userEvent.setup();
		render(Page);

		await user.click(screen.getByRole('button', { name: m.querylog_filter_open() }));
		const dialog = await screen.findByRole('dialog');
		await user.selectOptions(within(dialog).getByLabelText(m.querylog_protocol()), 'dot');
		await user.click(within(dialog).getByRole('button', { name: m.querylog_filter_apply() }));

		expect(nav.goto).toHaveBeenCalledTimes(1);
		const [target, options] = nav.goto.mock.calls[0] as [string, Record<string, unknown>];
		const params = new URL(target, 'http://localhost').searchParams;
		expect(params.get('protocol')).toBe('dot');
		expect(params.get('domain_substr')).toBe('ads');
		expect(params.get('limit')).toBe('25');
		expect(options).toMatchObject({ replaceState: true });
	});

	it('resets every filter with the reset action', async () => {
		setUrl('domain_substr=ads&status=blocked');
		serve();
		const user = userEvent.setup();
		render(Page);

		await user.click(screen.getByRole('button', { name: m.querylog_filter_open() }));
		const dialog = await screen.findByRole('dialog');
		await user.click(within(dialog).getByRole('button', { name: m.querylog_filter_reset() }));

		expect(nav.goto).toHaveBeenCalledWith('/query-log', expect.anything());
	});

	it('debounces the search box into domain_substr', async () => {
		serve();
		const user = userEvent.setup();
		render(Page);

		await user.type(screen.getByRole('searchbox', { name: m.querylog_search_label() }), 'ads');
		await waitFor(() =>
			expect(nav.goto).toHaveBeenCalledWith(
				expect.stringContaining('domain_substr=ads'),
				expect.anything(),
			),
		);
		expect(nav.goto).toHaveBeenCalledTimes(1);
	});
});

describe('invalid filters', () => {
	it('shows an invalid URL value inline in the filter sheet and does not query the API', async () => {
		setUrl('protocol=udp');
		serve();
		const user = userEvent.setup();
		render(Page);

		await user.click(screen.getByRole('button', { name: m.querylog_filter_open() }));
		const dialog = await screen.findByRole('dialog');
		const select = within(dialog).getByLabelText(m.querylog_protocol());
		expect(select).toHaveAttribute('aria-invalid', 'true');
		expect(within(dialog).getByText(m.error_control_api_query_log_invalid())).toBeInTheDocument();
		expect(requested('/api/v1/query-log')).toEqual([]);
		expect(screen.getByText(m.querylog_fix_filters())).toBeInTheDocument();
	});

	it('maps a server rejection back to the field the reason names', async () => {
		setUrl('node_id=n1');
		serve({
			'/api/v1/query-log': () =>
				fail(400, 'control_api.query_log.invalid', {
					reason: '`node_id` must not be empty',
				}),
		});
		const user = userEvent.setup();
		render(Page);

		await user.click(screen.getByRole('button', { name: m.querylog_filter_open() }));
		const dialog = await screen.findByRole('dialog');
		await waitFor(() =>
			expect(within(dialog).getByLabelText(m.querylog_node_id())).toHaveAttribute(
				'aria-invalid',
				'true',
			),
		);
		expect(screen.queryByRole('alert')).not.toBeInTheDocument();
	});
});

describe('prototype structure: sheet, quick segments, tags and summary', () => {
	it('opens the filter sheet on wide screens too and returns focus to the Filter button', async () => {
		setWide(true);
		serve();
		const user = userEvent.setup();
		render(Page);

		const trigger = screen.getByRole('button', { name: m.querylog_filter_open() });
		await user.click(trigger);
		expect(await screen.findByRole('dialog')).toBeInTheDocument();
		await user.keyboard('{Escape}');
		await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
		expect(trigger).toHaveFocus();
	});

	it('keeps the detailed filters out of the page until the sheet opens', async () => {
		setWide(true);
		serve();
		render(Page);

		expect(screen.queryByLabelText(m.querylog_domain_exact())).not.toBeInTheDocument();
		expect(
			screen.queryByRole('switch', { name: m.querylog_only_blocked() }),
		).not.toBeInTheDocument();
	});

	it('removing a tag clears its filter in the URL', async () => {
		setUrl('domain_substr=ads&protocol=doh');
		serve();
		const user = userEvent.setup();
		render(Page);

		await user.click(
			screen.getByRole('button', {
				name: m.querylog_tag_remove({ filter: m.querylog_domain_contains() }),
			}),
		);
		const [target] = nav.goto.mock.calls.at(-1) as [string];
		const params = new URL(target, 'http://localhost').searchParams;
		expect(params.has('domain_substr')).toBe(false);
		expect(params.get('protocol')).toBe('doh');
	});

	it('the reset link clears every filter', async () => {
		setUrl('domain_substr=ads&protocol=doh');
		serve();
		const user = userEvent.setup();
		render(Page);

		await user.click(screen.getByRole('button', { name: m.querylog_filter_reset() }));
		expect(nav.goto).toHaveBeenLastCalledWith('/query-log', expect.anything());
	});

	it('the status segment writes the status into the URL', async () => {
		serve();
		const user = userEvent.setup();
		render(Page);

		await user.click(screen.getByRole('radio', { name: m.querylog_status_blocked() }));
		const [target] = nav.goto.mock.calls.at(-1) as [string];
		expect(new URL(target, 'http://localhost').searchParams.get('status')).toBe('blocked');
	});

	it('a preset period writes period into the URL', async () => {
		serve();
		const user = userEvent.setup();
		render(Page);

		await user.click(screen.getByRole('radio', { name: m.period_7d() }));
		const [target] = nav.goto.mock.calls.at(-1) as [string];
		expect(new URL(target, 'http://localhost').searchParams.get('period')).toBe('7d');
	});

	it('Angepasst opens the sheet, which then shows from and to', async () => {
		setUrl('period=custom');
		serve();
		const user = userEvent.setup();
		render(Page);

		await user.click(screen.getByRole('button', { name: m.querylog_filter_open() }));
		const dialog = await screen.findByRole('dialog');
		expect(within(dialog).getByLabelText(m.querylog_from())).toBeInTheDocument();
		expect(within(dialog).getByLabelText(m.querylog_to())).toBeInTheDocument();
	});

	it('Angepasst asks the URL for custom and opens the sheet', async () => {
		serve();
		const user = userEvent.setup();
		render(Page);

		await user.click(screen.getByRole('radio', { name: m.querylog_range_custom() }));
		const [target] = nav.goto.mock.calls.at(-1) as [string];
		expect(new URL(target, 'http://localhost').searchParams.get('period')).toBe('custom');
		expect(await screen.findByRole('dialog')).toBeInTheDocument();
	});

	it('states the row range above the list', async () => {
		serve({
			'/api/v1/query-log': () =>
				pageOf([record('a'), record('b')], { has_more: true, next_offset: 2 }),
		});
		render(Page);

		expect(
			await screen.findByText(m.querylog_page_range({ from: '1', to: '2' })),
		).toBeInTheDocument();
		expect(screen.getByText(m.querylog_page_more())).toBeInTheDocument();
	});
});

describe('wide and compact layouts', () => {
	it('renders the wide table with status as icon and text', async () => {
		setWide(true);
		serve({
			'/api/v1/query-log': () =>
				pageOf([
					record('a'),
					record('b', {
						query: { name: 'www.example.com', type: 'AAAA', class: 'IN' },
						filter: null,
						rcode: 'NOERROR',
					}),
				]),
		});
		const { container } = render(Page);

		const table = await screen.findByRole('table', { name: m.querylog_table_label() });
		const blockedCell = within(table).getByText(m.querylog_status_blocked()).closest('.mark');
		expect(blockedCell?.querySelector('svg')).not.toBeNull();
		expect(within(table).getByText(m.querylog_status_allowed())).toBeInTheDocument();
		expect(container.querySelector('table td.mono')).not.toBeNull();
	});

	it('renders the same data as a card list on compact width', async () => {
		serve({ '/api/v1/query-log': () => pageOf([record('a')]) });
		const { container } = render(Page);

		expect(await screen.findByText('ads.example.com')).toBeInTheDocument();
		expect(container.querySelector('table')).toBeNull();
		expect(container.querySelector('.card .mark')?.textContent).toContain(
			m.querylog_status_blocked(),
		);
		const meta = container.querySelector('.card .meta')?.textContent ?? '';
		expect(meta).toContain('iPhone');
		// How the client asked (DoH, DoT, plain UDP/TCP) stays visible: it matters for privacy.
		expect(meta).toContain('doh');
	});

	it('hides technical columns by default and stores the switch for this viewer', async () => {
		setWide(true);
		localStorage.removeItem(TECHNICAL_KEY);
		serve({ '/api/v1/query-log': () => pageOf([record('a')]) });
		const user = userEvent.setup();
		const { container } = render(Page);

		await screen.findByRole('table', { name: m.querylog_table_label() });
		expect(screen.queryByRole('columnheader', { name: m.querylog_col_answer() })).toBeNull();
		expect(container.querySelector('tr.day th')?.getAttribute('colspan')).toBe('4');

		// The native input is visually hidden (pointer-events: none); the wrapping label is the target.
		const toggle = screen.getByRole('switch', { name: m.querylog_technical_columns() });
		await user.click(toggle.closest('label') as HTMLElement);
		expect(screen.getByRole('columnheader', { name: m.querylog_col_answer() })).toBeInTheDocument();
		expect(
			screen.getByRole('columnheader', { name: m.querylog_col_latency() }),
		).toBeInTheDocument();
		expect(container.querySelector('tr.day th')?.getAttribute('colspan')).toBe('6');
		expect(localStorage.getItem(TECHNICAL_KEY)).toBe('on');
	});

	it('shows the answer facts in a card while a domain is hovered or focused', async () => {
		setWide(true);
		serve({ '/api/v1/query-log': () => pageOf([record('a')]) });
		const user = userEvent.setup();
		render(Page);

		const link = await screen.findByRole('link', { name: /a/ });
		expect(screen.queryByRole('tooltip')).toBeNull();
		await user.hover(link);
		const tip = await screen.findByRole('tooltip');
		expect(tip).toHaveTextContent(m.querylog_row_rcode());
		expect(tip).toHaveTextContent('NXDOMAIN');
		expect(tip).toHaveTextContent('||ads.example.com^');
		expect(link).toHaveAttribute('aria-describedby', tip.id);
		await user.unhover(link);
		expect(screen.queryByRole('tooltip')).toBeNull();
	});

	it('shows the empty state when no record matches', async () => {
		serve();
		render(Page);

		expect(await screen.findByText(m.querylog_empty())).toBeInTheDocument();
	});

	it('stores a density choice for this viewer', async () => {
		setWide(true);
		serve({ '/api/v1/query-log': () => pageOf([record('a')]) });
		const user = userEvent.setup();
		render(Page);

		await user.click(await screen.findByRole('radio', { name: m.querylog_density_compact() }));
		expect(localStorage.getItem('dnscraft_querylog_density')).toBe('compact');
	});
});

describe('pagination and export', () => {
	it('moves to the next page with offset from has_more and next_offset', async () => {
		serve({
			'/api/v1/query-log': () => pageOf([record('a')], { has_more: true, next_offset: 50 }),
		});
		const user = userEvent.setup();
		render(Page);

		await user.click(await screen.findByRole('button', { name: m.querylog_next() }));
		expect(nav.goto).toHaveBeenCalledWith(expect.stringContaining('offset=50'), expect.anything());
	});

	it('disables Next when no further page exists', async () => {
		serve({ '/api/v1/query-log': () => pageOf([record('a')]) });
		render(Page);

		expect(await screen.findByRole('button', { name: m.querylog_next() })).toBeDisabled();
	});

	it('exports carry the current filters and no paging', async () => {
		setUrl('domain_substr=ads&limit=25&offset=50');
		serve();
		const { container } = render(Page);

		await waitFor(() => expect(requested('/api/v1/query-log').length).toBeGreaterThan(0));
		const csv = container.querySelector('a[href*="export.csv"]');
		const ndjson = container.querySelector('a[href*="export.ndjson"]');
		for (const [link, path] of [
			[csv, '/api/v1/query-log/export.csv'],
			[ndjson, '/api/v1/query-log/export.ndjson'],
		] as const) {
			const url = new URL(link?.getAttribute('href') ?? '', 'http://localhost');
			expect(url.pathname).toBe(path);
			expect(url.searchParams.get('domain_substr')).toBe('ads');
			expect(url.searchParams.has('from')).toBe(true);
			expect(url.searchParams.has('limit')).toBe(false);
			expect(url.searchParams.has('offset')).toBe(false);
		}
		expect(csv).toHaveAttribute('download');
	});
});

describe('dropped events', () => {
	it('shows a notice when the node dropped query events', async () => {
		serve({
			'/api/v1/stats/overview': () =>
				ok({
					source: 'raw',
					total: 1,
					allowed: 1,
					blocked: 0,
					allowed_ratio: 1,
					query_log_dropped: 3,
					by_answer_source: {},
				}),
		});
		render(Page);

		expect(await screen.findByText(m.querylog_dropped_title())).toBeInTheDocument();
		expect(screen.getByText(m.querylog_dropped_body({ count: '3' }))).toBeInTheDocument();
	});

	it('shows no notice when nothing was dropped', async () => {
		serve();
		render(Page);

		await waitFor(() => expect(requested('/api/v1/query-log').length).toBeGreaterThan(0));
		expect(screen.queryByText(m.querylog_dropped_title())).not.toBeInTheDocument();
	});
});

describe('always-on live stream', () => {
	it('opens SSE with the current filters and prepends new rows', async () => {
		setUrl('domain_substr=ads&protocol=doh');
		serve({ '/api/v1/query-log': () => pageOf([record('seed')]) });
		render(Page);

		expect(await screen.findByText('ads.example.com')).toBeInTheDocument();
		await waitFor(() => expect(FakeEventSource.instances.length).toBe(1));
		const es = FakeEventSource.instances[0]!;
		expect(es.url.startsWith('/api/v1/query-log/stream?')).toBe(true);
		expect(es.url).toContain('domain_substr=ads');
		expect(es.url).toContain('protocol=doh');
		expect(es.url).not.toContain('limit=');
		expect(es.url).not.toContain('offset=');

		es.emit(
			'row',
			JSON.stringify(
				record('live-1', { query: { name: 'live.ads.example', type: 'A', class: 'IN' } }),
			),
		);
		expect(await screen.findByText('live.ads.example')).toBeInTheDocument();
	});

	it('folds lagged events into the incomplete banner', async () => {
		serve();
		render(Page);
		await waitFor(() => expect(FakeEventSource.instances.length).toBe(1));
		FakeEventSource.instances[0]!.emit('lagged', '{"dropped":2}');
		expect(await screen.findByText(m.querylog_dropped_title())).toBeInTheDocument();
		expect(screen.getByText(m.querylog_dropped_body({ count: '2' }))).toBeInTheDocument();
	});
});

describe('untrusted record values', () => {
	it('renders markup, quotes, control characters and bidi overrides as inert text', async () => {
		setWide(true);
		serve({
			'/api/v1/query-log': () =>
				pageOf([
					record('x1', { query: { name: '<script>alert(1)</script>', type: 'A', class: 'IN' } }),
					record('x2', {
						query: { name: '"><img src=x onerror=alert(1)>', type: 'A', class: 'IN' },
					}),
					record('x3', {
						query: { name: 'bad\u0000name\nlive.example', type: 'A', class: 'IN' },
						client: null,
						client_id: null,
					}),
					record('x4', {
						query: { name: 'evil‮gnp.example', type: 'A', class: 'IN' },
						filter: null,
						rcode: 'NOERROR',
					}),
				]),
		});
		const { container } = render(Page);

		expect(await screen.findByText('<script>alert(1)</script>')).toBeInTheDocument();
		expect(screen.getByText('"><img src=x onerror=alert(1)>')).toBeInTheDocument();
		expect(screen.getByText(/bad�name�live\.example/)).toBeInTheDocument();
		expect(screen.getByText(/evil�gnp\.example/)).toBeInTheDocument();
		expect(container.querySelectorAll('script, img').length).toBe(0);
		expect(container.querySelector('[onerror]')).toBeNull();
	});

	it('shows the ASCII form next to a punycode name', async () => {
		setWide(true);
		serve({
			'/api/v1/query-log': () =>
				pageOf([
					record('idn', { query: { name: 'xn--bcher-kva.example', type: 'A', class: 'IN' } }),
				]),
		});
		render(Page);

		expect(await screen.findByText('bücher.example')).toBeInTheDocument();
		expect(screen.getByText('xn--bcher-kva.example')).toBeInTheDocument();
	});
});

describe('resolved answers in the rows', () => {
	const threeA: QueryRecord['answers'] = [
		{ type: 'A', data: '192.0.2.1', ttl: 60 },
		{ type: 'A', data: '192.0.2.2', ttl: 60 },
		{ type: 'A', data: '192.0.2.3', ttl: 60 },
	];
	const allowed = { filter: null, rcode: 'NOERROR' } as const;

	it('shows up to two values and a count for the rest on a card', async () => {
		serve({
			'/api/v1/query-log': () =>
				pageOf([record('a', { ...allowed, answers: threeA }), record('b', allowed)]),
		});
		const { container } = render(Page);

		await waitFor(() => expect(container.querySelectorAll('.card')).toHaveLength(2));
		const cards = container.querySelectorAll('.card');
		expect(cards[0]?.querySelector('.answers')?.textContent).toBe('192.0.2.1, 192.0.2.2 +1');
		expect(cards[1]?.querySelector('.answers')).toBeNull();
	});

	it('shows the same summary under the domain in the table', async () => {
		setWide(true);
		serve({
			'/api/v1/query-log': () =>
				pageOf([
					record('a', {
						...allowed,
						query: { name: 'cname.example.com', type: 'A', class: 'IN' },
						answers: [
							{ type: 'CNAME', data: '', ttl: 300 },
							{ type: 'A', data: '192.0.2.9', ttl: 300 },
						],
					}),
					record('b', allowed),
				]),
		});
		const { container } = render(Page);

		expect(await screen.findByText('cname.example.com')).toBeInTheDocument();
		const answers = container.querySelectorAll('table .answers');
		expect(answers).toHaveLength(1);
		expect(answers[0]?.textContent).toBe('CNAME, 192.0.2.9');
	});

	it('renders nothing extra for a blocked row without answers', async () => {
		serve({ '/api/v1/query-log': () => pageOf([record('a')]) });
		const { container } = render(Page);

		await screen.findByText('ads.example.com');
		expect(container.querySelector('.answers')).toBeNull();
	});
});
