// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import Page from './+page.svelte';
import type { QueryRecord } from '$lib/api/query-log';
import { endSession, setPrincipal } from '$lib/auth/state.svelte';
import { live } from '$lib/live.svelte';
import { m } from '$lib/paraglide/messages';

const pageState = vi.hoisted(() => ({ params: { id: 'q1' } as Record<string, string> }));
vi.mock('$app/state', () => ({
	page: {
		get url() {
			return new URL('http://localhost/query-log/q1');
		},
		get params() {
			return pageState.params;
		},
	},
}));

const json = (status: number, body: unknown): Response =>
	new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});
const ok = (data: unknown): Response => json(200, { data });
const fail = (status: number, code: string): Response => json(status, { error: { code } });

type Handler = (init: RequestInit) => Response;

let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;
let handlers: Record<string, Handler>;

function serve(overrides: Record<string, Handler> = {}): void {
	handlers = { ...overrides };
	fetchMock.mockImplementation(async (input, init) => {
		const path = new URL(String(input), 'http://localhost').pathname;
		const handler = handlers[`${init?.method ?? 'GET'} ${path}`];
		return handler ? handler(init ?? {}) : fail(404, 'control_api.not_found');
	});
}

function record(overrides: Partial<QueryRecord> = {}): QueryRecord {
	return {
		id: 'q1',
		node_id: 'node1',
		listener_id: 'lan-udp',
		protocol: 'doh',
		source_ip: '192.0.2.0',
		source_ip_truncated: true,
		client_id: 'iphone-k7q2x9',
		client: {
			id: 'c1',
			display_name: 'iPhone',
			source: 'unifi',
			macs: ['aa:bb:cc:dd:ee:ff'],
			vlan_id: 40,
			vlan_name: 'IoT',
			local_domain: null,
		},
		query: { name: 'ads.example.com', type: 'A', class: 'IN' },
		view_id: 'lan',
		profile_id: 'default',
		filter_set: 'default',
		selection: { cause: 'subnet', prefix: '192.0.2.0/24' },
		steps: [
			{
				stage: 'select',
				verdict: 'selected',
				selection: { cause: 'subnet', prefix: '192.0.2.0/24' },
			},
			{ stage: 'local_view', verdict: 'answered' },
			{ stage: 'filter_qname', verdict: 'blocked' },
		],
		answer_source: 'filter_block',
		filter: {
			reason: 'list',
			block_mode: 'nxdomain',
			rule_text: '||ads.example.com^',
			list_id: 'adguard-dns-filter',
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

beforeEach(() => {
	fetchMock = vi.fn<typeof fetch>();
	vi.stubGlobal('fetch', fetchMock);
	endSession();
	setPrincipal({ role: 'admin', actorId: 'alice', actorType: 'user', csrfToken: 'tok' });
	pageState.params = { id: 'q1' };
	live.message = '';
});

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

describe('why blocked view', () => {
	it('renders the decision steps in order', async () => {
		serve({ 'GET /api/v1/query-log/q1': () => ok(record()) });
		render(Page);

		const steps = await screen.findAllByRole('listitem');
		expect(steps).toHaveLength(3);
		expect(steps.map((step) => step.querySelector('.index')?.textContent)).toEqual(['1', '2', '3']);
		expect(steps[0]).toHaveTextContent(m.querylog_stage_select());
		expect(steps[1]).toHaveTextContent(m.querylog_stage_local_view());
		expect(steps[2]).toHaveTextContent(m.querylog_stage_filter_qname());
	});

	it('shows the matching rule and its list in mono text', async () => {
		serve({ 'GET /api/v1/query-log/q1': () => ok(record()) });
		render(Page);

		expect(await screen.findByText('||ads.example.com^')).toHaveClass('mono');
		expect(screen.getByText('adguard-dns-filter')).toHaveClass('mono');
		expect(screen.getByText(m.querylog_provenance_list())).toBeInTheDocument();
	});

	it('shows the Unicode name with the ASCII form available', async () => {
		serve({
			'GET /api/v1/query-log/q1': () =>
				ok(record({ query: { name: 'xn--bcher-kva.example', type: 'A', class: 'IN' } })),
		});
		render(Page);

		expect(await screen.findByText('bücher.example')).toBeInTheDocument();
		expect(screen.getByText('xn--bcher-kva.example')).toBeInTheDocument();
	});

	it('neutralises control characters in a rule text and expands long values', async () => {
		const longRule = `||${'a'.repeat(300)}^`;
		serve({
			'GET /api/v1/query-log/q1': () =>
				ok(
					record({
						filter: {
							reason: 'custom',
							block_mode: 'nxdomain',
							rule_text: `bad\u0000rule‮${longRule}`,
							list_id: null,
							important: true,
						},
					}),
				),
		});
		render(Page);

		expect(await screen.findByText(/bad�rule�\|\|a+…/)).toBeInTheDocument();
		expect(screen.getByText(m.querylog_show_full())).toBeInTheDocument();
	});

	it('hides admin actions from a viewer', async () => {
		setPrincipal({ role: 'viewer', actorId: 'bob', actorType: 'user', csrfToken: 'tok' });
		serve({ 'GET /api/v1/query-log/q1': () => ok(record()) });
		render(Page);

		await screen.findByText('ads.example.com');
		expect(
			screen.queryByRole('button', { name: m.querylog_allow_action() }),
		).not.toBeInTheDocument();
	});

	it('answers a missing record with the unavailable state', async () => {
		serve({ 'GET /api/v1/query-log/q1': () => fail(404, 'control_api.not_found') });
		render(Page);

		expect(await screen.findByText(m.querylog_unavailable_title())).toBeInTheDocument();
		expect(screen.queryByRole('alert')).not.toBeInTheDocument();
	});
});

describe('temporary allow', () => {
	it('confirms the domain and announces the new expiry', async () => {
		serve({
			'GET /api/v1/query-log/q1': () => ok(record()),
			'POST /api/v1/filtering/temporary-allows': () =>
				ok({
					domain: 'ads.example.com',
					include_subdomains: false,
					created_at: '2026-10-27T12:00:00Z',
					expires_at: '2026-10-27T12:05:00Z',
					filter_set_id: 'default',
				}),
		});
		const user = userEvent.setup();
		render(Page);

		await user.click(await screen.findByRole('button', { name: m.querylog_allow_action() }));
		const dialog = await screen.findByRole('dialog');
		expect(within(dialog).getByText('ads.example.com')).toBeInTheDocument();
		await user.click(within(dialog).getByRole('button', { name: m.querylog_allow_confirm() }));

		await waitFor(() => expect(live.message).toContain('ads.example.com'));
		const post = fetchMock.mock.calls.find(([, init]) => init?.method === 'POST');
		expect(JSON.parse(String(post?.[1]?.body))).toEqual({
			domain: 'ads.example.com',
			include_subdomains: false,
			duration: 'PT5M',
			filter_set_id: 'default',
		});
	});

	it('explains that the node lacks temporary allows on 404', async () => {
		serve({
			'GET /api/v1/query-log/q1': () => ok(record()),
			'POST /api/v1/filtering/temporary-allows': () => fail(404, 'control_api.not_found'),
		});
		const user = userEvent.setup();
		render(Page);

		await user.click(await screen.findByRole('button', { name: m.querylog_allow_action() }));
		const dialog = await screen.findByRole('dialog');
		await user.click(within(dialog).getByRole('button', { name: m.querylog_allow_confirm() }));

		expect(await within(dialog).findByText(m.querylog_allow_unavailable())).toBeInTheDocument();
	});
});
