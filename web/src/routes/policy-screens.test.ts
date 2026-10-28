// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import ZonesPage from './zones/+page.svelte';
import NamesPage from './names/+page.svelte';
import ClientsPage from './clients/+page.svelte';
import FilterSetsPage from './filter-sets/+page.svelte';
import TestQueryPage from './test-query/+page.svelte';
import { endSession, setPrincipal } from '$lib/auth/state.svelte';
import { m } from '$lib/paraglide/messages';
import { buildRuleText } from '$lib/api/filtering';

const json = (status: number, body: unknown): Response =>
	new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});
const ok = (data: unknown): Response => json(200, { data });
const fail = (status: number, code: string): Response => json(status, { error: { code } });

let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;
let handlers: Record<string, (init?: RequestInit, url?: string) => Response>;

function serve(
	overrides: Record<string, (init?: RequestInit, url?: string) => Response> = {},
): void {
	handlers = {
		'GET /api/v1/auth/me': () =>
			ok({ role: 'admin', actor_id: 'admin', actor_type: 'user', csrf_token: 'tok' }),
		'GET /api/v1/policy/views': () =>
			ok({
				views: [
					{
						id: 'lan',
						is_default: true,
						subnets: ['192.0.2.0/24'],
						nodes: [],
						profile: 'default',
					},
				],
			}),
		'GET /api/v1/config': () =>
			ok({
				version: 3,
				config: {
					policy: {
						profiles: [
							{
								id: 'default',
								filter_set: 'default',
								suppress_aaaa: false,
								firefox_canary: false,
								icloud_private_relay: false,
								rebind: null,
								rebind_exceptions: [],
								forward_zones: null,
								safesearch: null,
								schedules: [],
							},
						],
					},
				},
			}),
		'GET /api/v1/policy/records': () =>
			ok({
				records: [
					{
						name: '<script>alert(1)</script>.evil.test.',
						type: 'A',
						ttl: 60,
						rdata: '192.0.2.1',
						overrides: {},
					},
				],
			}),
		'GET /api/v1/clients': () =>
			ok({
				clients: [
					{
						id: 'c1',
						name: 'Phone',
						dns_label: 'phone',
						local_domain: 'lan',
						source: 'unifi',
						ips: ['192.0.2.2'],
						macs: [],
						vlan: null,
						online: true,
						last_seen: null,
					},
				],
				manual: [],
			}),
		'GET /api/v1/filter-sets': () =>
			ok({
				filter_sets: [
					{
						id: 'default',
						name: 'Default',
						lists: [],
						custom_rules: '',
						services: [],
						block_mode: 'refused',
					},
				],
			}),
		...overrides,
	};
	fetchMock.mockImplementation(async (input, init) => {
		const url = String(input);
		const method = init?.method ?? 'GET';
		const path = url.split('?')[0];
		const handler = handlers[`${method} ${path}`];
		return handler ? handler(init, url) : fail(404, 'control_api.not_found');
	});
}

beforeEach(() => {
	fetchMock = vi.fn();
	vi.stubGlobal('fetch', fetchMock);
	setPrincipal({ role: 'admin', actorId: 'admin', actorType: 'user', csrfToken: 'tok' });
	serve();
});

afterEach(() => {
	cleanup();
	endSession();
	vi.unstubAllGlobals();
});

describe('policy screens', () => {
	it('lists zones and saves a new zone', async () => {
		handlers['PUT /api/v1/policy/views/office'] = () =>
			ok({
				version: 4,
				view: { id: 'office', is_default: false, subnets: [], nodes: [], profile: 'default' },
			});
		const user = userEvent.setup();
		render(ZonesPage);
		expect(await screen.findByText('lan')).toBeInTheDocument();
		await user.click(screen.getByText(m.zones_add()));
		await user.type(screen.getByLabelText(m.zones_id_label()), 'office');
		await user.click(screen.getByRole('button', { name: m.action_save() }));
		await waitFor(() =>
			expect(
				fetchMock.mock.calls.some(
					([url, init]) => String(url).includes('/policy/views/office') && init?.method === 'PUT',
				),
			).toBe(true),
		);
	});

	it('renders hostile record names as inert text', async () => {
		render(NamesPage);
		const row = await screen.findByText(/evil\.test/);
		expect(row.innerHTML).not.toContain('<script>');
	});

	it('lists clients and creates a manual entry', async () => {
		handlers['POST /api/v1/clients/manual'] = () =>
			ok({ version: 2, entry: { name: 'TV', ip: '192.0.2.9' } });
		const user = userEvent.setup();
		render(ClientsPage);
		expect(await screen.findByText('Phone')).toBeInTheDocument();
		await user.click(screen.getByText(m.clients_add_manual()));
		await user.type(screen.getByLabelText(m.clients_field_name()), 'TV');
		await user.type(screen.getByLabelText(m.clients_field_ip()), '192.0.2.9');
		await user.click(
			within(screen.getByRole('dialog')).getByRole('button', { name: m.action_save() }),
		);
		await waitFor(() =>
			expect(fetchMock.mock.calls.some(([url]) => String(url).includes('/clients/manual'))).toBe(
				true,
			),
		);
	});

	it('hides zone mutations for a viewer', async () => {
		setPrincipal({ role: 'viewer', actorId: 'bob', actorType: 'user', csrfToken: null });
		render(ZonesPage);
		await screen.findByText('lan');
		expect(screen.queryByText(m.zones_add())).not.toBeInTheDocument();
		expect(screen.queryByText(m.action_edit())).not.toBeInTheDocument();
	});

	it('shows unavailable state on 404 list', async () => {
		handlers['GET /api/v1/filter-sets'] = () => fail(404, 'control_api.not_found');
		render(FilterSetsPage);
		expect(await screen.findByText(m.dashboard_unavailable_title())).toBeInTheDocument();
	});

	it('renders test-query decision steps', async () => {
		handlers['POST /api/v1/policy/test-query'] = () =>
			ok({
				steps: [
					{ stage: 'select', verdict: 'selected' },
					{ stage: 'resolve', verdict: 'resolved' },
				],
				answer: { rcode: 'NOERROR', records: [] },
			});
		const user = userEvent.setup();
		render(TestQueryPage);
		await user.click(screen.getByRole('button', { name: m.test_query_run() }));
		expect(await screen.findByText(m.querylog_stage_select())).toBeInTheDocument();
	});

	it('builds guided filter rules without typed special characters', () => {
		expect(
			buildRuleText({ action: 'block', domain: 'ads.example.com', include_subdomains: true }),
		).toBe('||ads.example.com^');
	});
});
