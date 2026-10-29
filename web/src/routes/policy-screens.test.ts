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

	it('opens the names sheet with Netzbereich deviation rows, not freitext overrides', async () => {
		handlers['GET /api/v1/policy/records'] = () =>
			ok({
				records: [
					{
						name: 'nas.example.test.',
						type: 'A',
						ttl: 60,
						rdata: '192.0.2.1',
						overrides: { lan: '192.0.2.9' },
					},
				],
			});
		const user = userEvent.setup();
		render(NamesPage);
		await user.click(await screen.findByRole('button', { name: /192\.0\.2\.1\b/ }));
		const dialog = await screen.findByRole('dialog');
		expect(within(dialog).getByText(m.names_field_overrides())).toBeInTheDocument();
		expect(within(dialog).queryByRole('textbox', { name: /zone=wert|zone=value/i })).toBeNull();
		expect(within(dialog).getByLabelText(m.names_overrides_view())).toHaveValue('lan');
		expect(within(dialog).getByLabelText(m.names_overrides_value())).toHaveValue('192.0.2.9');
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

	it('shows node scope on the zones list', async () => {
		handlers['GET /api/v1/policy/views'] = () =>
			ok({
				views: [
					{
						id: 'lan',
						is_default: true,
						subnets: ['192.0.2.0/24'],
						nodes: [],
						profile: 'default',
					},
					{
						id: 'cabin',
						is_default: false,
						subnets: [],
						nodes: ['node2'],
						profile: 'default',
					},
				],
			});
		render(ZonesPage);
		expect(await screen.findByText('cabin')).toBeInTheDocument();
		expect(screen.getByText('node2')).toBeInTheDocument();
		expect(screen.getByText(m.listeners_nodes_all())).toBeInTheDocument();
	});

	it('marks the default range, shows capped range chips and counts devices', async () => {
		handlers['GET /api/v1/policy/views'] = () =>
			ok({
				views: [
					{
						id: 'lan',
						is_default: true,
						subnets: ['192.0.2.0/24', '2001:db8::/64', '10.0.0.0/8', '172.16.0.0/12'],
						nodes: [],
						profile: 'default',
					},
				],
			});
		render(ZonesPage);
		expect(await screen.findByText(m.zones_badge_default())).toBeInTheDocument();
		const more = m.zones_more({ count: 1 });
		expect(screen.getByText(more, { exact: false })).toBeInTheDocument();
		// The client at 192.0.2.2 lies inside 192.0.2.0/24.
		expect(
			screen.getByText(m.zones_count_devices_one({ count: 1 }), { exact: false }),
		).toBeInTheDocument();
	});

	it('lists the Client IDs pinned to a range, three by name and the rest counted', async () => {
		handlers['GET /api/v1/policy/views'] = () =>
			ok({
				views: [
					{ id: 'lan', is_default: true, subnets: ['192.0.2.0/24'], nodes: [], profile: 'default' },
					{ id: 'unterwegs', is_default: false, subnets: [], nodes: [], profile: 'default' },
				],
			});
		handlers['GET /api/v1/policy/client-ids'] = () =>
			ok({
				client_ids: [
					{ id: 'a-1', label: 'iPhone von Anna', device: null, view: 'unterwegs' },
					{ id: 'b-2', label: 'Pixel 8 Jonas', device: null, view: 'unterwegs' },
					{ id: 'c-3', label: null, device: null, view: 'unterwegs' },
					{ id: 'd-4', label: 'Tablet', device: null, view: 'unterwegs' },
					{ id: 'e-5', label: 'Home', device: null, view: null },
				],
			});
		render(ZonesPage);
		expect(await screen.findByText(m.zones_pinned_label())).toBeInTheDocument();
		expect(
			screen.getByText(m.zones_pinned({ names: 'iPhone von Anna, Pixel 8 Jonas, c-3' }), {
				exact: false,
			}),
		).toBeInTheDocument();
		expect(screen.getByText(m.zones_more({ count: 1 }), { exact: false })).toBeInTheDocument();
		expect(screen.getByText(m.zones_no_subnets())).toBeInTheDocument();
	});

	it('replaces the delete button of a pinned range with the pinned names', async () => {
		handlers['GET /api/v1/policy/views'] = () =>
			ok({
				views: [{ id: 'unterwegs', is_default: false, subnets: [], nodes: [], profile: 'default' }],
			});
		handlers['GET /api/v1/policy/client-ids'] = () =>
			ok({
				client_ids: [{ id: 'a-1', label: 'iPhone von Anna', device: null, view: 'unterwegs' }],
			});
		const user = userEvent.setup();
		render(ZonesPage);
		await user.click(await screen.findByRole('button', { name: /unterwegs/ }));
		const dialog = await screen.findByRole('dialog');
		expect(within(dialog).queryByRole('button', { name: m.action_delete() })).toBeNull();
		expect(
			within(dialog).getByText(m.zones_pinned_blocked({ names: 'iPhone von Anna' })),
		).toBeInTheDocument();
	});

	it('maps the server refusal view_in_use to the same text with the device names', async () => {
		handlers['GET /api/v1/policy/views'] = () =>
			ok({
				views: [{ id: 'unterwegs', is_default: false, subnets: [], nodes: [], profile: 'default' }],
			});
		handlers['GET /api/v1/policy/client-ids'] = () =>
			ok({
				client_ids: [{ id: 'a-1', label: 'iPhone von Anna', device: null, view: null }],
			});
		handlers['DELETE /api/v1/policy/views/unterwegs'] = () =>
			json(400, {
				error: {
					code: 'policy.config.invalid',
					params: { reason: 'view_in_use', view: 'unterwegs', client_ids: ['a-1'] },
				},
			});
		const user = userEvent.setup();
		render(ZonesPage);
		await user.click(await screen.findByRole('button', { name: /unterwegs/ }));
		let dialog = await screen.findByRole('dialog');
		await user.click(within(dialog).getByRole('button', { name: m.action_delete() }));
		dialog = screen.getByRole('dialog');
		await user.click(within(dialog).getByRole('button', { name: m.action_delete() }));
		expect(
			await within(dialog).findByText(m.zones_pinned_blocked({ names: 'iPhone von Anna' })),
		).toBeInTheDocument();
		expect(screen.queryByText(m.error_policy_config_invalid())).not.toBeInTheDocument();
	});

	it('allows a range without subnets, saves it empty and explains its use', async () => {
		handlers['PUT /api/v1/policy/views/unterwegs'] = () =>
			ok({
				version: 6,
				view: { id: 'unterwegs', is_default: false, subnets: [], nodes: [], profile: 'default' },
			});
		const user = userEvent.setup();
		render(ZonesPage);
		await user.click(await screen.findByText(m.zones_add()));
		await user.type(screen.getByLabelText(m.zones_id_label()), 'unterwegs');
		expect(screen.getByText(m.zones_no_subnets())).toBeInTheDocument();
		const save = screen.getByRole('button', { name: m.action_save() });
		expect(save).toBeEnabled();
		await user.click(save);
		await waitFor(() =>
			expect(
				fetchMock.mock.calls.some(
					([url, init]) =>
						String(url).endsWith('/policy/views/unterwegs') &&
						init?.method === 'PUT' &&
						JSON.parse(String(init.body)).subnets.length === 0,
				),
			).toBe(true),
		);
	});

	it('shows the empty state with the add action when no range exists', async () => {
		handlers['GET /api/v1/policy/views'] = () => ok({ views: [] });
		render(ZonesPage);
		expect(await screen.findByText(m.zones_empty())).toBeInTheDocument();
		expect(screen.getByText(m.zones_add())).toBeInTheDocument();
	});

	it('blocks saving while a range line is invalid and names the line', async () => {
		const user = userEvent.setup();
		render(ZonesPage);
		await user.click(await screen.findByText(m.zones_add()));
		await user.type(screen.getByLabelText(m.zones_id_label()), 'office');
		const ranges = screen.getByLabelText(m.zones_subnets_label());
		await user.type(ranges, '192.0.2.0/24{enter}{enter}192.0.2.1/33');
		expect(screen.getByText(m.zones_range_invalid({ line: 3 }))).toBeInTheDocument();
		expect(screen.getByRole('button', { name: m.action_save() })).toBeDisabled();
		await user.clear(ranges);
		await user.type(ranges, '2001:db8:10::/64');
		expect(screen.queryByRole('alert')).not.toBeInTheDocument();
		expect(screen.getByRole('button', { name: m.action_save() })).toBeEnabled();
	});

	it('confirms a delete inside the sheet and offers none for the default range', async () => {
		handlers['GET /api/v1/policy/views'] = () =>
			ok({
				views: [
					{ id: 'lan', is_default: true, subnets: ['192.0.2.0/24'], nodes: [], profile: 'default' },
					{
						id: 'office',
						is_default: false,
						subnets: ['10.10.0.0/16'],
						nodes: [],
						profile: 'default',
					},
				],
			});
		handlers['DELETE /api/v1/policy/views/office'] = () => ok({ version: 5 });
		const user = userEvent.setup();
		render(ZonesPage);

		await user.click(await screen.findByRole('button', { name: /^lan\b/ }));
		let dialog = await screen.findByRole('dialog');
		expect(within(dialog).queryByRole('button', { name: m.action_delete() })).toBeNull();
		expect(within(dialog).getByText(m.zones_default_delete_blocked())).toBeInTheDocument();
		await user.click(within(dialog).getByRole('button', { name: m.action_cancel() }));
		await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());

		await user.click(await screen.findByRole('button', { name: /^office\b/ }));
		dialog = await screen.findByRole('dialog');
		await user.click(within(dialog).getByRole('button', { name: m.action_delete() }));
		expect(within(dialog).getByText(m.zones_delete_body({ id: 'office' }))).toBeInTheDocument();
		expect(
			fetchMock.mock.calls.some(
				([url, init]) => String(url).endsWith('/policy/views/office') && init?.method === 'DELETE',
			),
		).toBe(false);
		await user.click(within(dialog).getByRole('button', { name: m.action_delete() }));
		await waitFor(() =>
			expect(
				fetchMock.mock.calls.some(
					([url, init]) =>
						String(url).endsWith('/policy/views/office') && init?.method === 'DELETE',
				),
			).toBe(true),
		);
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

	it('shows answer records including the IP from a test query', async () => {
		handlers['POST /api/v1/policy/test-query'] = () =>
			ok({
				view_id: 'zuhauseserver',
				profile_id: 'default',
				filter_set_id: 'default',
				answer_source: 'local_view',
				steps: [
					{ stage: 'select', verdict: 'selected' },
					{ stage: 'local_view', verdict: 'answered' },
				],
				answer: {
					rcode: 'NOERROR',
					records: [{ name: 'elmo.barner.cloud.', qtype: 'A', ttl: 60, data: '172.20.10.10' }],
				},
				timings: { select_us: 12, filter_us: 3, resolve_us: 40, total_us: 55 },
			});
		const user = userEvent.setup();
		render(TestQueryPage);
		await user.click(screen.getByRole('button', { name: m.test_query_run() }));
		expect(await screen.findByText('172.20.10.10 · TTL 60')).toBeInTheDocument();
		expect(screen.getByText('NOERROR')).toBeInTheDocument();
		expect(screen.getByText('zuhauseserver')).toBeInTheDocument();
	});

	it('builds guided filter rules without typed special characters', () => {
		expect(
			buildRuleText({ action: 'block', domain: 'ads.example.com', include_subdomains: true }),
		).toBe('||ads.example.com^');
	});
});
