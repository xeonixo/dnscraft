// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import ProfilesPage from './profiles/+page.svelte';
import ForwardZonesPage from './forward-zones/+page.svelte';
import ListenersPage from './listeners/+page.svelte';
import ClientsPage from './clients/+page.svelte';
import ClusterPage from './cluster/+page.svelte';
import NamesPage from './names/+page.svelte';
import FilterListsPage from './filter-lists/+page.svelte';
import { endSession, setPrincipal } from '$lib/auth/state.svelte';
import { m } from '$lib/paraglide/messages';
import { errorMessage, reasonMessage } from '$lib/i18n/locale';

const json = (status: number, body: unknown): Response =>
	new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});
const ok = (data: unknown): Response => json(200, { data });
const fail = (status: number, code: string): Response => json(status, { error: { code } });

type Handler = (init?: RequestInit, url?: string) => Response;
let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;
let handlers: Record<string, Handler>;

const profile = (safesearch: unknown) => ({
	id: 'default',
	filter_set: 'default',
	suppress_aaaa: false,
	firefox_canary: false,
	icloud_private_relay: false,
	rebind: null,
	rebind_exceptions: [],
	forward_zones: null,
	safesearch,
	schedules: [],
});

function serve(overrides: Record<string, Handler> = {}): void {
	handlers = {
		'GET /api/v1/auth/me': () =>
			ok({ role: 'admin', actor_id: 'admin', actor_type: 'user', csrf_token: 'tok' }),
		'GET /api/v1/config': () =>
			ok({
				version: 3,
				config: {
					policy: {
						profiles: [profile({ enabled: false, providers: [], youtube_mode: 'Strict' })],
					},
					resolver: {
						forward_zones: [
							{ id: 'lan', zone: 'home.example.', targets: ['192.0.2.1:53'], validate: false },
						],
					},
				},
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
		const handler = handlers[`${init?.method ?? 'GET'} ${url.split('?')[0]}`];
		return handler ? handler(init, url) : fail(404, 'control_api.not_found');
	});
}

const calls = (method: string, path: string) =>
	fetchMock.mock.calls.filter(
		([input, init]) => String(input).split('?')[0] === path && (init?.method ?? 'GET') === method,
	);

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

describe('profiles', () => {
	it('shows SafeSearch off for the stored object and keeps it off on save', async () => {
		handlers['PUT /api/v1/policy/profiles/default'] = () => ok({ version: 4, profile: {} });
		const user = userEvent.setup();
		render(ProfilesPage);
		await screen.findByText('default');
		expect(screen.queryByText(m.profiles_safesearch_on())).toBeNull();
		await user.click(screen.getByRole('button', { name: m.action_edit() }));
		const dialog = await screen.findByRole('dialog');
		expect(
			within(dialog).getByRole('switch', { name: m.profiles_safesearch_label() }),
		).not.toBeChecked();
		await user.click(within(dialog).getByRole('button', { name: m.action_save() }));
		await waitFor(() => expect(calls('PUT', '/api/v1/policy/profiles/default')).toHaveLength(1));
		const body = JSON.parse(String(calls('PUT', '/api/v1/policy/profiles/default')[0][1]?.body));
		expect(body.safesearch).toEqual({ enabled: false, providers: [], youtube_mode: 'Strict' });
	});

	it('sends the SafeSearch structure when creating with SafeSearch on', async () => {
		handlers['PUT /api/v1/policy/profiles/kids'] = () => ok({ version: 4, profile: {} });
		const user = userEvent.setup();
		render(ProfilesPage);
		await user.click(await screen.findByRole('button', { name: m.profiles_add() }));
		const dialog = await screen.findByRole('dialog');
		await user.type(within(dialog).getByLabelText(m.profiles_id_label()), 'kids');
		await fireEvent.click(
			within(dialog).getByRole('switch', { name: m.profiles_safesearch_label() }),
		);
		await user.click(within(dialog).getByRole('button', { name: m.action_save() }));
		await waitFor(() => expect(calls('PUT', '/api/v1/policy/profiles/kids')).toHaveLength(1));
		const body = JSON.parse(String(calls('PUT', '/api/v1/policy/profiles/kids')[0][1]?.body));
		expect(body.safesearch.enabled).toBe(true);
		expect(body.safesearch.providers).toEqual(['google', 'bing', 'youtube', 'duckduckgo']);
	});

	it('names an empty or invalid id next to the field without calling the server', async () => {
		const user = userEvent.setup();
		render(ProfilesPage);
		await user.click(await screen.findByRole('button', { name: m.profiles_add() }));
		const dialog = await screen.findByRole('dialog');
		await user.click(within(dialog).getByRole('button', { name: m.action_save() }));
		expect(within(dialog).getByText(m.field_id_required())).toBeInTheDocument();
		await user.type(within(dialog).getByLabelText(m.profiles_id_label()), 'Bad Id');
		expect(within(dialog).getByText(m.field_id_invalid())).toBeInTheDocument();
		await user.click(within(dialog).getByRole('button', { name: m.action_save() }));
		expect(fetchMock.mock.calls.some(([, init]) => init?.method === 'PUT')).toBe(false);
	});
});

describe('delete confirmation', () => {
	it('asks before deleting a forward zone and shows it without the trailing dot', async () => {
		handlers['PUT /api/v1/config'] = () => ok({ version: 4 });
		const user = userEvent.setup();
		render(ForwardZonesPage);
		expect(await screen.findByText('home.example')).toBeInTheDocument();
		await user.click(screen.getByRole('button', { name: m.action_delete() }));
		const dialog = await screen.findByRole('dialog');
		expect(within(dialog).getByText(/home\.example/)).toBeInTheDocument();
		expect(calls('PUT', '/api/v1/config')).toHaveLength(0);
		await user.click(within(dialog).getByRole('button', { name: m.action_delete() }));
		await waitFor(() => expect(calls('PUT', '/api/v1/config')).toHaveLength(1));
	});

	it('asks before deleting a listener and warns about DNS access', async () => {
		handlers['GET /api/v1/listeners'] = () =>
			ok({
				listeners: [
					{
						id: 'dot-1',
						protocol: 'dot',
						address: '0.0.0.0:853',
						exposure: 'local',
						h3: false,
						nodes: [],
					},
				],
			});
		handlers['DELETE /api/v1/listeners'] = () => ok({ version: 5 });
		const user = userEvent.setup();
		render(ListenersPage);
		await user.click(await screen.findByRole('button', { name: m.action_delete() }));
		const dialog = await screen.findByRole('dialog');
		expect(within(dialog).getByText(m.listeners_delete_body({ id: 'dot-1' }))).toBeInTheDocument();
		expect(calls('DELETE', '/api/v1/listeners')).toHaveLength(0);
		await user.click(within(dialog).getByRole('button', { name: m.action_delete() }));
		await waitFor(() => expect(calls('DELETE', '/api/v1/listeners')).toHaveLength(1));
	});

	it('asks before deleting a manual device and lists it only once after a sync', async () => {
		handlers['GET /api/v1/clients'] = () =>
			ok({
				clients: [
					{
						id: 'm1',
						name: 'nas',
						dns_label: 'nas',
						local_domain: 'lan',
						source: 'manual',
						ips: ['192.0.2.9'],
						macs: [],
						vlan: null,
						online: false,
						last_seen: null,
					},
				],
				manual: [{ name: 'nas', ip: '192.0.2.9' }],
			});
		handlers['DELETE /api/v1/clients/manual'] = () => ok({ version: 5 });
		const user = userEvent.setup();
		render(ClientsPage);
		expect(await screen.findAllByText('nas')).toHaveLength(1);
		await user.click(screen.getByRole('button', { name: m.action_delete() }));
		const dialog = await screen.findByRole('dialog');
		expect(calls('DELETE', '/api/v1/clients/manual')).toHaveLength(0);
		await user.click(within(dialog).getByRole('button', { name: m.action_delete() }));
		await waitFor(() => expect(calls('DELETE', '/api/v1/clients/manual')).toHaveLength(1));
	});
});

describe('client side validation', () => {
	it('validates a manual device before posting', async () => {
		handlers['GET /api/v1/clients'] = () => ok({ clients: [], manual: [] });
		const user = userEvent.setup();
		render(ClientsPage);
		await user.click(await screen.findByRole('button', { name: m.clients_add_manual() }));
		const dialog = await screen.findByRole('dialog');
		await user.click(within(dialog).getByRole('button', { name: m.action_save() }));
		expect(within(dialog).getByText(m.clients_name_required())).toBeInTheDocument();
		await user.type(within(dialog).getByLabelText(m.clients_field_name()), 'nas');
		await user.type(within(dialog).getByLabelText(m.clients_field_ip()), '999.1.1.1');
		expect(within(dialog).getByText(m.clients_ip_invalid())).toBeInTheDocument();
		await user.click(within(dialog).getByRole('button', { name: m.action_save() }));
		expect(calls('POST', '/api/v1/clients/manual')).toHaveLength(0);
	});

	it('validates a name record owner and its data', async () => {
		handlers['GET /api/v1/policy/records'] = () => ok({ records: [] });
		const user = userEvent.setup();
		render(NamesPage);
		await user.click(await screen.findByRole('button', { name: m.names_add() }));
		const dialog = await screen.findByRole('dialog');
		await user.click(within(dialog).getByRole('button', { name: m.action_save() }));
		expect(within(dialog).getByText(m.names_owner_required())).toBeInTheDocument();
		await user.type(within(dialog).getByLabelText(m.names_field_name()), 'nas.example.test');
		await user.type(within(dialog).getByLabelText(m.names_field_rdata()), '300.1.1.1');
		expect(within(dialog).getByText(m.names_rdata_ipv4())).toBeInTheDocument();
	});

	it('refuses a non-http source and an empty name for a filter list', async () => {
		handlers['GET /api/v1/filter-lists'] = () => ok({ filter_lists: [] });
		const user = userEvent.setup();
		render(FilterListsPage);
		await user.click(await screen.findByRole('button', { name: m.filter_lists_add() }));
		const dialog = await screen.findByRole('dialog');
		await user.click(within(dialog).getByRole('button', { name: m.action_save() }));
		expect(within(dialog).getByText(m.filter_lists_name_required())).toBeInTheDocument();
		await user.type(
			within(dialog).getByLabelText(m.filter_lists_source_label()),
			'ftp://x.test/l.txt',
		);
		expect(within(dialog).getByText(m.filter_lists_source_invalid())).toBeInTheDocument();
	});
});

describe('cluster master row', () => {
	it('shows "this node" instead of "never seen" and offers no revoke', async () => {
		handlers['GET /api/v1/cluster/nodes'] = () =>
			ok([
				{
					node_id: 'master1',
					role: 'master',
					fingerprint: null,
					joined_at: null,
					last_seen: null,
					applied_config_version: 3,
					revoked: false,
					local: true,
				},
			]);
		render(ClusterPage);
		await screen.findByText('master1');
		expect(screen.getByText(/dieser Knoten|this node/i)).toBeInTheDocument();
		expect(screen.queryByText(m.cluster_never_seen())).toBeNull();
		expect(screen.queryByRole('button', { name: m.cluster_revoke() })).toBeNull();
	});
});

describe('reasonMessage', () => {
	it('translates known validator texts and passes others through', () => {
		for (const raw of [
			'profile id must match [a-z0-9-]{1,64}',
			'invalid IPv4 address',
			'empty label in domain name',
		]) {
			expect(reasonMessage(raw)).not.toBe(raw);
			expect(reasonMessage(raw)).not.toContain('[a-z0-9-]');
		}
		expect(
			reasonMessage('invalid policy config: subnet 10.0.0.0/8 is listed on more than one view'),
		).toBe(m.error_reason_subnet_overlap({ subnet: '10.0.0.0/8' }));
		expect(reasonMessage('something else')).toBe('something else');
		expect(errorMessage('policy.config.invalid', { reason: 'invalid IPv4 address' })).toContain(
			m.error_reason_invalid_ipv4(),
		);
		expect(errorMessage('tls.acme.order')).toBe(m.error_tls_acme_order());
	});
});
