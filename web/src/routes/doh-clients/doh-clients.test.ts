// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import DohClientsPage from './+page.svelte';
import { endSession, setPrincipal } from '$lib/auth/state.svelte';
import { getLocale } from '$lib/i18n/locale';
import { formatDateTime } from '$lib/format';
import { m } from '$lib/paraglide/messages';

const json = (status: number, body: unknown): Response =>
	new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});
const ok = (data: unknown): Response => json(200, { data });
const fail = (status: number, code: string): Response => json(status, { error: { code } });

type Handler = (init?: RequestInit, url?: URL) => Response;
let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;
let handlers: Record<string, Handler>;
let calls: { key: string; body: unknown }[];

const ENTRIES = [
	{ id: 'iphone-k7q2x9', label: 'iPhone von Anna', device: 'dir-iphone-k7q2x9' },
	{ id: 'macbook-r4t8vn', label: 'MacBook Pro', device: null },
	{ id: 'reserve-tablet-p7k2', label: null, device: null },
];

const CLIENTS = [
	{
		id: 'dir-iphone-k7q2x9',
		name: 'iPhone von Anna',
		dns_label: 'iphone-anna',
		local_domain: 'lan.example.test',
		source: 'unifi',
		ips: ['192.168.1.11'],
		macs: [],
		vlan: null,
		online: true,
		last_seen: null,
	},
];

const BASE_VIEWS = [
	{ id: 'lan', is_default: true, subnets: ['192.168.1.0/24'], nodes: [], profile: 'default' },
];

function serve(
	overrides: Record<string, Handler> = {},
	entries: {
		id: string;
		label: string | null;
		device: string | null;
		view?: string | null;
	}[] = ENTRIES,
): void {
	calls = [];
	handlers = {
		'GET /api/v1/auth/me': () =>
			ok({ role: 'admin', actor_id: 'admin', actor_type: 'user', csrf_token: 'tok' }),
		'GET /api/v1/policy/client-ids': () => ok({ client_ids: entries }),
		'GET /api/v1/tls': () => ok({ tls: { mode: 'acme', public_domain: 'example.test' } }),
		'GET /api/v1/clients': () => ok({ clients: CLIENTS, manual: [] }),
		'GET /api/v1/listeners': () =>
			ok({
				listeners: [
					{
						id: 'doh-local',
						protocol: 'doh',
						address: '0.0.0.0:443',
						exposure: 'local',
						h3: false,
					},
				],
			}),
		'GET /api/v1/policy/records': () => ok({ records: [] }),
		'GET /api/v1/policy/views': () => ok({ views: BASE_VIEWS }),
		'GET /api/v1/query-log': (_init, url) => {
			const id = url?.searchParams.get('client_id');
			return ok({ queries: [], has_more: false, next_offset: null, _id: id });
		},
		...overrides,
	};
	fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = new URL(
			typeof input === 'string' ? input : input instanceof URL ? input.href : input.url,
			'http://localhost',
		);
		const method = init?.method ?? 'GET';
		const key = `${method} ${url.pathname}`;
		calls.push({ key, body: init?.body ? JSON.parse(String(init.body)) : undefined });
		const handler = handlers[key];
		if (!handler) return fail(404, 'control_api.not_found');
		return handler(init, url);
	});
	vi.stubGlobal('fetch', fetchMock);
}

const callsTo = (key: string) => calls.filter((call) => call.key === key);

beforeEach(() => {
	endSession();
	setPrincipal({ role: 'admin', actorId: 'admin', actorType: 'user', csrfToken: 'tok' });
	serve();
});

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

describe('DoH clients page', () => {
	it('lists registered devices by label, id and linked device', async () => {
		render(DohClientsPage);
		expect(await screen.findByRole('button', { name: 'iPhone von Anna' })).toBeInTheDocument();
		expect(screen.getByText('macbook-r4t8vn')).toBeInTheDocument();
		expect(screen.getByText('iPhone von Anna', { selector: 'a' })).toBeInTheDocument();
		expect(screen.getAllByText(m.doh_device_none())).toHaveLength(2);
		expect(
			screen.getByText('https://dns.example.test/dns-query/iphone-k7q2x9'),
		).toBeInTheDocument();
	});

	it('shows the empty state with no registered id', async () => {
		serve({}, []);
		render(DohClientsPage);
		expect(await screen.findByText(m.doh_empty())).toBeInTheDocument();
	});

	it('creates a client id with a generated, editable id from the label', async () => {
		serve({ 'POST /api/v1/policy/client-ids': () => ok({ version: 9, client_id: 'x' }) });
		const user = userEvent.setup();
		render(DohClientsPage);
		await screen.findByRole('button', { name: 'iPhone von Anna' });
		await user.click(screen.getByRole('button', { name: m.doh_add() }));
		await user.type(screen.getByLabelText(m.doh_label_label()), 'Gäste Handy');
		const idField = screen.getByLabelText(m.doh_id_label()) as HTMLInputElement;
		expect(idField.value).toMatch(/^gaeste-handy-[a-z0-9]{12}$/);
		await user.click(screen.getByRole('button', { name: m.doh_create_submit() }));
		await waitFor(() => expect(callsTo('POST /api/v1/policy/client-ids')).toHaveLength(1));
		const body = callsTo('POST /api/v1/policy/client-ids')[0].body as Record<string, string>;
		expect(body.label).toBe('Gäste Handy');
		expect(body.id).toMatch(/^gaeste-handy-[a-z0-9]{12}$/);
	});

	it('requires a name and shows a field message instead of calling the server', async () => {
		serve({ 'POST /api/v1/policy/client-ids': () => ok({ version: 9, client_id: 'x' }) });
		const user = userEvent.setup();
		render(DohClientsPage);
		await screen.findByRole('button', { name: 'iPhone von Anna' });
		await user.click(screen.getByRole('button', { name: m.doh_add() }));
		await user.click(screen.getByRole('button', { name: m.doh_create_submit() }));
		expect(screen.getByText(m.doh_label_required())).toBeInTheDocument();
		expect(callsTo('POST /api/v1/policy/client-ids')).toHaveLength(0);
	});

	it('edits label and device through PUT', async () => {
		serve({
			'PUT /api/v1/policy/client-ids/macbook-r4t8vn': () =>
				ok({ version: 10, client_id: 'macbook-r4t8vn' }),
		});
		const user = userEvent.setup();
		render(DohClientsPage);
		await user.click(await screen.findByRole('button', { name: 'MacBook Pro' }));
		const label = screen.getByLabelText(m.doh_label_label());
		await user.clear(label);
		await user.type(label, 'Büro-Laptop');
		await user.selectOptions(
			screen.getByLabelText(m.doh_device_select_label()),
			'dir-iphone-k7q2x9',
		);
		await user.click(screen.getByRole('button', { name: m.action_save() }));
		await waitFor(() =>
			expect(callsTo('PUT /api/v1/policy/client-ids/macbook-r4t8vn')).toHaveLength(1),
		);
		expect(callsTo('PUT /api/v1/policy/client-ids/macbook-r4t8vn')[0].body).toEqual({
			label: 'Büro-Laptop',
			device: 'dir-iphone-k7q2x9',
			view: null,
		});
	});

	it('blocks a duplicate label (case-insensitive) before saving', async () => {
		const user = userEvent.setup();
		render(DohClientsPage);
		await user.click(await screen.findByRole('button', { name: 'MacBook Pro' }));
		const label = screen.getByLabelText(m.doh_label_label());
		await user.clear(label);
		await user.type(label, 'iphone von anna');
		expect(screen.getByText(m.doh_label_taken())).toBeInTheDocument();
		expect(screen.getByRole('button', { name: m.action_save() })).toBeDisabled();
	});

	it('shows the server error when the save is refused', async () => {
		serve({
			'PUT /api/v1/policy/client-ids/macbook-r4t8vn': () => fail(400, 'policy.config.invalid'),
		});
		const user = userEvent.setup();
		render(DohClientsPage);
		await user.click(await screen.findByRole('button', { name: 'MacBook Pro' }));
		await user.type(screen.getByLabelText(m.doh_label_label()), ' 2');
		await user.click(screen.getByRole('button', { name: m.action_save() }));
		expect(
			await screen.findByText(m.error_policy_config_invalid({ reason: 'invalid' })),
		).toBeInTheDocument();
	});

	it('asks before deleting and explains the effect', async () => {
		const user = userEvent.setup();
		serve({
			'DELETE /api/v1/policy/client-ids/macbook-r4t8vn': () => ok({ version: 11, deleted: true }),
		});
		render(DohClientsPage);
		await user.click(await screen.findByRole('button', { name: 'MacBook Pro' }));
		await user.click(screen.getByRole('button', { name: m.action_delete() }));
		expect(screen.getByText(m.doh_delete_body())).toBeInTheDocument();
		expect(callsTo('DELETE /api/v1/policy/client-ids/macbook-r4t8vn')).toHaveLength(0);
		const dialog = screen.getByRole('dialog');
		await user.click(within(dialog).getByRole('button', { name: m.action_delete() }));
		await waitFor(() =>
			expect(callsTo('DELETE /api/v1/policy/client-ids/macbook-r4t8vn')).toHaveLength(1),
		);
	});

	it('is read-only for viewers', async () => {
		endSession();
		setPrincipal({ role: 'viewer', actorId: 'viewer', actorType: 'user', csrfToken: null });
		render(DohClientsPage);
		expect(await screen.findByText('iPhone von Anna')).toBeInTheDocument();
		expect(screen.queryByRole('button', { name: m.doh_add() })).not.toBeInTheDocument();
		expect(screen.queryByRole('button', { name: m.doh_profile_open() })).not.toBeInTheDocument();
		expect(screen.queryByRole('button', { name: 'iPhone von Anna' })).not.toBeInTheDocument();
		expect(callsTo('GET /api/v1/clients')).toHaveLength(0);
	});

	it('downloads the profile as a Blob with the mobileconfig type', async () => {
		const created: Blob[] = [];
		const createObjectURL = vi.fn((blob: Blob) => {
			created.push(blob);
			return 'blob:test';
		});
		vi.stubGlobal('URL', Object.assign(URL, { createObjectURL, revokeObjectURL: vi.fn() }));
		const user = userEvent.setup();
		render(DohClientsPage);
		await user.click(await screen.findByRole('button', { name: 'iPhone von Anna' }));
		await user.click(screen.getAllByRole('button', { name: m.doh_profile_open() })[0]);
		await user.click(screen.getByRole('button', { name: m.doh_profile_download() }));
		expect(createObjectURL).toHaveBeenCalledTimes(1);
		const blob = created[0];
		expect(blob.type).toBe('application/x-apple-aspen-config');
		const text = await new Promise<string>((resolve) => {
			const reader = new FileReader();
			reader.onload = () => resolve(String(reader.result));
			reader.readAsText(blob);
		});
		expect(text).toContain('<string>https://dns.example.test/dns-query/iphone-k7q2x9</string>');
	});

	it('shows the setup checklist states', async () => {
		serve({
			'GET /api/v1/tls': () => ok({ tls: { mode: 'self_signed', public_domain: 'example.test' } }),
		});
		render(DohClientsPage);
		// domain ok, certificate warn, listener ok, record missing -> two open items
		expect(await screen.findByText(m.doh_setup_open({ count: 2 }))).toBeInTheDocument();
		expect(screen.getByRole('button', { name: m.doh_record_action() })).toBeInTheDocument();
		expect(screen.getByText(m.doh_check_cert_missing())).toBeInTheDocument();
		// self-signed: no DoH address is shown, a warning replaces it
		expect(
			screen.queryByText('https://dns.example.test/dns-query/iphone-k7q2x9'),
		).not.toBeInTheDocument();
		// The certificate warning lives in the setup check; cards only say the address is pending.
		expect(screen.getAllByText(m.doh_url_pending()).length).toBeGreaterThan(0);
	});

	it('creates the home-network record through the records endpoint', async () => {
		serve({ 'PUT /api/v1/policy/records': () => ok({ version: 12, record: {} }) });
		const user = userEvent.setup();
		render(DohClientsPage);
		await user.click(await screen.findByRole('button', { name: m.doh_record_action() }));
		await user.type(screen.getByLabelText(m.doh_record_lan_label()), '192.168.1.2');
		await user.click(screen.getByRole('button', { name: m.action_save() }));
		await waitFor(() => expect(callsTo('PUT /api/v1/policy/records')).toHaveLength(1));
		expect(callsTo('PUT /api/v1/policy/records')[0].body).toMatchObject({
			name: 'dns.example.test',
			type: 'A',
			overrides: { lan: '192.168.1.2' },
		});
	});

	it('states the last assignment and warns for a linked device on the default range', async () => {
		const time = '2026-10-27T10:00:00Z';
		serve({
			'GET /api/v1/query-log': (_init, url) => {
				const id = url?.searchParams.get('client_id');
				if (id === 'iphone-k7q2x9') {
					return ok({
						queries: [
							{
								time,
								protocol: 'doh',
								source_ip: '192.168.1.11',
								view_id: 'lan',
								selection: { cause: 'default' },
							},
						],
						has_more: false,
						next_offset: null,
					});
				}
				return ok({ queries: [], has_more: false, next_offset: null });
			},
		});
		render(DohClientsPage);
		const expected = m.doh_seen_default({
			time: formatDateTime(new Date(time), getLocale()),
			protocol: 'DOH',
		});
		expect(await screen.findByText(expected)).toBeInTheDocument();
		expect(screen.getByText(m.doh_seen_warn())).toBeInTheDocument();
		expect(screen.getAllByText(m.doh_seen_never())).toHaveLength(2);
	});

	it('chooses the Netzbereich for the road, defaulting to none, and saves it on create', async () => {
		serve({
			'GET /api/v1/policy/views': () =>
				ok({
					views: [
						...BASE_VIEWS,
						{ id: 'unterwegs', is_default: false, subnets: [], nodes: [], profile: 'default' },
					],
				}),
			'POST /api/v1/policy/client-ids': () => ok({ version: 9, client_id: 'x' }),
		});
		const user = userEvent.setup();
		render(DohClientsPage);
		await screen.findByRole('button', { name: 'iPhone von Anna' });
		await user.click(screen.getByRole('button', { name: m.doh_add() }));
		const select = screen.getByLabelText(m.doh_view_label()) as HTMLSelectElement;
		expect(select.value).toBe('');
		expect(within(select).getByRole('option', { name: m.doh_view_none() })).toBeInTheDocument();
		expect(screen.getByText(m.doh_view_hint())).toBeInTheDocument();
		await user.type(screen.getByLabelText(m.doh_label_label()), 'Gast');
		await user.selectOptions(select, 'unterwegs');
		await user.click(screen.getByRole('button', { name: m.doh_create_submit() }));
		await waitFor(() => expect(callsTo('POST /api/v1/policy/client-ids')).toHaveLength(1));
		expect(callsTo('POST /api/v1/policy/client-ids')[0].body).toMatchObject({ view: 'unterwegs' });
	});

	it('shows the pinned range on the card, a muted default line otherwise, and the roaming last-seen', async () => {
		const time = '2026-10-27T10:00:00Z';
		serve(
			{
				'GET /api/v1/query-log': (_init, url) => {
					const id = url?.searchParams.get('client_id');
					if (id === 'iphone-k7q2x9') {
						return ok({
							queries: [
								{
									time,
									protocol: 'doh',
									source_ip: '198.18.77.0',
									view_id: 'unterwegs',
									selection: { cause: 'client_id' },
								},
							],
							has_more: false,
							next_offset: null,
						});
					}
					return ok({ queries: [], has_more: false, next_offset: null });
				},
			},
			[
				{
					id: 'iphone-k7q2x9',
					label: 'iPhone von Anna',
					device: 'dir-iphone-k7q2x9',
					view: 'unterwegs',
				},
				...ENTRIES.slice(1).map((entry) => ({ ...entry, view: null })),
			],
		);
		render(DohClientsPage);
		const link = await screen.findByRole('link', { name: m.doh_roam_view({ view: 'unterwegs' }) });
		expect(link).toHaveAttribute('href', '/zones');
		expect(screen.getAllByText(m.doh_roam_default())).toHaveLength(2);
		const expected = m.doh_seen_client_id({
			time: formatDateTime(new Date(time), getLocale()),
			protocol: 'DOH',
			view: 'unterwegs',
		});
		expect(await screen.findByText(expected)).toBeInTheDocument();
	});

	it('shows an unknown Netzbereich inline next to the select, not as a footer error', async () => {
		serve({
			'PUT /api/v1/policy/client-ids/macbook-r4t8vn': () =>
				json(400, {
					error: {
						code: 'policy.config.invalid',
						params: { reason: 'view_unknown', field: 'view' },
					},
				}),
		});
		const user = userEvent.setup();
		render(DohClientsPage);
		await user.click(await screen.findByRole('button', { name: 'MacBook Pro' }));
		await user.click(screen.getByRole('button', { name: m.action_save() }));
		const alert = await screen.findByText(m.doh_view_invalid());
		expect(alert).toHaveAttribute('role', 'alert');
		expect(
			screen.queryByText(m.error_policy_config_invalid({ reason: 'invalid' })),
		).not.toBeInTheDocument();
	});
});
