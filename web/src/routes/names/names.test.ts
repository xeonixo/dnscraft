// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import NamesPage from './+page.svelte';
import { endSession, setPrincipal } from '$lib/auth/state.svelte';
import { m } from '$lib/paraglide/messages';

const json = (status: number, body: unknown): Response =>
	new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});
const ok = (data: unknown): Response => json(200, { data });
const fail = (status: number, code: string, params: Record<string, unknown> = {}): Response =>
	json(status, { error: { code, params } });

type Handler = (init?: RequestInit, url?: string) => Response;
let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;
let handlers: Record<string, Handler>;

const view = (id: string, isDefault = false) => ({
	id,
	is_default: isDefault,
	subnets: [],
	nodes: [],
	profile: 'default',
});

const attachedZones = {
	zones: [
		{
			id: 'zone-example-test',
			name: 'example.test',
			status: 'active',
			name_servers: ['ada.ns.cloudflare.com'],
			source: 'public_domain',
		},
	],
	has_cloudflare_token: true,
};

const cfRecords = {
	records: [
		{
			id: 'cf-rec-nas-a',
			name: 'nas.example.test',
			record_type: 'A',
			content: '203.0.113.10',
			ttl: 60,
			proxied: false,
		},
	],
	page: 1,
	per_page: 100,
	total_count: 1,
	total_pages: 1,
};

function serve(overrides: Record<string, Handler> = {}): void {
	handlers = {
		'GET /api/v1/auth/me': () =>
			ok({ role: 'admin', actor_id: 'admin', actor_type: 'user', csrf_token: 'tok' }),
		'GET /api/v1/policy/views': () =>
			ok({
				views: [view('lan', true), view('guest'), view('unterwegs')],
			}),
		'GET /api/v1/policy/records': () =>
			ok({
				records: [
					{
						name: 'nas.example.test.',
						type: 'A',
						ttl: 60,
						rdata: '203.0.113.10',
						overrides: { lan: '192.0.2.50' },
					},
					{
						name: 'nas.lan.',
						type: 'A',
						ttl: 60,
						rdata: '192.0.2.50',
						overrides: { guest: '192.0.2.51' },
					},
				],
			}),
		'GET /api/v1/domain-zones': () => ok(attachedZones),
		'GET /api/v1/domain-zones/zone-example-test/records': () => ok(cfRecords),
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

const putBodies = (): unknown[] =>
	fetchMock.mock.calls
		.filter(
			([url, init]) =>
				String(url).includes('/policy/records') && (init?.method ?? 'GET') === 'PUT',
		)
		.map(([, init]) => JSON.parse(String(init?.body)));

const bodiesFor = (method: string, pathIncludes: string): unknown[] =>
	fetchMock.mock.calls
		.filter(
			([url, init]) =>
				String(url).includes(pathIncludes) && (init?.method ?? 'GET') === method,
		)
		.map(([, init]) => (init?.body ? JSON.parse(String(init.body)) : null));

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

describe('names sheet Öffentlich then Abweichungen', () => {
	it('shows Cloudflare public value above Netzbereich deviations', async () => {
		const user = userEvent.setup();
		render(NamesPage);
		expect(await screen.findByText('203.0.113.10')).toBeInTheDocument();

		await user.click(screen.getByRole('button', { name: /203\.0\.113\.10/ }));
		const dialog = await screen.findByRole('dialog');

		const publicHeading = within(dialog).getByText(m.names_field_public());
		const overridesHeading = within(dialog).getByText(m.names_field_overrides());
		expect(
			publicHeading.compareDocumentPosition(overridesHeading) & Node.DOCUMENT_POSITION_FOLLOWING,
		).toBeTruthy();

		await waitFor(() =>
			expect(within(dialog).getByLabelText(m.names_public_value_label())).toHaveValue(
				'203.0.113.10',
			),
		);
		expect(within(dialog).getByLabelText(m.names_overrides_view())).toHaveValue('lan');
		expect(within(dialog).getByLabelText(m.names_overrides_value())).toHaveValue('192.0.2.50');
		expect(within(dialog).getByLabelText(m.names_overrides_value())).toHaveAttribute(
			'placeholder',
			m.names_overrides_inherit_public(),
		);
	});

	it('links to TLS when the Cloudflare token is missing', async () => {
		handlers['GET /api/v1/domain-zones'] = () =>
			ok({
				zones: [{ name: 'example.test', status: null, name_servers: [], source: 'public_domain' }],
				has_cloudflare_token: false,
			});
		const user = userEvent.setup();
		render(NamesPage);
		await user.click(await screen.findByRole('button', { name: /203\.0\.113\.10/ }));
		const dialog = await screen.findByRole('dialog');
		expect(within(dialog).getByText(m.names_public_token_missing())).toBeInTheDocument();
		const cta = within(dialog).getByRole('link', { name: m.names_public_token_cta() });
		expect(cta).toHaveAttribute('href', expect.stringMatching(/\/tls$/));
	});

	it('allows purely internal names without a public row', async () => {
		const user = userEvent.setup();
		render(NamesPage);
		await user.click(await screen.findByRole('button', { name: /192\.0\.2\.50/ }));
		const dialog = await screen.findByRole('dialog');
		expect(within(dialog).getByText(m.names_public_internal())).toBeInTheDocument();
		expect(within(dialog).queryByLabelText(m.names_public_value_label())).toBeNull();
		expect(within(dialog).getByText(m.names_field_overrides())).toBeInTheDocument();
		expect(within(dialog).getByLabelText(m.names_overrides_value())).toHaveAttribute(
			'placeholder',
			m.names_overrides_inherit_standard(),
		);
	});

	it('keeps structured Netzbereich rows instead of freitext zone=value lines', async () => {
		const user = userEvent.setup();
		render(NamesPage);
		await user.click(await screen.findByRole('button', { name: /203\.0\.113\.10/ }));
		const dialog = await screen.findByRole('dialog');
		expect(within(dialog).queryByRole('textbox', { name: /zone=wert|zone=value/i })).toBeNull();
		expect(within(dialog).queryByLabelText(/Zonen-Überschreibungen|Per-zone overrides/i)).toBeNull();
		expect(within(dialog).getByText(m.names_field_overrides())).toBeInTheDocument();
	});

	it('adds and removes override rows and saves the same overrides map shape', async () => {
		handlers['PUT /api/v1/policy/records'] = () =>
			ok({
				version: 4,
				record: {
					name: 'nas.example.test.',
					type: 'A',
					ttl: 60,
					rdata: '203.0.113.10',
					overrides: { lan: '192.0.2.50', guest: '10.0.0.1' },
				},
			});
		handlers['GET /api/v1/policy/records'] = (() => {
			let n = 0;
			return () => {
				n += 1;
				return ok({
					records: [
						{
							name: 'nas.example.test.',
							type: 'A',
							ttl: 60,
							rdata: '203.0.113.10',
							overrides:
								n === 1 ? { lan: '192.0.2.50' } : { lan: '192.0.2.50', guest: '10.0.0.1' },
						},
					],
				});
			};
		})();

		const user = userEvent.setup();
		render(NamesPage);
		await user.click(await screen.findByRole('button', { name: /203\.0\.113\.10/ }));
		const dialog = await screen.findByRole('dialog');

		await user.click(within(dialog).getByRole('button', { name: m.names_overrides_add() }));
		const selects = within(dialog).getAllByLabelText(m.names_overrides_view());
		expect(selects).toHaveLength(2);
		await user.selectOptions(selects[1]!, 'guest');
		const values = within(dialog).getAllByLabelText(m.names_overrides_value());
		await user.clear(values[1]!);
		await user.type(values[1]!, '10.0.0.1');

		await user.click(within(dialog).getByRole('button', { name: m.action_save() }));
		await waitFor(() => expect(putBodies()).toHaveLength(1));
		expect(putBodies()[0]).toMatchObject({
			name: 'nas.example.test.',
			type: 'A',
			ttl: 60,
			rdata: '203.0.113.10',
			overrides: { lan: '192.0.2.50', guest: '10.0.0.1' },
		});
	});

	it('omits empty override values so missing keys inherit the default', async () => {
		handlers['PUT /api/v1/policy/records'] = () =>
			ok({
				version: 5,
				record: {
					name: 'nas.example.test.',
					type: 'A',
					ttl: 60,
					rdata: '203.0.113.10',
					overrides: {},
				},
			});

		const user = userEvent.setup();
		render(NamesPage);
		await user.click(await screen.findByRole('button', { name: /203\.0\.113\.10/ }));
		const dialog = await screen.findByRole('dialog');
		await user.clear(within(dialog).getByLabelText(m.names_overrides_value()));
		await user.click(within(dialog).getByRole('button', { name: m.action_save() }));
		await waitFor(() => expect(putBodies()).toHaveLength(1));
		expect(putBodies()[0]).toMatchObject({ overrides: {} });
	});

	it('removes an override row before save', async () => {
		handlers['PUT /api/v1/policy/records'] = () =>
			ok({
				version: 6,
				record: {
					name: 'nas.example.test.',
					type: 'A',
					ttl: 60,
					rdata: '203.0.113.10',
					overrides: {},
				},
			});

		const user = userEvent.setup();
		render(NamesPage);
		await user.click(await screen.findByRole('button', { name: /203\.0\.113\.10/ }));
		const dialog = await screen.findByRole('dialog');
		await user.click(within(dialog).getByRole('button', { name: m.names_overrides_remove() }));
		expect(within(dialog).queryByLabelText(m.names_overrides_view())).toBeNull();
		expect(within(dialog).getByText(m.names_overrides_empty())).toBeInTheDocument();
		await user.click(within(dialog).getByRole('button', { name: m.action_save() }));
		await waitFor(() => expect(putBodies()).toHaveLength(1));
		expect(putBodies()[0]).toMatchObject({ overrides: {} });
	});

	it('opens a read-only sheet for viewers', async () => {
		setPrincipal({ role: 'viewer', actorId: 'bob', actorType: 'user', csrfToken: null });
		const user = userEvent.setup();
		render(NamesPage);
		expect(await screen.findByText('203.0.113.10')).toBeInTheDocument();
		expect(screen.queryByText(m.names_add())).not.toBeInTheDocument();
		expect(screen.queryByText(m.names_zones_manage())).not.toBeInTheDocument();

		await user.click(screen.getByRole('button', { name: /203\.0\.113\.10/ }));
		const dialog = await screen.findByRole('dialog');
		expect(within(dialog).getByText(m.names_view_title())).toBeInTheDocument();
		expect(within(dialog).getByLabelText(m.names_public_value_label())).toHaveTextContent(
			'203.0.113.10',
		);
		expect(within(dialog).getByLabelText(m.names_overrides_view())).toBeDisabled();
		expect(within(dialog).getByLabelText(m.names_field_rdata())).toBeDisabled();
		expect(within(dialog).queryByRole('button', { name: m.action_save() })).toBeNull();
		expect(within(dialog).queryByRole('button', { name: m.names_overrides_add() })).toBeNull();
	});

	it('saves Öffentlich to Cloudflare and aligns local default without wiping overrides', async () => {
		handlers['PUT /api/v1/domain-zones/zone-example-test/records'] = () =>
			ok({
				id: 'cf-rec-nas-a',
				name: 'nas.example.test',
				record_type: 'A',
				content: '198.51.100.9',
				ttl: 60,
				proxied: false,
			});
		handlers['PUT /api/v1/policy/records'] = () =>
			ok({
				version: 7,
				record: {
					name: 'nas.example.test.',
					type: 'A',
					ttl: 60,
					rdata: '198.51.100.9',
					overrides: { lan: '192.0.2.50' },
				},
			});

		const user = userEvent.setup();
		render(NamesPage);
		await user.click(await screen.findByRole('button', { name: /203\.0\.113\.10/ }));
		const dialog = await screen.findByRole('dialog');
		const publicField = await waitFor(() => {
			const field = within(dialog).getByLabelText(m.names_public_value_label());
			expect(field).toHaveValue('203.0.113.10');
			return field;
		});
		await user.clear(publicField);
		await user.type(publicField, '198.51.100.9');
		await user.click(within(dialog).getByRole('button', { name: m.action_save() }));

		await waitFor(() => expect(bodiesFor('PUT', '/domain-zones/zone-example-test/records')).toHaveLength(1));
		expect(bodiesFor('PUT', '/domain-zones/zone-example-test/records')[0]).toMatchObject({
			id: 'cf-rec-nas-a',
			name: 'nas.example.test',
			type: 'A',
			content: '198.51.100.9',
		});
		await waitFor(() => expect(putBodies()).toHaveLength(1));
		expect(putBodies()[0]).toMatchObject({
			name: 'nas.example.test.',
			type: 'A',
			rdata: '198.51.100.9',
			overrides: { lan: '192.0.2.50' },
		});
	});

	it('saves Abweichungen via policy records only (no Cloudflare mutate)', async () => {
		handlers['PUT /api/v1/policy/records'] = () =>
			ok({
				version: 8,
				record: {
					name: 'nas.example.test.',
					type: 'A',
					ttl: 60,
					rdata: '203.0.113.10',
					overrides: { lan: '10.0.0.9' },
				},
			});

		const user = userEvent.setup();
		render(NamesPage);
		await user.click(await screen.findByRole('button', { name: /203\.0\.113\.10/ }));
		const dialog = await screen.findByRole('dialog');
		await waitFor(() =>
			expect(within(dialog).getByLabelText(m.names_public_value_label())).toHaveValue(
				'203.0.113.10',
			),
		);
		const overrideValue = within(dialog).getByLabelText(m.names_overrides_value());
		await user.clear(overrideValue);
		await user.type(overrideValue, '10.0.0.9');
		await user.click(within(dialog).getByRole('button', { name: m.action_save() }));

		await waitFor(() => expect(putBodies()).toHaveLength(1));
		expect(putBodies()[0]).toMatchObject({
			rdata: '203.0.113.10',
			overrides: { lan: '10.0.0.9' },
		});
		expect(bodiesFor('PUT', '/domain-zones/')).toHaveLength(0);
		expect(bodiesFor('POST', '/domain-zones/')).toHaveLength(0);
		expect(bodiesFor('DELETE', '/domain-zones/')).toHaveLength(0);
	});

	it('attaches a discoverable Cloudflare zone from the Namen module', async () => {
		handlers['GET /api/v1/domain-zones'] = ((_init, url) => {
			const discover = url?.includes('discover=1');
			return ok({
				zones: attachedZones.zones,
				has_cloudflare_token: true,
				...(discover
					? {
							discoverable: [
								...attachedZones.zones,
								{
									id: 'zone-unattached',
									name: 'other.example',
									status: 'active',
									name_servers: [],
									source: 'discoverable',
								},
							],
						}
					: {}),
			});
		}) as Handler;
		handlers['POST /api/v1/domain-zones/attach'] = () =>
			ok({
				id: 'zone-unattached',
				name: 'other.example',
				status: 'active',
				name_servers: [],
				source: 'dns_provider',
			});

		const user = userEvent.setup();
		render(NamesPage);
		await user.click(await screen.findByRole('button', { name: m.names_zones_manage() }));
		const dialog = await screen.findByRole('dialog');
		expect(within(dialog).getByText(m.names_zones_title())).toBeInTheDocument();
		await waitFor(() => expect(within(dialog).getByText('other.example')).toBeInTheDocument());
		await user.click(within(dialog).getByRole('button', { name: m.names_zones_attach() }));
		await waitFor(() => expect(bodiesFor('POST', '/domain-zones/attach')).toHaveLength(1));
		expect(bodiesFor('POST', '/domain-zones/attach')[0]).toMatchObject({
			name: 'other.example',
			zone_id: 'zone-unattached',
		});
	});

	it('warns when enabling proxied on a DoT inventory name', async () => {
		handlers['GET /api/v1/policy/records'] = () =>
			ok({
				records: [
					{
						name: 'ns1.dns.example.test.',
						type: 'A',
						ttl: 120,
						rdata: '192.0.2.10',
						overrides: {},
					},
				],
			});
		handlers['GET /api/v1/domain-zones/zone-example-test/records'] = () =>
			ok({
				records: [
					{
						id: 'cf-rec-ns1-a',
						name: 'ns1.dns.example.test',
						record_type: 'A',
						content: '192.0.2.10',
						ttl: 120,
						proxied: false,
					},
				],
				page: 1,
				per_page: 100,
				total_count: 1,
				total_pages: 1,
			});

		const user = userEvent.setup();
		render(NamesPage);
		await user.click(await screen.findByRole('button', { name: /192\.0\.2\.10/ }));
		const dialog = await screen.findByRole('dialog');
		await waitFor(() =>
			expect(within(dialog).getByLabelText(m.names_public_value_label())).toHaveValue(
				'192.0.2.10',
			),
		);
		expect(within(dialog).queryByText(m.names_public_proxied_warn())).toBeNull();
		const proxied = within(dialog).getByRole('switch', { name: m.names_public_proxied_label() });
		await user.click(proxied.closest('label') ?? proxied);
		expect(within(dialog).getByText(m.names_public_proxied_warn())).toBeInTheDocument();
	});
});
