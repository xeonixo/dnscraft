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

		expect(within(dialog).getByLabelText(m.names_public_value_label())).toHaveTextContent(
			'203.0.113.10',
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
});
