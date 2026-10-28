// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import GeneralPage from './settings/+page.svelte';
import McpSettingsPage from './settings/mcp/+page.svelte';
import ApiExplorerPage from './settings/api/+page.svelte';
import ListenersPage from './listeners/+page.svelte';
import TlsPage from './tls/+page.svelte';
import ClusterPage from './cluster/+page.svelte';
import { endSession, setPrincipal } from '$lib/auth/state.svelte';
import { m } from '$lib/paraglide/messages';

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
		'GET /api/v1/status': () =>
			ok({
				version: '1.0.0',
				ready: true,
				modules_not_ready: [],
				tls_mode: 'self_signed',
				tls_fingerprint: 'aa'.repeat(32),
				tls: { identifiers: ['dns.test'] },
			}),
		'GET /api/v1/config': () =>
			ok({
				version: 3,
				config: {
					filtering: { sets: [], lists: [] },
					clients: { manual: [] },
					policy: { profiles: [], views: [], records: [], client_ids: [] },
					listeners: { listeners: [] },
					tls: { mode: 'self_signed', public_domain: 'dns.test' },
					control_api_settings: { query_log: { retention_days: 30 } },
					mcp: { enabled: true, write_tools_enabled: false, max_custom_rules_per_set: 100 },
				},
			}),
		'GET /api/v1/update/check': () =>
			ok({
				enabled: false,
				current: '1.0.0',
				latest: null,
				update_available: false,
				release_url: null,
				checked_at: null,
			}),
		'GET /api/v1/auth/tokens': () => ok({ tokens: [] }),
		'GET /api/v1/audit': () => ok({ audit: [] }),
		'GET /api/v1/tls/status': () =>
			ok({
				mode: 'self_signed',
				fingerprint_sha256: 'aa'.repeat(32),
				not_before: '2026-10-01T00:00:00Z',
				not_after: '2027-01-01T00:00:00Z',
				days_to_expiry: 90,
				identifiers: ['dns.test'],
				issuer: 'DNScraft (self-signed)',
				subject: 'dns.test',
				self_signed: true,
			}),
		'GET /api/v1/tls': () =>
			ok({
				tls: {
					mode: 'self_signed',
					public_domain: 'dns.test',
					dyndns: { enabled: false, hostname: '' },
					acme: { enabled: false, email: 'ops@dns.test' },
				},
			}),
		...overrides,
	};
	fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		const method = init?.method ?? 'GET';
		const path =
			new URL(url, 'http://localhost').pathname + new URL(url, 'http://localhost').search;
		const key = `${method} ${new URL(url, 'http://localhost').pathname}`;
		const handler = handlers[key] ?? handlers[`${method} ${path}`];
		if (!handler) return fail(404, 'control_api.not_found');
		return handler(init, url);
	});
	vi.stubGlobal('fetch', fetchMock);
}

beforeEach(() => {
	endSession();
	setPrincipal({ role: 'admin', actorId: 'admin', actorType: 'user', csrfToken: 'tok' });
	serve();
});

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

describe('settings general (W9)', () => {
	it('shows account and hides pending placeholders', async () => {
		render(GeneralPage);
		expect(await screen.findByText(m.settings_account_actor())).toBeInTheDocument();
		expect(screen.queryByText(m.settings_pending())).not.toBeInTheDocument();
	});

	it('creates a token and shows plaintext once', async () => {
		serve({
			'POST /api/v1/auth/tokens': () =>
				ok({
					id: 'abc',
					name: 'ci',
					scope: 'viewer',
					actor_id: 'admin',
					created_at: '2026-10-27T12:00:00Z',
					expires_at: null,
					token: 'secret-plaintext-once',
					warnings: [],
				}),
		});
		const user = userEvent.setup();
		render(GeneralPage);
		await user.click(await screen.findByRole('button', { name: m.token_create() }));
		await user.type(screen.getByLabelText(m.token_name_label()), 'ci');
		await user.click(screen.getByRole('button', { name: m.token_create_confirm() }));
		expect(await screen.findByText('secret-plaintext-once')).toBeInTheDocument();
		expect(screen.getByText(m.token_plaintext_body())).toBeInTheDocument();
	});

	it('hides tokens and audit sections for viewers', async () => {
		endSession();
		setPrincipal({ role: 'viewer', actorId: 'viewer', actorType: 'user', csrfToken: null });
		render(GeneralPage);
		expect(screen.queryByRole('button', { name: m.token_create() })).not.toBeInTheDocument();
		expect(screen.queryByLabelText(m.audit_search_label())).not.toBeInTheDocument();
	});
});

describe('TLS screen', () => {
	it('never renders stored private key fields', async () => {
		render(TlsPage);
		await screen.findByRole('radio', { name: m.tls_tab_overview() });
		expect(screen.queryByDisplayValue(/BEGIN PRIVATE KEY/)).not.toBeInTheDocument();
		expect(screen.getByText(m.tls_private_key_never())).toBeInTheDocument();
	});

	it('shows overview status and certificate tab forms', async () => {
		const user = userEvent.setup();
		render(TlsPage);
		expect(await screen.findByText(m.tls_issuer_label())).toBeInTheDocument();
		await user.click(screen.getByRole('radio', { name: m.tls_tab_cert() }));
		expect(await screen.findByLabelText(m.tls_public_domain_label())).toBeInTheDocument();
		expect(screen.queryByDisplayValue(/BEGIN PRIVATE KEY/)).not.toBeInTheDocument();
	});

	it('shows per-node DynDNS profiles and CNAME expected records', async () => {
		serve({
			'GET /api/v1/cluster/nodes': () =>
				ok([
					{
						node_id: 'node1',
						role: 'master',
						fingerprint: 'aa'.repeat(32),
						joined_at: '2026-10-27T12:00:00Z',
						last_seen: null,
						applied_config_version: 3,
						revoked: false,
					},
					{
						node_id: 'node2',
						role: 'sub_node',
						fingerprint: 'bb'.repeat(32),
						joined_at: '2026-10-27T12:00:00Z',
						last_seen: null,
						applied_config_version: 3,
						revoked: false,
					},
				]),
			'GET /api/v1/tls/status': () =>
				ok({
					mode: 'self_signed',
					fingerprint_sha256: 'aa'.repeat(32),
					identifiers: ['dns.example.test'],
					self_signed: true,
					dyndns_ipv4: '192.0.2.10',
					dyndns_ipv6: '2001:db8::10',
					last_dyndns_success: '2026-10-28T14:00:00Z',
				}),
			'GET /api/v1/tls': () =>
				ok({
					tls: {
						mode: 'self_signed',
						public_domain: 'example.test',
						dyndns: {
							enabled: true,
							hostname: 'ns1.dns.example.test',
							public_entry: true,
							ipv4: true,
							ipv6: true,
							nodes: [
								{
									node_id: 'node1',
									hostname: 'ns1.dns.example.test',
									enabled: true,
									ipv4: true,
									ipv6: true,
									public_entry: true,
									ipv6_identifier: { mode: 'eui64' },
									interfaces: ['eth0'],
								},
								{
									node_id: 'node2',
									hostname: 'ns2.dns.example.test',
									enabled: false,
									ipv4: true,
									ipv6: false,
									public_entry: false,
								},
							],
						},
						dns_provider: {
							kind: 'cloudflare',
							cloudflare: { zone_id: 'zone-example-test' },
							zones: [],
						},
						acme: { enabled: false, email: 'ops@example.test' },
					},
					has_cloudflare_token: true,
				}),
		});
		const user = userEvent.setup();
		render(TlsPage);
		await user.click(await screen.findByRole('radio', { name: m.tls_tab_provider() }));
		expect(await screen.findByText(m.tls_dns_provider_hint())).toBeInTheDocument();
		expect(screen.getByDisplayValue('zone-example-test')).toBeInTheDocument();
		expect(screen.getByPlaceholderText(m.tls_cf_token_set())).toBeInTheDocument();
		await user.click(screen.getByRole('radio', { name: m.tls_tab_dns() }));
		expect(await screen.findByText(m.tls_dns_provider_cloudflare())).toBeInTheDocument();
		expect(screen.getByRole('button', { name: m.tls_dns_provider_configure() })).toBeInTheDocument();
		expect(await screen.findByText(m.tls_dyndns_detected_group())).toBeInTheDocument();
		expect(screen.getByText('192.0.2.10')).toBeInTheDocument();
		expect(await screen.findByText(m.tls_dyndns_nodes_group())).toBeInTheDocument();
		expect(screen.getByDisplayValue('ns1.dns.example.test')).toBeInTheDocument();
		expect(screen.getByDisplayValue('ns2.dns.example.test')).toBeInTheDocument();
		expect(screen.getByDisplayValue('eth0')).toBeInTheDocument();
		expect(screen.getByRole('radio', { name: m.tls_dyndns_ipv6_mode_eui64() })).toBeChecked();
		expect(screen.getByText(m.tls_dyndns_ipv6_mode_eui64_hint())).toBeInTheDocument();
		await user.click(screen.getByRole('button', { name: m.tls_dyndns_ipv6_help() }));
		expect(await screen.findByText(m.tls_dyndns_ipv6_help_eui64_body())).toBeInTheDocument();
		expect(screen.getAllByText(m.tls_record_tag_cname()).length).toBeGreaterThanOrEqual(2);
		expect(screen.getAllByText(/CNAME → ns1\.dns\.example\.test/).length).toBeGreaterThanOrEqual(1);
	});
});

describe('cluster join token', () => {
	it('shows one-time token with copy action', async () => {
		serve({
			'GET /api/v1/cluster/nodes': () => ok([]),
			'POST /api/v1/cluster/join-tokens': () =>
				ok({ token: 'join-secret', expires_at: '2026-10-27T13:00:00Z' }),
		});
		const user = userEvent.setup();
		render(ClusterPage);
		await user.click(await screen.findByRole('button', { name: m.cluster_join_token() }));
		await user.type(screen.getByLabelText(m.cluster_join_node_label()), 'node-9');
		await user.click(screen.getByRole('button', { name: m.cluster_join_mint() }));
		expect(await screen.findByText('join-secret')).toBeInTheDocument();
		expect(screen.getByRole('button', { name: m.action_copy() })).toBeInTheDocument();
	});
});

describe('listeners node scope', () => {
	it('shows pinned nodes and all-nodes label in the list', async () => {
		serve({
			'GET /api/v1/listeners': () =>
				ok({
					listeners: [
						{
							id: 'doh-local',
							protocol: 'doh',
							address: '127.0.0.1:443',
							exposure: 'local',
							h3: false,
							nodes: ['node2'],
						},
						{
							id: 'doh-any',
							protocol: 'doh',
							address: '0.0.0.0:443',
							exposure: 'public',
							h3: false,
							nodes: [],
						},
					],
				}),
			'GET /api/v1/cluster/nodes': () =>
				ok([
					{
						node_id: 'node2',
						role: 'sub_node',
						fingerprint: 'aa'.repeat(32),
						joined_at: '2026-10-27T12:00:00Z',
						last_seen: null,
						applied_config_version: 3,
						revoked: false,
					},
				]),
		});
		render(ListenersPage);
		expect(await screen.findByText(/node2/)).toBeInTheDocument();
		expect(screen.getByText(new RegExp(m.listeners_nodes_all()))).toBeInTheDocument();
	});

	it('hides public for plaintext and updates the default port', async () => {
		serve({
			'GET /api/v1/listeners': () => ok({ listeners: [] }),
			'GET /api/v1/cluster/nodes': () => ok([]),
		});
		const user = userEvent.setup();
		render(ListenersPage);
		await user.click(await screen.findByRole('button', { name: m.listeners_add() }));
		expect(screen.queryByLabelText(m.listeners_id_label())).toBeNull();
		expect(screen.getByText(/local-doh/)).toBeInTheDocument();
		expect(screen.getByRole('switch', { name: m.listeners_exposure_public() })).toBeInTheDocument();
		expect(screen.getByDisplayValue('127.0.0.1:443')).toBeInTheDocument();
		await user.selectOptions(screen.getByLabelText(m.listeners_protocol_label()), 'udp53');
		expect(screen.queryByRole('switch', { name: m.listeners_exposure_public() })).toBeNull();
		expect(screen.getByText(m.listeners_exposure_plaintext_hint())).toBeInTheDocument();
		expect(screen.getByDisplayValue('127.0.0.1:53')).toBeInTheDocument();
		await user.selectOptions(screen.getByLabelText(m.listeners_protocol_label()), 'dot');
		expect(screen.getByDisplayValue('127.0.0.1:853')).toBeInTheDocument();
		expect(screen.getByRole('switch', { name: m.listeners_exposure_public() })).toBeInTheDocument();
		await user.click(screen.getByRole('radio', { name: m.listeners_family_ipv6() }));
		expect(screen.getByDisplayValue('[::1]:853')).toBeInTheDocument();
		expect(screen.getByText(/local-dot-v6/)).toBeInTheDocument();
	});

	it('saves a public DoH listener with an auto id', async () => {
		const put = vi.fn(() =>
			ok({
				version: 2,
				listener: {
					id: 'public-doh',
					protocol: 'doh',
					address: '0.0.0.0:443',
					exposure: 'public',
					h3: true,
					nodes: [],
				},
			}),
		);
		serve({
			'GET /api/v1/listeners': () => ok({ listeners: [] }),
			'GET /api/v1/cluster/nodes': () => ok([]),
			'GET /api/v1/config': () => ok({ version: 1, config: {} }),
			'PUT /api/v1/listeners': put,
		});
		const user = userEvent.setup();
		render(ListenersPage);
		await user.click(await screen.findByRole('button', { name: m.listeners_add() }));
		for (const name of [m.listeners_exposure_public(), m.listeners_h3_label()]) {
			const toggle = screen.getByRole('switch', { name });
			toggle.focus();
			await user.keyboard(' ');
		}
		expect(screen.getByText(/public-doh/)).toBeInTheDocument();
		await user.click(screen.getByRole('button', { name: m.action_save() }));
		await waitFor(() => expect(put).toHaveBeenCalled());
		const init = put.mock.calls[0]?.[0] as RequestInit | undefined;
		const body = JSON.parse(String(init?.body ?? '{}')) as {
			id: string;
			exposure: string;
			h3: boolean;
			address: string;
		};
		expect(body).toMatchObject({
			id: 'public-doh',
			exposure: 'public',
			h3: true,
			address: '0.0.0.0:443',
		});
	});
});

describe('cluster node detail', () => {
	it('shows identity, connection and applied config version in the detail sheet', async () => {
		serve({
			'GET /api/v1/cluster/nodes': () =>
				ok([
					{
						node_id: 'node2',
						role: 'sub_node',
						fingerprint: 'bb'.repeat(32),
						joined_at: '2026-10-27T12:00:00Z',
						last_seen: '2026-10-28T12:00:00Z',
						applied_config_version: 7,
						revoked: false,
						local: false,
						connected: true,
						remote_addr: '192.0.2.91:8443',
						transport: 'mtls',
					},
				]),
		});
		const user = userEvent.setup();
		render(ClusterPage);
		await user.click(await screen.findByRole('button', { name: m.cluster_detail() }));
		const dialog = await screen.findByRole('dialog');
		expect(within(dialog).getByText(m.cluster_field_node_id())).toBeInTheDocument();
		expect(within(dialog).getByText('node2')).toBeInTheDocument();
		expect(within(dialog).getByText(m.cluster_field_remote_addr())).toBeInTheDocument();
		expect(within(dialog).getByText('192.0.2.91:8443')).toBeInTheDocument();
		expect(within(dialog).getByText(m.cluster_transport_mtls())).toBeInTheDocument();
		expect(within(dialog).getByText(m.cluster_connection_connected())).toBeInTheDocument();
		expect(within(dialog).getByText(m.cluster_field_applied_version())).toBeInTheDocument();
		expect(within(dialog).getByText('7')).toBeInTheDocument();
	});
});

describe('unavailable endpoints', () => {
	it('shows unavailable notice for listeners 404', async () => {
		serve({
			'GET /api/v1/listeners': () => fail(404, 'control_api.not_found'),
		});
		render(ListenersPage);
		expect(await screen.findByText(m.dashboard_unavailable_title())).toBeInTheDocument();
	});
});

describe('audit XSS inert', () => {
	it('renders hostile actor_id as text', async () => {
		serve({
			'GET /api/v1/audit': () =>
				ok({
					audit: [
						{
							id: 1,
							time: '2026-10-27T12:00:00Z',
							node_id: 'n1',
							actor_id: '<img src=x onerror=alert(1)>',
							actor_type: 'user',
							action: 'config.replace',
							object_type: null,
							object_id: null,
							config_version: 1,
							before_digest: null,
							after_digest: null,
							before: null,
							after: null,
							result: 'ok',
							error_code: null,
						},
					],
				}),
		});
		render(GeneralPage);
		await screen.findByText('config.replace');
		expect(document.body.innerHTML).toContain('&lt;img src=x onerror=alert(1)&gt;');
		expect(document.body.innerHTML).not.toContain('<img src=x onerror=alert(1)>');
	});
});

describe('settings tabs W9', () => {
	it('renders MCP settings when config exposes mcp section', async () => {
		render(McpSettingsPage);
		expect(await screen.findByText(m.settings_mcp_enabled())).toBeInTheDocument();
	});

	it('renders API explorer catalog', async () => {
		render(ApiExplorerPage);
		expect(await screen.findByText(m.api_explorer_catalog())).toBeInTheDocument();
	});
});
