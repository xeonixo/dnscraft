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
import McpRulesPage from './mcp-rules/+page.svelte';
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
				not_after: '2027-01-01T00:00:00Z',
				identifiers: ['dns.test'],
				self_signed: true,
			}),
		'GET /api/v1/tls': () => ok({ tls: { public_domain: 'dns.test', dyndns: { hostname: '' } } }),
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
		await screen.findByText(m.tls_status_group());
		expect(screen.queryByDisplayValue(/BEGIN PRIVATE KEY/)).not.toBeInTheDocument();
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

describe('mcp-rules segmented filter', () => {
	it('loads rules and switches kind', async () => {
		serve({
			'GET /api/v1/filtering/mcp-rules': (_init, url) => {
				const kind = new URL(String(url), 'http://localhost').searchParams.get('kind') ?? 'rules';
				if (kind === 'pauses') {
					return ok({
						filter_set_id: 'default',
						kind,
						pauses: [{ filter_set_id: 'default', paused_until: '2026-10-27T14:00:00Z' }],
						has_more: false,
						next_offset: null,
					});
				}
				return ok({
					filter_set_id: 'default',
					kind: 'rules',
					rules: [
						{
							id: 'r1',
							domain: 'blocked.test',
							include_subdomains: true,
							rule_text: '||blocked.test^',
							created_at: '2026-10-27T10:00:00Z',
							expires_at: null,
						},
					],
					has_more: false,
					next_offset: null,
				});
			},
		});
		const user = userEvent.setup();
		render(McpRulesPage);
		expect(await screen.findByText('blocked.test')).toBeInTheDocument();
		const group = screen.getByRole('radiogroup', { name: m.mcp_rules_kind_label() });
		await user.click(within(group).getByRole('radio', { name: m.mcp_rules_kind_pauses() }));
		await waitFor(() => expect(screen.getByText('default')).toBeInTheDocument());
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
