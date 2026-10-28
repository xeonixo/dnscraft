// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import ClientsPage from '../routes/clients/+page.svelte';
import RulesPage from '../routes/rules/+page.svelte';
import AuditPanel from '$lib/settings/AuditPanel.svelte';
import TokensPanel from '$lib/settings/TokensPanel.svelte';
import QueryLogPage from '../routes/query-log/+page.svelte';
import QueryDetailPage from '../routes/query-log/[id]/+page.svelte';
import type { QueryRecord } from '$lib/api/query-log';
import { endSession, setPrincipal } from '$lib/auth/state.svelte';
import { displayText } from '$lib/safe-text';

const queryLogPage = vi.hoisted(() => ({ url: new URL('http://localhost/query-log') }));
const detailPage = vi.hoisted(() => ({ params: { id: 'rec-xss' } as Record<string, string> }));

vi.mock('$app/state', () => ({
	page: {
		get url() {
			return queryLogPage.url;
		},
		get params() {
			return detailPage.params;
		},
	},
}));

/** Hostile strings mirrored from mock/fixtures.mjs (query log + config corpus). */
export const XSS_CORPUS = [
	'<script>alert(1)</script>',
	'"><img src=x onerror=alert(1)>',
	'bad\u0000name.example',
	'line\nbreak.example',
	'evil‮gnp.example',
	`${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(63)}.example`,
] as const;

const json = (status: number, body: unknown): Response =>
	new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});
const ok = (data: unknown): Response => json(200, { data });

let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;

function stubFetch(handlers: Record<string, () => Response>): void {
	fetchMock = vi.fn(async (input: RequestInfo | URL) => {
		const url = new URL(
			typeof input === 'string' ? input : input instanceof URL ? input.href : input.url,
			'http://localhost',
		);
		const key = `GET ${url.pathname}`;
		const handler = handlers[key] ?? handlers[url.pathname];
		if (!handler) return json(404, { error: { code: 'control_api.not_found' } });
		return handler();
	});
	vi.stubGlobal('fetch', fetchMock);
}

function hostileRecord(id: string, domain: string, extra: Partial<QueryRecord> = {}): QueryRecord {
	return {
		id,
		node_id: 'node1',
		listener_id: 'lan-udp',
		protocol: 'doh',
		source_ip: '192.0.2.11',
		source_ip_truncated: true,
		client_id: null,
		client: null,
		query: { name: domain, type: 'A', class: 'IN' },
		view_id: 'lan',
		profile_id: 'default',
		filter_set: 'default',
		selection: { cause: 'default' },
		steps: [],
		answer_source: 'resolver',
		filter: null,
		dnssec: null,
		forward_zone: null,
		rcode: 'NOERROR',
		answer_size: 0,
		timings: { select_us: 1, filter_us: 0, resolve_us: 0, total_us: 1 },
		time: '2026-10-27T12:00:00.000000Z',
		...extra,
	};
}

function assertInert(container: HTMLElement): void {
	expect(container.querySelectorAll('script').length).toBe(0);
	expect(container.querySelector('img[src^="x"]')).toBeNull();
	expect(container.querySelector('[onerror]')).toBeNull();
}

beforeEach(() => {
	endSession();
	setPrincipal({ role: 'admin', actorId: 'admin', actorType: 'user', csrfToken: 'tok' });
	vi.stubGlobal('matchMedia', (query: string) => ({
		matches: query.includes('64rem'),
		addEventListener: () => undefined,
		removeEventListener: () => undefined,
	}));
});

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

describe('XSS corpus rendering', () => {
	it('renders hostile token names as inert text', async () => {
		const hostile = XSS_CORPUS[1];
		stubFetch({
			'GET /api/v1/auth/tokens': () =>
				ok({
					tokens: [
						{
							id: 't1',
							name: hostile,
							scope: 'viewer',
							actor_id: 'admin',
							created_at: '2026-10-27T12:00:00Z',
							expires_at: null,
						},
					],
				}),
			'GET /api/v1/status': () =>
				ok({
					version: '1',
					ready: true,
					modules_not_ready: [],
					tls_mode: 'acme',
					tls_fingerprint: '',
					tls: { identifiers: [] },
				}),
		});
		const { container } = render(TokensPanel, { props: { isAdmin: true } });
		await waitFor(() => expect(container.textContent).toContain('alert(1)'));
		assertInert(container);
	});

	it('renders hostile audit actor_id as inert text', async () => {
		const hostile = XSS_CORPUS[0];
		stubFetch({
			'GET /api/v1/audit': () =>
				ok({
					audit: [
						{
							id: 1,
							time: '2026-10-27T12:00:00Z',
							node_id: 'n1',
							actor_id: hostile,
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
		const { container } = render(AuditPanel, { props: { isAdmin: true } });
		await waitFor(() => expect(screen.getByText('config.replace')).toBeInTheDocument());
		expect(container.textContent).toContain('alert(1)');
		assertInert(container);
	});

	it('renders hostile query-log domains on list and detail', async () => {
		const domain = XSS_CORPUS[0];
		const reason = XSS_CORPUS[1];
		const row = hostileRecord('rec-xss', domain);
		const detailRow = hostileRecord('rec-xss', domain, {
			filter: {
				reason,
				block_mode: 'refused',
				rule_text: '||x^',
				list_id: 'x',
				important: false,
			},
		});
		stubFetch({
			'/api/v1/query-log': () => ok({ queries: [row], has_more: false, next_offset: null }),
			'/api/v1/stats/overview': () =>
				ok({
					source: 'raw',
					total: 1,
					allowed: 1,
					blocked: 0,
					allowed_ratio: 1,
					query_log_dropped: 0,
					by_answer_source: {},
				}),
			'/api/v1/query-log/rec-xss': () => ok(detailRow),
		});
		vi.stubGlobal('matchMedia', (query: string) => ({
			matches: query.includes('64rem'),
			addEventListener: () => undefined,
			removeEventListener: () => undefined,
		}));
		const list = render(QueryLogPage);
		expect(await screen.findByText(domain)).toBeInTheDocument();
		assertInert(list.container);
		cleanup();

		detailPage.params = { id: 'rec-xss' };
		const detail = render(QueryDetailPage);
		expect(await screen.findByText(domain)).toBeInTheDocument();
		expect(screen.getByText(reason)).toBeInTheDocument();
		assertInert(detail.container);
	});

	it('renders hostile client display names as inert text', async () => {
		const hostile = XSS_CORPUS[1];
		stubFetch({
			'GET /api/v1/clients': () =>
				ok({
					clients: [
						{
							id: 'c1',
							name: hostile,
							dns_label: 'c1',
							local_domain: '',
							source: 'unifi',
							ips: ['192.0.2.5'],
							macs: [],
							vlan: null,
							online: true,
							last_seen: null,
						},
					],
					manual: [],
				}),
		});
		const { container } = render(ClientsPage);
		expect(await screen.findByText(displayText(hostile).text)).toBeInTheDocument();
		assertInert(container);
	});

	it('renders hostile MCP rule domains as inert text', async () => {
		const hostile = XSS_CORPUS[1];
		stubFetch({
			'GET /api/v1/filter-sets': () =>
				ok({
					filter_sets: [
						{
							id: 'default',
							name: 'Standard',
							lists: [],
							custom_rules: `||${hostile}^`,
							services: [],
							block_mode: 'refused',
						},
					],
				}),
			'GET /api/v1/filtering/mcp-rules': () =>
				ok({
					filter_set_id: 'default',
					kind: 'rules',
					rules: [
						{
							id: 'r1',
							domain: hostile,
							include_subdomains: false,
							rule_text: `|${hostile}^`,
							created_at: '2026-10-27T10:00:00Z',
							expires_at: null,
						},
					],
					has_more: false,
					next_offset: null,
				}),
		});
		const { container } = render(RulesPage);
		expect(await screen.findByText(hostile)).toBeInTheDocument();
		assertInert(container);
	});
});
