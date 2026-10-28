// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { createRawSnippet } from 'svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { setPrincipal } from '$lib/auth/state.svelte';
import Layout from './+layout.svelte';
import GeneralPage from './+page.svelte';
import { m } from '$lib/paraglide/messages';

const pageState = vi.hoisted(() => ({ url: new URL('http://localhost/settings') }));
vi.mock('$app/state', () => ({ page: pageState }));

const ok = (data: unknown) =>
	new Response(JSON.stringify({ data }), {
		status: 200,
		headers: { 'Content-Type': 'application/json' },
	});

const configBody = {
	version: 1,
	config: {
		filtering: { sets: [], lists: [] },
		clients: {
			local_domain: 'home.arpa',
			local_domain_mode: 'unifi_then_config',
			unifi_profiles: [
				{
					id: 'home',
					sync_owner: 'local',
					enabled: true,
					base_url: 'https://192.0.2.1',
					site_id: null,
					poll_interval: '60s',
					classic_clients: true,
					tls_pin_sha256: `sha256:${'ab'.repeat(32)}`,
					ca_file: null,
					insecure_skip_verify: false,
				},
			],
			unifi_bindings: { local: 'home' },
			manual: [],
		},
		policy: { profiles: [], views: [], records: [], client_ids: [] },
		listeners: { listeners: [] },
		tls: {},
		control_api_settings: { query_log: { retention_days: 30, ip_truncate: 'none' } },
	},
};

/** The stored query_log section the mocked GET returns; tests set it before rendering. */
let storedQueryLog: Record<string, unknown> = { retention_days: 30, ip_truncate: 'none' };

beforeEach(() => {
	storedQueryLog = { retention_days: 30, ip_truncate: 'none' };
	setPrincipal({ role: 'admin', actorId: 'admin', actorType: 'user', csrfToken: 'tok' });
	vi.stubGlobal(
		'fetch',
		vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const href =
				typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			const url = new URL(href, 'http://localhost');
			if (url.pathname === '/api/v1/config' && (!init?.method || init.method === 'GET')) {
				return ok({
					...configBody,
					config: {
						...configBody.config,
						control_api_settings: { query_log: storedQueryLog },
					},
				});
			}
			if (url.pathname === '/api/v1/config' && init?.method === 'PUT') {
				return ok({ version: 2 });
			}
			if (url.pathname === '/api/v1/update/check') {
				return ok({
					enabled: false,
					current: '1',
					latest: null,
					update_available: false,
					release_url: null,
					checked_at: null,
				});
			}
			if (url.pathname === '/api/v1/status') {
				return ok({ version: '1', ready: true, modules_not_ready: [] });
			}
			if (url.pathname === '/api/v1/clients/unifi') {
				return ok({
					profiles: configBody.config.clients.unifi_profiles.map((profile) => ({
						...profile,
						has_api_key: false,
					})),
					bindings: configBody.config.clients.unifi_bindings,
				});
			}
			if (url.pathname === '/api/v1/cluster/nodes') {
				return ok([]);
			}
			if (url.pathname === '/api/v1/auth/tokens') return ok({ tokens: [] });
			if (url.pathname === '/api/v1/audit') return ok({ audit: [] });
			if (url.pathname === '/api/v1/clients/sync') {
				return ok({ generation: 1, rebuilt: true, client_count: 12, ip_conflicts: 0 });
			}
			return ok({});
		}),
	);
});

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

function renderAt(path: string) {
	pageState.url = new URL(`http://localhost${path}`);
	const content = createRawSnippet(() => ({ render: () => '<p data-testid="content">Screen</p>' }));
	return render(Layout, { props: { children: content } });
}

describe('Einstellungen tab bar', () => {
	const tabs = [
		['/settings', () => m.settings_tab_general()],
		['/settings/config', () => m.settings_tab_configuration()],
		['/settings/mcp', () => m.settings_tab_mcp()],
		['/settings/api', () => m.settings_tab_api_explorer()],
	] as const;

	it('renders one tab bar with the four tabs as links', () => {
		renderAt('/settings');
		const bar = screen.getByRole('navigation', { name: m.settings_tabs_label() });
		const links = within(bar).getAllByRole('link');
		expect(links.map((link) => link.getAttribute('href'))).toEqual(tabs.map(([path]) => path));
		expect(links.map((link) => link.textContent)).toEqual(tabs.map(([, label]) => label()));
	});

	it.each(tabs)('marks only %s as the current tab', (path) => {
		renderAt(path);
		const current = screen.getAllByRole('link').filter((link) => link.hasAttribute('aria-current'));
		expect(current).toHaveLength(1);
		expect(current[0]).toHaveAttribute('href', path);
		expect(current[0]).toHaveAttribute('aria-current', 'page');
	});

	it('shows the screen content below the bar on every tab', () => {
		renderAt('/settings/config');
		expect(screen.getByTestId('content')).toBeInTheDocument();
	});
});

describe('Einstellungen general tab', () => {
	it('keeps the theme and language controls', () => {
		render(GeneralPage);
		expect(screen.getByRole('radiogroup', { name: m.theme_group_label() })).toBeInTheDocument();
	});

	it('loads UniFi settings and saves a clients patch with If-Match', async () => {
		const user = userEvent.setup();
		render(GeneralPage);

		const gateway = await screen.findByLabelText(m.settings_unifi_gateway());
		expect(gateway).toHaveValue('https://192.0.2.1');
		expect(screen.getByLabelText(m.settings_unifi_enabled())).toBeChecked();

		await user.clear(gateway);
		await user.type(gateway, 'https://192.0.2.99');
		const unifi = screen
			.getByRole('heading', { name: m.settings_group_unifi() })
			.closest('section');
		expect(unifi).not.toBeNull();
		await user.click(within(unifi as HTMLElement).getByRole('button', { name: m.action_save() }));

		await waitFor(() => {
			const puts = vi.mocked(fetch).mock.calls.filter(([input, init]) => {
				const href =
					typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
				return href.includes('/api/v1/config') && init?.method === 'PUT';
			});
			expect(puts).toHaveLength(1);
			const [, init] = puts[0]!;
			const body = JSON.parse(String(init?.body));
			expect(body.clients.unifi_profiles[0].base_url).toBe('https://192.0.2.99');
			expect(body.clients.unifi_bindings).toEqual({ local: 'home' });
			expect((init?.headers as Record<string, string>)['If-Match']).toBe('1');
		});
	});

	it('shows the stored IP truncation mode', async () => {
		storedQueryLog = { retention_days: 30, ip_truncate: 'last_group' };
		render(GeneralPage);
		const select = screen.getByLabelText(m.settings_ip_truncation_label());
		await waitFor(() => expect(select).toHaveValue('last_group'));
	});

	it('saves the IP truncation mode and keeps the retention days', async () => {
		const user = userEvent.setup();
		render(GeneralPage);
		await screen.findByDisplayValue('30');
		const select = screen.getByLabelText(m.settings_ip_truncation_label());
		await user.selectOptions(select, 'last_octet');
		const row = select.closest('.ip-control') as HTMLElement;
		await user.click(within(row).getByRole('button', { name: m.action_save() }));

		await waitFor(() => {
			const puts = vi.mocked(fetch).mock.calls.filter(([, init]) => init?.method === 'PUT');
			expect(puts).toHaveLength(1);
			const [, init] = puts[0]!;
			const body = JSON.parse(String(init?.body));
			expect(body.control_api_settings.query_log).toEqual({
				retention_days: 30,
				ip_truncate: 'last_octet',
			});
			expect((init?.headers as Record<string, string>)['If-Match']).toBe('1');
		});
	});

	it('keeps the IP truncation mode when the retention days are saved', async () => {
		storedQueryLog = { retention_days: 30, ip_truncate: 'last_group' };
		const user = userEvent.setup();
		render(GeneralPage);
		const retention = await screen.findByDisplayValue('30');
		await user.clear(retention);
		await user.type(retention, '14');
		const row = retention.closest('.row') as HTMLElement;
		await user.click(within(row).getByRole('button', { name: m.action_save() }));

		await waitFor(() => {
			const put = vi.mocked(fetch).mock.calls.find(([, init]) => init?.method === 'PUT');
			expect(put).toBeDefined();
			const body = JSON.parse(String(put![1]?.body));
			expect(body.control_api_settings.query_log).toEqual({
				retention_days: 14,
				ip_truncate: 'last_group',
			});
		});
	});

	it('disables the IP truncation control for non-admins', async () => {
		setPrincipal({ role: 'viewer', actorId: 'viewer', actorType: 'user', csrfToken: 'tok' });
		storedQueryLog = { retention_days: 30, ip_truncate: 'last_octet' };
		render(GeneralPage);
		const select = screen.getByLabelText(m.settings_ip_truncation_label());
		await waitFor(() => expect(select).toHaveValue('last_octet'));
		expect(select).toBeDisabled();
		const row = select.closest('.ip-control') as HTMLElement;
		expect(within(row).queryByRole('button', { name: m.action_save() })).toBeNull();
	});

	it('asks before enabling UniFi skip-verify', async () => {
		const user = userEvent.setup();
		render(GeneralPage);
		await screen.findByLabelText(m.settings_unifi_gateway());

		await user.click(screen.getByRole('radio', { name: m.settings_unifi_tls_insecure() }));
		const dialog = screen.getByRole('dialog', {
			name: m.settings_unifi_insecure_confirm_title(),
		});
		await user.click(within(dialog).getByRole('button', { name: m.action_cancel() }));
		expect(screen.queryByRole('dialog')).toBeNull();
		expect(screen.getByRole('radio', { name: m.settings_unifi_tls_pin() })).toHaveAttribute(
			'aria-checked',
			'true',
		);
	});
});
