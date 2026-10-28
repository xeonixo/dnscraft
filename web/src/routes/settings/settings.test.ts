// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen, within } from '@testing-library/svelte';
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

beforeEach(() => {
	setPrincipal({ role: 'admin', actorId: 'admin', actorType: 'user', csrfToken: 'tok' });
	vi.stubGlobal(
		'fetch',
		vi.fn(async (input: RequestInfo | URL) => {
			const href =
				typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			const url = new URL(href, 'http://localhost');
			if (url.pathname === '/api/v1/config') {
				return ok({
					version: 1,
					config: {
						filtering: { sets: [], lists: [] },
						clients: { manual: [] },
						policy: { profiles: [], views: [], records: [], client_ids: [] },
						listeners: { listeners: [] },
						tls: {},
						control_api_settings: { query_log: { retention_days: 30 } },
					},
				});
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
			if (url.pathname === '/api/v1/auth/tokens') return ok({ tokens: [] });
			if (url.pathname === '/api/v1/audit') return ok({ audit: [] });
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
});
