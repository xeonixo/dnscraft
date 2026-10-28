// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen } from '@testing-library/svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import McpPage from './+page.svelte';
import ApiPage from '../api/+page.svelte';
import { setPrincipal } from '$lib/auth/state.svelte';
import { m } from '$lib/paraglide/messages';

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
			const path = new URL(href, 'http://localhost').pathname;
			if (path === '/api/v1/auth/me') {
				return ok({ role: 'admin', actor_id: 'admin', actor_type: 'user', csrf_token: 'tok' });
			}
			if (path === '/api/v1/config') {
				return ok({
					version: 1,
					config: {
						filtering: { sets: [], lists: [] },
						clients: { manual: [] },
						policy: { profiles: [], views: [], records: [], client_ids: [] },
						listeners: { listeners: [] },
						tls: {},
						mcp: { enabled: false, write_tools_enabled: false },
					},
				});
			}
			return new Response(JSON.stringify({ error: { code: 'control_api.not_found' } }), {
				status: 404,
			});
		}),
	);
});

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

describe('Einstellungen MCP and API tabs', () => {
	it('shows MCP toggles when config includes mcp', async () => {
		render(McpPage);
		expect(await screen.findByText(m.settings_mcp_enabled())).toBeInTheDocument();
	});

	it('shows the API explorer catalog', async () => {
		render(ApiPage);
		expect(await screen.findByText(m.api_explorer_catalog())).toBeInTheDocument();
	});
});
