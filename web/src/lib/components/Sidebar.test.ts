// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen } from '@testing-library/svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import Sidebar from './Sidebar.svelte';
import { navSections, type NavSection } from '$lib/nav';
import { m } from '$lib/paraglide/messages';

const json = (body: unknown): Response =>
	new Response(JSON.stringify(body), {
		status: 200,
		headers: { 'Content-Type': 'application/json' },
	});

function mockStatus(data: Record<string, unknown>): void {
	vi.stubGlobal(
		'fetch',
		vi.fn(async (input: RequestInfo | URL) => {
			const url = String(input);
			if (url.includes('/api/v1/status')) return json({ data });
			return new Response(JSON.stringify({ error: { code: 'control_api.not_found' } }), {
				status: 404,
			});
		}),
	);
}

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

beforeEach(() => {
	mockStatus({ version: '1.0.0', ready: true, modules_not_ready: [] });
});

const adminSections: NavSection[] = [
	{
		heading: () => 'Test',
		items: [
			{ path: '/zones', label: () => 'Open item', icon: 'target', minRole: 'viewer' },
			{ path: '/tls', label: () => 'Admin item', icon: 'lock', minRole: 'admin' },
		],
	},
];

describe('Sidebar', () => {
	it('marks only the current route with aria-current', () => {
		const { container } = render(Sidebar, { props: { currentPath: '/dashboard' } });
		const current = container.querySelectorAll('[aria-current="page"]');
		expect(current).toHaveLength(1);
		expect(current[0]).toHaveAttribute('href', '/dashboard');
	});

	it('keeps the Einstellungen item active on every tab of the screen group', () => {
		const { container } = render(Sidebar, { props: { currentPath: '/settings/config' } });
		expect(container.querySelector('.nav-settings a')).toHaveAttribute('aria-current', 'page');
		expect(container.querySelectorAll('[aria-current="page"]')).toHaveLength(1);
	});

	it('renders the Einstellungen item and the Hilfe link outside the sections', () => {
		const { container } = render(Sidebar, { props: { currentPath: '/settings' } });
		expect(container.querySelector('.nav-settings a')).toHaveAttribute('href', '/settings');
		expect(container.querySelector('.nav-settings a')).toHaveAttribute('aria-current', 'page');
		expect(container.querySelector('.sidebar-foot a')).toHaveAttribute('href', '/feedback');
	});

	it('shows every section item to a viewer', () => {
		const { container } = render(Sidebar, { props: { currentPath: '/dashboard' } });
		const links = container.querySelectorAll('nav a.nav-item');
		const expected = navSections.reduce((count, section) => count + section.items.length, 0);
		// The sections plus the Einstellungen item.
		expect(links).toHaveLength(expected + 1);
	});

	it('hides admin-only items from a viewer and shows them to an admin', () => {
		const viewer = render(Sidebar, {
			props: { currentPath: '/zones', sections: adminSections, role: 'viewer', open: true },
		});
		expect(screen.getByRole('link', { name: 'Open item' })).toBeInTheDocument();
		expect(screen.queryByRole('link', { name: 'Admin item' })).toBeNull();
		viewer.unmount();

		render(Sidebar, {
			props: { currentPath: '/zones', sections: adminSections, role: 'admin', open: true },
		});
		expect(screen.getByRole('link', { name: 'Admin item' })).toBeInTheDocument();
	});

	it('shows standalone in the footer when status has no cluster', async () => {
		render(Sidebar, { props: { currentPath: '/dashboard' } });
		expect(await screen.findByText(m.sidebar_node_standalone())).toBeInTheDocument();
	});

	it('shows the cluster role in the footer when status includes cluster', async () => {
		mockStatus({
			version: '1.0.0',
			ready: true,
			modules_not_ready: [],
			cluster: {
				role: 'sub_node',
				master_reachable: true,
				applied_version: 2,
				lag: 3,
				queue_depth: 0,
				last_sync: null,
				degraded_nodes: 0,
			},
		});
		render(Sidebar, { props: { currentPath: '/dashboard' } });
		expect(await screen.findByText(new RegExp(m.sidebar_node_sub()))).toBeInTheDocument();
		expect(screen.getByText(new RegExp(m.sidebar_node_lag({ lag: '3' })))).toBeInTheDocument();
	});

	it('is closed on compact widths unless the drawer is open', async () => {
		const { container, rerender } = render(Sidebar, { props: { currentPath: '/dashboard' } });
		const aside = container.querySelector('aside');
		expect(aside).not.toHaveClass('open');

		await rerender({ open: true });
		expect(aside).toHaveClass('open');
	});
});
