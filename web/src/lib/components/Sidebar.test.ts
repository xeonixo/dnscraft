// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen } from '@testing-library/svelte';
import { afterEach, describe, expect, it } from 'vitest';
import Sidebar from './Sidebar.svelte';
import { navSections, type NavSection } from '$lib/nav';

afterEach(() => cleanup());

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

	it('is closed on compact widths unless the drawer is open', async () => {
		const { container, rerender } = render(Sidebar, { props: { currentPath: '/dashboard' } });
		const aside = container.querySelector('aside');
		expect(aside).not.toHaveClass('open');

		await rerender({ open: true });
		expect(aside).toHaveClass('open');
	});
});
