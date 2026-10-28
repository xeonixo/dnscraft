// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { createRawSnippet } from 'svelte';
import { afterEach, describe, expect, it } from 'vitest';
import AppShell from './AppShell.svelte';

afterEach(() => cleanup());

const content = createRawSnippet(() => ({ render: () => '<p>Screen body</p>' }));

function setup() {
	render(AppShell, { props: { title: 'Dashboard', currentPath: '/dashboard', children: content } });
	// The menu button is display:none on wide widths; jsdom applies no media queries, so role queries
	// would exclude it. Its aria-label is the accessible name, so look it up by label.
	return screen.getByLabelText('Menu');
}

describe('AppShell drawer', () => {
	it('sets aria-expanded and aria-controls on the menu button when the drawer opens and closes', async () => {
		const user = userEvent.setup();
		const menu = setup();
		expect(menu).toHaveAttribute('aria-expanded', 'false');
		expect(menu).toHaveAttribute('aria-controls', 'sidebar-nav');

		await user.click(menu);
		expect(menu).toHaveAttribute('aria-expanded', 'true');
		expect(document.getElementById('sidebar-nav')).toHaveClass('open');

		await user.click(screen.getByRole('button', { name: 'Close menu' }));
		expect(menu).toHaveAttribute('aria-expanded', 'false');
		expect(document.getElementById('sidebar-nav')).not.toHaveClass('open');
	});

	it('closes on Escape and returns focus to the menu button', async () => {
		const user = userEvent.setup();
		const menu = setup();

		await user.click(menu);
		await user.keyboard('{Escape}');
		expect(menu).toHaveAttribute('aria-expanded', 'false');
		expect(menu).toHaveFocus();
	});

	it('renders the title in the toolbar heading and the screen body', () => {
		setup();
		expect(screen.getByRole('heading', { level: 1, name: 'Dashboard' })).toHaveAttribute(
			'tabindex',
			'-1',
		);
		expect(screen.getByText('Screen body')).toBeInTheDocument();
	});
});
