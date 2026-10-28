// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { createRawSnippet } from 'svelte';
import { afterEach, describe, expect, it, vi } from 'vitest';
import Sheet from './Sheet.svelte';

afterEach(() => {
	cleanup();
	document.body.innerHTML = '';
});

// Two focusable controls inside the sheet body; the sheet's own dialog is tabindex -1.
const body = createRawSnippet(() => ({
	render: () =>
		'<div><button type="button">First</button><button type="button">Second</button></div>',
}));

function setup(open: boolean) {
	const trigger = document.createElement('button');
	trigger.type = 'button';
	document.body.append(trigger);
	trigger.focus();

	const onclose = vi.fn();
	const view = render(Sheet, { props: { open, title: 'Confirm', onclose, children: body } });
	return { trigger, onclose, ...view };
}

describe('Sheet', () => {
	it('is a modal dialog named by its title', async () => {
		const { rerender } = setup(false);
		expect(screen.queryByRole('dialog')).toBeNull();

		await rerender({ open: true });
		const dialog = screen.getByRole('dialog', { name: 'Confirm' });
		expect(dialog).toHaveAttribute('aria-modal', 'true');
	});

	it('moves focus into the dialog and traps Tab and Shift+Tab inside it', async () => {
		const user = userEvent.setup();
		const { rerender } = setup(false);
		await rerender({ open: true });

		await waitFor(() => expect(screen.getByRole('button', { name: 'First' })).toHaveFocus());

		await user.tab();
		expect(screen.getByRole('button', { name: 'Second' })).toHaveFocus();
		await user.tab();
		expect(screen.getByRole('button', { name: 'First' })).toHaveFocus();

		await user.tab({ shift: true });
		expect(screen.getByRole('button', { name: 'Second' })).toHaveFocus();
	});

	it('calls onclose on Escape', async () => {
		const user = userEvent.setup();
		const { rerender, onclose } = setup(false);
		await rerender({ open: true });
		await waitFor(() => expect(screen.getByRole('button', { name: 'First' })).toHaveFocus());

		await user.keyboard('{Escape}');
		expect(onclose).toHaveBeenCalledTimes(1);
	});

	it('closes through the scrim', async () => {
		const user = userEvent.setup();
		const { rerender, onclose } = setup(false);
		await rerender({ open: true });

		await user.click(screen.getByRole('button', { name: 'Cancel' }));
		expect(onclose).toHaveBeenCalledTimes(1);
	});

	it('returns focus to the trigger when closed', async () => {
		const { rerender, trigger } = setup(false);
		await rerender({ open: true });
		await waitFor(() => expect(screen.getByRole('button', { name: 'First' })).toHaveFocus());

		await rerender({ open: false });
		expect(screen.queryByRole('dialog')).toBeNull();
		expect(trigger).toHaveFocus();
	});
});
