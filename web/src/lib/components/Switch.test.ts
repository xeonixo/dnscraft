// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it } from 'vitest';
import Switch from './Switch.svelte';

afterEach(() => cleanup());

describe('Switch', () => {
	it('exposes a named switch whose checked state follows the native checkbox', () => {
		render(Switch, { props: { checked: true, 'aria-label': 'Logging' } });
		const control = screen.getByRole('switch', { name: 'Logging' });
		expect(control).toBeChecked();
	});

	it('toggles with Space once focused', async () => {
		const user = userEvent.setup();
		render(Switch, { props: { checked: false, 'aria-label': 'Logging' } });
		const control = screen.getByRole('switch', { name: 'Logging' });
		expect(control).not.toBeChecked();

		await user.tab();
		expect(control).toHaveFocus();
		await user.keyboard(' ');
		expect(control).toBeChecked();

		await user.keyboard(' ');
		expect(control).not.toBeChecked();
	});
});
