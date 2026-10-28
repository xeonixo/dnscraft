// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import Segmented from './Segmented.svelte';

afterEach(() => cleanup());

const options = [
	{ value: 'a', label: 'Alpha' },
	{ value: 'b', label: 'Beta' },
	{ value: 'c', label: 'Gamma' },
];

describe('Segmented', () => {
	it('exposes a radio group with aria-checked on the selected segment only', () => {
		render(Segmented, { props: { options, value: 'b', label: 'Period' } });
		expect(screen.getByRole('radiogroup', { name: 'Period' })).toBeInTheDocument();
		expect(screen.getByRole('radio', { name: 'Beta' })).toHaveAttribute('aria-checked', 'true');
		expect(screen.getByRole('radio', { name: 'Alpha' })).toHaveAttribute('aria-checked', 'false');
		expect(screen.getByRole('radio', { name: 'Gamma' })).toHaveAttribute('aria-checked', 'false');
	});

	it('moves and selects with the arrow keys, wrapping at both ends', async () => {
		const user = userEvent.setup();
		const onchange = vi.fn();
		render(Segmented, { props: { options, value: 'a', label: 'Period', onchange } });

		await user.tab();
		expect(screen.getByRole('radio', { name: 'Alpha' })).toHaveFocus();

		await user.keyboard('{ArrowRight}');
		expect(screen.getByRole('radio', { name: 'Beta' })).toHaveFocus();
		expect(screen.getByRole('radio', { name: 'Beta' })).toHaveAttribute('aria-checked', 'true');
		expect(onchange).toHaveBeenLastCalledWith('b');

		await user.keyboard('{ArrowLeft}{ArrowLeft}');
		expect(screen.getByRole('radio', { name: 'Gamma' })).toHaveFocus();
		expect(screen.getByRole('radio', { name: 'Gamma' })).toHaveAttribute('aria-checked', 'true');
		expect(screen.getByRole('radio', { name: 'Beta' })).toHaveAttribute('aria-checked', 'false');
		expect(onchange).toHaveBeenLastCalledWith('c');
	});
});
