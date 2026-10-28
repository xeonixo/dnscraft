// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen } from '@testing-library/svelte';
import { afterEach, describe, expect, it, vi } from 'vitest';
import McpPage from './+page.svelte';
import ApiPage from '../api/+page.svelte';
import { m } from '$lib/paraglide/messages';

const pageState = vi.hoisted(() => ({ url: new URL('http://localhost/settings/mcp') }));
vi.mock('$app/state', () => ({ page: pageState }));

afterEach(() => cleanup());

describe('Einstellungen placeholder tabs', () => {
	it.each([
		['MCP', McpPage],
		['API-Explorer', ApiPage],
	])('shows the coming-soon state on the %s tab', (_name, component) => {
		render(component);
		expect(screen.getByText(m.state_coming_soon())).toBeInTheDocument();
	});
});
