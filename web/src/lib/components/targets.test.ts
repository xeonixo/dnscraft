import { describe, expect, it } from 'vitest';
import buttonSource from './Button.svelte?raw';
import segmentedSource from './Segmented.svelte?raw';
import sidebarSource from './Sidebar.svelte?raw';
import switchSource from './Switch.svelte?raw';
import toolbarSource from './Toolbar.svelte?raw';

// jsdom has no layout, so the 44pt (2.75rem) target rule is checked against the component
// styles: every interactive control class must declare the minimum size.

const MIN_TARGET = /min-height:\s*2\.75rem/;
const MIN_WIDTH = /min-width:\s*2\.75rem/;

function styleOf(source: string): string {
	const start = source.indexOf('<style>');
	return start === -1 ? '' : source.slice(start);
}

describe('touch targets (SPEC: 44pt minimum)', () => {
	it.each([
		['Button', buttonSource],
		['Switch', switchSource],
		['Segmented', segmentedSource],
		['Sidebar links', sidebarSource],
		['Toolbar buttons', toolbarSource],
	])('%s declare a 2.75rem minimum height', (_name, source) => {
		expect(styleOf(source)).toMatch(MIN_TARGET);
	});

	it.each([
		['Button', buttonSource],
		['Switch', switchSource],
		['Segmented', segmentedSource],
		['Toolbar buttons', toolbarSource],
	])('%s declare a 2.75rem minimum width', (_name, source) => {
		expect(styleOf(source)).toMatch(MIN_WIDTH);
	});
});
