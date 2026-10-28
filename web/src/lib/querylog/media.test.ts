import { afterEach, describe, expect, it, vi } from 'vitest';
import { WIDE_QUERY, mediaMatches } from './media';

afterEach(() => {
	vi.unstubAllGlobals();
});

describe('mediaMatches', () => {
	it('is false without matchMedia', () => {
		expect(mediaMatches(WIDE_QUERY)).toBe(false);
	});

	it('reports the engine answer for the query', () => {
		vi.stubGlobal('matchMedia', (query: string) => ({ matches: query === WIDE_QUERY }));
		expect(mediaMatches(WIDE_QUERY)).toBe(true);
		expect(mediaMatches('(min-width: 1px)')).toBe(false);
	});
});
