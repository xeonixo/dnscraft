import { describe, expect, it } from 'vitest';
import { nodesFromWire } from './listeners';

describe('nodesFromWire', () => {
	it('treats missing nodes as every node', () => {
		expect(nodesFromWire(undefined)).toEqual([]);
		expect(nodesFromWire(null)).toEqual([]);
	});

	it('dedupes and trims node ids', () => {
		expect(nodesFromWire([' garage ', 'garage', 'office', ''])).toEqual(['garage', 'office']);
	});
});
