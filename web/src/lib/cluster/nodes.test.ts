import { describe, expect, it } from 'vitest';
import { nodeLag } from './nodes';

describe('nodeLag', () => {
	it('measures each node against the newest applied version of the non-revoked nodes', () => {
		expect(
			nodeLag([
				{ applied_config_version: 5, revoked: false },
				{ applied_config_version: 3, revoked: false },
				{ applied_config_version: 9, revoked: true },
			]),
		).toEqual([0, 2, 0]);
	});

	it('counts a node without a reported version as fully behind', () => {
		expect(
			nodeLag([
				{ applied_config_version: 5, revoked: false },
				{ applied_config_version: null, revoked: false },
			]),
		).toEqual([0, 5]);
	});
});
