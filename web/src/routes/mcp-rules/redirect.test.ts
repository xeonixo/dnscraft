import { describe, expect, it } from 'vitest';
import { load } from './+page';

describe('/mcp-rules', () => {
	it('redirects old links to /rules', () => {
		let thrown: unknown;
		try {
			load();
		} catch (cause) {
			thrown = cause;
		}
		expect(thrown).toMatchObject({ status: 307, location: '/rules' });
	});
});
