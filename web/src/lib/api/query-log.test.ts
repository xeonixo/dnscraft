import { describe, expect, it } from 'vitest';
import { exportHref } from './query-log';

describe('exportHref', () => {
	it('carries the current filters and drops paging', () => {
		const query = new URLSearchParams('domain_substr=ads&limit=25&offset=50&protocol=doh');
		expect(exportHref('csv', query)).toBe(
			'/api/v1/query-log/export.csv?domain_substr=ads&protocol=doh',
		);
	});

	it('is a bare same-origin path without filters', () => {
		expect(exportHref('ndjson', new URLSearchParams())).toBe('/api/v1/query-log/export.ndjson');
	});
});
