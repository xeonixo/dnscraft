import { describe, expect, it } from 'vitest';
import { cnameChainOf, exportHref } from './query-log';

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

describe('cnameChainOf', () => {
	it('reads hops in chain order with their rule and list', () => {
		const chain = cnameChainOf({
			stage: 'cname_chain',
			verdict: 'resolved',
			hops: [
				{
					name: 'a.example',
					verdict: 'pass',
					rule_text: null,
					list_id: null,
					source: null,
					important: false,
				},
				{
					name: 'b.example',
					verdict: 'blocked',
					rule_text: '||b.example^',
					list_id: 'l1',
					source: 'list',
					important: true,
				},
			],
			addresses: ['1.2.3.4'],
		});
		expect(chain.hops).toEqual([
			{
				name: 'a.example',
				verdict: 'pass',
				rule_text: null,
				list_id: null,
				source: null,
				important: false,
			},
			{
				name: 'b.example',
				verdict: 'blocked',
				rule_text: '||b.example^',
				list_id: 'l1',
				source: 'list',
				important: true,
			},
		]);
		expect(chain.addresses).toEqual(['1.2.3.4']);
	});

	it('drops malformed hops and non-string addresses', () => {
		const chain = cnameChainOf({
			stage: 'cname_chain',
			verdict: 'resolved',
			hops: [
				null,
				'x',
				{ verdict: 'pass' },
				{ name: 'c.example' },
				{
					name: 'd.example',
					verdict: 'allowed',
					rule_text: 7,
					list_id: {},
					source: 3,
					important: 'yes',
				},
			],
			addresses: ['9.9.9.9', 4, null],
		});
		expect(chain.hops).toEqual([
			{
				name: 'd.example',
				verdict: 'allowed',
				rule_text: null,
				list_id: null,
				source: null,
				important: false,
			},
		]);
		expect(chain.addresses).toEqual(['9.9.9.9']);
	});

	it('reads missing or non-array fields as empty', () => {
		expect(cnameChainOf({ stage: 'cname_chain', verdict: 'resolved' })).toEqual({
			hops: [],
			addresses: [],
		});
		expect(
			cnameChainOf({ stage: 'cname_chain', verdict: 'resolved', hops: 'no', addresses: 'no' }),
		).toEqual({
			hops: [],
			addresses: [],
		});
	});
});
