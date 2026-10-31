import { describe, expect, it } from 'vitest';
import { parseTestQueryRecords } from './policy';

describe('parseTestQueryRecords', () => {
	it('reads control-api records with qtype/data', () => {
		expect(
			parseTestQueryRecords([
				{ name: 'elmo.barner.cloud.', qtype: 'A', ttl: 60, data: '172.20.10.10' },
			]),
		).toEqual([{ name: 'elmo.barner.cloud.', type: 'A', ttl: 60, data: '172.20.10.10' }]);
	});

	it('reads MCP-shaped records with type/data and rdata aliases', () => {
		expect(
			parseTestQueryRecords([
				{ name: 'a.example.', type: 'AAAA', ttl: 30, data: '2001:db8::1' },
				{ name: 'b.example.', type: 'A', ttl: 10, rdata: '192.0.2.1' },
			]),
		).toEqual([
			{ name: 'a.example.', type: 'AAAA', ttl: 30, data: '2001:db8::1' },
			{ name: 'b.example.', type: 'A', ttl: 10, data: '192.0.2.1' },
		]);
	});

	it('skips empty junk', () => {
		expect(parseTestQueryRecords([null, {}, 'x'])).toEqual([]);
	});
});
