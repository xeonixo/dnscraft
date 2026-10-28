import { describe, expect, it } from 'vitest';
import { findingLabel, mcpRuleChanges, parseConfigText } from './view';

const rule = { id: 'r1', domain: 'example.com', include_subdomains: true };

describe('parseConfigText', () => {
	it('accepts a JSON object', () => {
		expect(parseConfigText('{"filtering": {}}')).toEqual({ ok: true, value: { filtering: {} } });
	});

	it('locates a syntax error by line and column when the engine reports a position', () => {
		// Position 5 is the "1" after the property name: line 1, column 6.
		expect(parseConfigText('{"a" 1}')).toEqual({
			ok: false,
			reason: 'syntax',
			line: 1,
			column: 6,
		});
		expect(parseConfigText('{\n  "a" 1\n}')).toMatchObject({ ok: false, line: 2, column: 7 });
	});

	it('leaves the location empty when the engine reports none', () => {
		const result = parseConfigText('{\n  "filtering": ,\n}');
		expect(result).toEqual({ ok: false, reason: 'syntax', line: null, column: null });
	});

	it('rejects valid JSON that is not an object', () => {
		expect(parseConfigText('[1, 2]')).toEqual({
			ok: false,
			reason: 'not_object',
			line: null,
			column: null,
		});
		expect(parseConfigText('null')).toMatchObject({ ok: false, reason: 'not_object' });
	});

	it('reports empty text as a syntax error without a position', () => {
		expect(parseConfigText('')).toEqual({ ok: false, reason: 'syntax', line: null, column: null });
	});
});

describe('mcpRuleChanges', () => {
	const stored = {
		filtering: {
			sets: [
				{ id: 'default', mcp_rules: [rule, { ...rule, id: 'r2' }] },
				{ id: 'kids', mcp_rules: [] },
			],
		},
	};

	it('reports an omitted field as carried over when the stored set has rules', () => {
		const candidate = { filtering: { sets: [{ id: 'default' }, { id: 'kids' }] } };
		expect(mcpRuleChanges(stored, candidate)).toEqual([
			{ set: 'default', kind: 'carried', count: 2 },
		]);
	});

	it('reports an explicit empty array as deleted only when rules existed', () => {
		const candidate = {
			filtering: {
				sets: [
					{ id: 'default', mcp_rules: [] },
					{ id: 'kids', mcp_rules: [] },
				],
			},
		};
		expect(mcpRuleChanges(stored, candidate)).toEqual([
			{ set: 'default', kind: 'deleted', count: 2 },
		]);
	});

	it('reports a changed non-empty list as replaced and an identical one as no change', () => {
		const replaced = { filtering: { sets: [{ id: 'default', mcp_rules: [rule] }] } };
		expect(mcpRuleChanges(stored, replaced)).toEqual([
			{ set: 'default', kind: 'replaced', count: 1 },
		]);
		const identical = {
			filtering: { sets: [{ id: 'default', mcp_rules: stored.filtering.sets[0].mcp_rules }] },
		};
		expect(mcpRuleChanges(stored, identical)).toEqual([]);
	});

	it('tolerates a missing or malformed snapshot', () => {
		expect(mcpRuleChanges(null, { filtering: { sets: [{ id: 'x' }] } })).toEqual([]);
		expect(mcpRuleChanges(stored, { filtering: 'nope' })).toEqual([]);
	});
});

describe('findingLabel', () => {
	it('translates a known code and falls back to the raw code otherwise', () => {
		expect(findingLabel({ code: 'control_api.config.version', path: null, params: null })).not.toBe(
			'control_api.config.version',
		);
		expect(
			findingLabel({ code: 'policy.config.unknown_filter_set', path: null, params: null }),
		).toBe('policy.config.unknown_filter_set');
	});
});
