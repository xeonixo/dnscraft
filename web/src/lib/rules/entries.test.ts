import { describe, expect, it } from 'vitest';
import type { FilterSet } from '$lib/api/filtering';
import type { McpRuleRow } from '$lib/api/mcp-rules';
import { buildRuleEntries, filterEntries, isLive, minutesLeft, type RuleEntry } from './entries';

function set(id: string, name: string, custom_rules: string): FilterSet {
	return {
		id,
		name,
		lists: [],
		custom_rules,
		services: [],
		block_mode: 'refused',
	};
}

const mcp = (overrides: Partial<McpRuleRow> & { domain: string }): McpRuleRow => ({
	id: `id-${overrides.domain}`,
	include_subdomains: true,
	created_at: '2026-10-26T08:00:00Z',
	expires_at: null,
	...overrides,
});

const SETS = [
	set(
		'default',
		'Standard',
		'! Kopf\n||ads.example^\n@@|kids.example^\n||ads.example.net^$important',
	),
	set('kids', 'Kinder', '@@||de.wikipedia.org^'),
];

describe('buildRuleEntries', () => {
	it('merges every set’s rule lines and MCP rules, skipping comments', () => {
		const entries = buildRuleEntries(
			SETS,
			new Map([['default', [mcp({ domain: 'example.com' })]]]),
		);
		expect(entries.map((entry) => `${entry.source}:${entry.setId}:${entry.domain}`)).toEqual([
			'text:default:||ads.example.net^$important',
			'text:default:ads.example',
			'text:kids:de.wikipedia.org',
			'mcp:default:example.com',
			'text:default:kids.example',
		]);
	});

	it('reads plain rules as domain rules with their action and scope', () => {
		const entries = buildRuleEntries(SETS, new Map());
		const byDomain = (domain: string): RuleEntry | undefined =>
			entries.find((entry) => entry.domain === domain);
		expect(byDomain('ads.example')).toMatchObject({
			action: 'block',
			advanced: false,
			includeSubdomains: true,
			lineIndex: 1,
			ruleText: '||ads.example^',
		});
		expect(byDomain('kids.example')).toMatchObject({
			action: 'allow',
			includeSubdomains: false,
		});
	});

	it('keeps an advanced line as written, with the action of its prefix', () => {
		const advanced = buildRuleEntries(SETS, new Map()).find(
			(entry) => entry.ruleText === '||ads.example.net^$important',
		);
		expect(advanced).toMatchObject({
			advanced: true,
			action: 'block',
			domain: '||ads.example.net^$important',
			includeSubdomains: null,
		});
	});

	it('takes MCP rules as block rules with their expiry and the set name', () => {
		const [entry] = buildRuleEntries(
			SETS,
			new Map([
				[
					'kids',
					[
						mcp({
							domain: 'tv.example',
							include_subdomains: false,
							expires_at: '2026-11-26T09:30:00Z',
						}),
					],
				],
			]),
		).filter((item) => item.source === 'mcp');
		expect(entry).toMatchObject({
			action: 'block',
			domain: 'tv.example',
			includeSubdomains: false,
			setName: 'Kinder',
			expiresAt: '2026-11-26T09:30:00Z',
			ruleText: '|tv.example^',
		});
	});

	it('sorts alphabetically by domain', () => {
		const domains = buildRuleEntries(
			SETS,
			new Map([['default', [mcp({ domain: 'aaa.example' })]]]),
		).map((entry) => entry.domain);
		expect(domains).toEqual([...domains].sort((a, b) => a.localeCompare(b)));
	});
});

describe('filterEntries', () => {
	const entries = buildRuleEntries(SETS, new Map([['default', [mcp({ domain: 'example.com' })]]]));

	it('matches a domain substring case-insensitively', () => {
		const found = filterEntries(entries, { query: '  EXAMPLE.COM ', action: 'all', setId: 'all' });
		expect(found.map((entry) => entry.domain)).toEqual(['example.com']);
	});

	it('filters by action and by filter set', () => {
		expect(
			filterEntries(entries, { query: '', action: 'allow', setId: 'all' }).map((e) => e.domain),
		).toEqual(['de.wikipedia.org', 'kids.example']);
		expect(
			filterEntries(entries, { query: '', action: 'all', setId: 'kids' }).map((e) => e.domain),
		).toEqual(['de.wikipedia.org']);
	});
});

describe('minutesLeft and isLive', () => {
	const now = new Date('2026-10-28T12:00:00Z');

	it('rounds up to whole minutes and never goes below one', () => {
		expect(minutesLeft('2026-10-28T12:03:30Z', now)).toBe(4);
		expect(minutesLeft('2026-10-28T12:00:10Z', now)).toBe(1);
		expect(minutesLeft('2026-10-28T11:00:00Z', now)).toBe(1);
	});

	it('treats only future instants as live', () => {
		expect(isLive('2026-10-28T12:05:00Z', now)).toBe(true);
		expect(isLive('2026-10-28T12:00:00Z', now)).toBe(false);
		expect(isLive('not a date', now)).toBe(false);
	});
});
