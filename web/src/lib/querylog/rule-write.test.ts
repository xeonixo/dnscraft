import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { FilterSet } from '$lib/api/filtering';

const api = vi.hoisted(() => ({
	listFilterSets: vi.fn(),
	saveFilterSet: vi.fn(),
}));

vi.mock('$lib/api/filtering', async (importOriginal) => ({
	...(await importOriginal<typeof import('$lib/api/filtering')>()),
	listFilterSets: api.listFilterSets,
	saveFilterSet: api.saveFilterSet,
}));

import {
	appendRuleLine,
	defaultRuleAction,
	isTemporary,
	preferredSetId,
	removePermanentRule,
	writePermanentRule,
} from './rule-write';

function set(overrides: Partial<FilterSet> = {}): FilterSet {
	return {
		id: 'default',
		name: 'Standard',
		lists: [],
		custom_rules: '||ads.example^',
		services: [],
		block_mode: 'refused',
		...overrides,
	};
}

describe('defaultRuleAction', () => {
	it('flips the verdict: blocked queries get an allow, allowed queries a block', () => {
		expect(defaultRuleAction('blocked')).toBe('allow');
		expect(defaultRuleAction('allowed')).toBe('block');
	});

	it('defaults other statuses to allow', () => {
		expect(defaultRuleAction('servfail')).toBe('allow');
		expect(defaultRuleAction('dnssec_bogus')).toBe('allow');
	});
});

describe('isTemporary', () => {
	it('routes only a duration-bound allow to the temporary endpoint', () => {
		expect(isTemporary('allow', 'PT5M')).toBe(true);
		expect(isTemporary('allow', 'PT1H')).toBe(true);
		expect(isTemporary('allow', 'permanent')).toBe(false);
	});

	it('never routes a block to the temporary endpoint', () => {
		expect(isTemporary('block', 'PT5M')).toBe(false);
		expect(isTemporary('block', 'permanent')).toBe(false);
	});
});

describe('appendRuleLine', () => {
	it('appends on a new line after existing rules', () => {
		expect(appendRuleLine('||a^\n! note', '@@||b^')).toEqual({
			raw: '||a^\n! note\n@@||b^',
			added: true,
		});
	});

	it('does not add a trailing blank line when the text is empty or blank', () => {
		expect(appendRuleLine('', '||a^')).toEqual({ raw: '||a^', added: true });
		expect(appendRuleLine('  \n', '||a^')).toEqual({ raw: '||a^', added: true });
	});

	it('does not duplicate an exact rule line, ignoring surrounding whitespace', () => {
		expect(appendRuleLine('||a^\n  @@||b^  ', '@@||b^')).toEqual({
			raw: '||a^\n  @@||b^  ',
			added: false,
		});
	});

	it('treats a comment that mentions the rule as a different line', () => {
		expect(appendRuleLine('! @@||b^', '@@||b^').added).toBe(true);
	});
});

describe('preferredSetId', () => {
	const sets = [{ id: 'kids' }, { id: 'default' }];

	it('prefers the set that decided the query', () => {
		expect(preferredSetId(sets, 'kids')).toBe('kids');
	});

	it('falls back to default, then to the first set', () => {
		expect(preferredSetId(sets, 'gone')).toBe('default');
		expect(preferredSetId([{ id: 'work' }, { id: 'kids' }])).toBe('work');
	});

	it('returns an empty id when there are no sets', () => {
		expect(preferredSetId([], 'default')).toBe('');
	});
});

describe('writePermanentRule', () => {
	beforeEach(() => {
		api.listFilterSets.mockReset();
		api.saveFilterSet.mockReset();
		api.saveFilterSet.mockResolvedValue({ version: 2, filter_set: set(), created: false });
	});

	it('appends the built rule text to the freshly loaded set and saves it', async () => {
		api.listFilterSets.mockResolvedValue([set()]);

		const result = await writePermanentRule(
			{ action: 'allow', domain: 'example.com', include_subdomains: true },
			'default',
		);

		expect(result).toEqual({
			status: 'added',
			ruleText: '@@||example.com^',
			filterSetId: 'default',
			filterSetName: 'Standard',
		});
		expect(api.saveFilterSet).toHaveBeenCalledWith(
			expect.objectContaining({ id: 'default', custom_rules: '||ads.example^\n@@||example.com^' }),
		);
	});

	it('writes nothing when the exact rule already exists', async () => {
		api.listFilterSets.mockResolvedValue([set({ custom_rules: '||ads.example^' })]);

		const result = await writePermanentRule(
			{ action: 'block', domain: 'ads.example', include_subdomains: true },
			'default',
		);

		expect(result.status).toBe('exists');
		expect(result.ruleText).toBe('||ads.example^');
		expect(api.saveFilterSet).not.toHaveBeenCalled();
	});

	it('reports an unknown set without writing', async () => {
		api.listFilterSets.mockResolvedValue([set()]);

		const result = await writePermanentRule(
			{ action: 'block', domain: 'x.example', include_subdomains: false },
			'nope',
		);

		expect(result.status).toBe('unknown_set');
		expect(api.saveFilterSet).not.toHaveBeenCalled();
	});
});

describe('removePermanentRule', () => {
	beforeEach(() => {
		api.listFilterSets.mockReset();
		api.saveFilterSet.mockReset();
		api.saveFilterSet.mockResolvedValue({ version: 3, filter_set: set(), created: false });
	});

	it('removes exactly that line from a fresh copy and keeps the other lines', async () => {
		api.listFilterSets.mockResolvedValue([
			set({ custom_rules: '! Schule\n||ads.example^\n@@|kids.example^' }),
		]);

		expect(await removePermanentRule('default', 1, '||ads.example^')).toBe('removed');
		expect(api.saveFilterSet).toHaveBeenCalledWith(
			expect.objectContaining({ id: 'default', custom_rules: '! Schule\n@@|kids.example^' }),
		);
	});

	it('writes nothing when the line is no longer in the set', async () => {
		api.listFilterSets.mockResolvedValue([set({ custom_rules: '||other^' })]);

		expect(await removePermanentRule('default', 0, '||ads.example^')).toBe('missing');
		expect(api.saveFilterSet).not.toHaveBeenCalled();
	});

	it('reports an unknown set without writing', async () => {
		api.listFilterSets.mockResolvedValue([set()]);

		expect(await removePermanentRule('nope', 0, '||ads.example^')).toBe('unknown_set');
		expect(api.saveFilterSet).not.toHaveBeenCalled();
	});
});
