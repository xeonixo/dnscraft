import { describe, expect, it } from 'vitest';
import {
	countRules,
	isCommentLine,
	parseRuleLine,
	removeRuleLine,
	ruleDomainProblem,
	ruleLines,
} from './rule-lines';

describe('parseRuleLine', () => {
	it.each([
		['||ads.example^', 'block', 'ads.example', true],
		['|exact.example^', 'block', 'exact.example', false],
		['@@||api.github.com^', 'allow', 'api.github.com', true],
		['@@|only.example^', 'allow', 'only.example', false],
	])('reads %s as a plain %s rule', (line, action, domain, includeSubdomains) => {
		expect(parseRuleLine(line)).toEqual({ kind: 'domain', action, domain, includeSubdomains });
	});

	it.each([
		['||ads.example.net^$important'],
		['/^ad[0-9]+\\./'],
		['0.0.0.0 ads.example'],
		['||no-caret.example'],
		['@@||allow-with-modifier.example^$dnstype=A'],
	])('keeps %s as an advanced rule with its raw text', (line) => {
		const parsed = parseRuleLine(line);
		expect(parsed.kind).toBe('advanced');
		expect(parsed).toMatchObject({ text: line });
	});

	it('takes the action of an advanced rule from its @@ prefix', () => {
		expect(parseRuleLine('@@||a.example^$important')).toMatchObject({ action: 'allow' });
		expect(parseRuleLine('||a.example^$important')).toMatchObject({ action: 'block' });
	});

	it('trims surrounding whitespace before parsing', () => {
		expect(parseRuleLine('  ||ads.example^  ')).toMatchObject({ domain: 'ads.example' });
	});
});

describe('ruleLines and countRules', () => {
	it('keeps the raw position of each non-blank line', () => {
		expect(ruleLines('||a^\n\n  ! note\n|b^')).toEqual([
			{ index: 0, text: '||a^' },
			{ index: 2, text: '! note' },
			{ index: 3, text: '|b^' },
		]);
	});

	it('does not count comment lines as rules', () => {
		expect(countRules('||a^\n! comment\n# hosts comment\n@@|b^')).toBe(2);
		expect(isCommentLine('! x')).toBe(true);
		expect(isCommentLine('# x')).toBe(true);
		expect(isCommentLine('||x^')).toBe(false);
	});
});

describe('removeRuleLine', () => {
	it('removes only the matching line and keeps every other line byte-identical', () => {
		const raw = '! Schule\n||a.example^\n@@|b.example^\n  ||c.example^  \n';
		expect(removeRuleLine(raw, 1, '||a.example^')).toEqual({
			raw: '! Schule\n@@|b.example^\n  ||c.example^  \n',
			removed: true,
		});
	});

	it('keeps CRLF line endings of the other lines', () => {
		const raw = '||a^\r\n||x^\r\n||b^';
		expect(removeRuleLine(raw, 1, '||x^')).toEqual({ raw: '||a^\r\n||b^', removed: true });
	});

	it('finds the line by its text when the index has moved', () => {
		const raw = '||new^\n||x^';
		expect(removeRuleLine(raw, 0, '||x^')).toEqual({ raw: '||new^', removed: true });
	});

	it('reports nothing removed when the line is gone', () => {
		const raw = '||a^\n||b^';
		expect(removeRuleLine(raw, 0, '||gone^')).toEqual({ raw, removed: false });
	});
});

describe('ruleDomainProblem', () => {
	it('flags an empty domain', () => {
		expect(ruleDomainProblem('   ')).toBe('empty');
	});

	it.each(['bad domain.example', 'example.com/path', 'a^b', 'x|y', 'a*.example', '@x'])(
		'rejects %s',
		(value) => {
			expect(ruleDomainProblem(value)).toBe('invalid');
		},
	);

	it('accepts a plain host name, trimmed', () => {
		expect(ruleDomainProblem('  ads.example.com ')).toBeNull();
	});
});
