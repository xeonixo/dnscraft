// Parsing of one filter set's custom rules text (one rule per line). Shared by the filter-set editor
// and the Regeln page so both read the same lines the same way.

export type RuleAction = 'block' | 'allow';

export interface RuleLine {
	/** Position in the raw text (split on `\n`); the handle a removal starts from. */
	index: number;
	/** The line without surrounding whitespace. */
	text: string;
}

export type ParsedRule =
	| { kind: 'domain'; action: RuleAction; domain: string; includeSubdomains: boolean }
	| { kind: 'advanced'; action: RuleAction; text: string };

/**
 * Plain domain rules as the guided form writes them: `||domain^` (block incl. subdomains), `|domain^`
 * (exact name) and the `@@` allow forms. Anything else (modifiers such as `$important`, regex, hosts
 * syntax, a missing caret) is an advanced rule and is shown as written.
 */
const DOMAIN_RULE = /^(@@)?(\|{1,2})([^\s^|$*\/@]+)\^$/;
/** Characters a domain typed into the add form may not contain (same set the rule syntax reserves). */
const RESERVED = /[\s^|$*\/@]/;

/** Non-blank lines with their position in the raw text. */
export function ruleLines(raw: string): RuleLine[] {
	return raw
		.split('\n')
		.map((text, index) => ({ index, text: text.trim() }))
		.filter((line) => line.text !== '');
}

/** Comment lines use AdGuard `!` or hosts-style `#`. */
export function isCommentLine(text: string): boolean {
	return /^[!#]/.test(text);
}

/** Rules are the non-blank lines that are not comments. */
export function countRules(raw: string): number {
	return ruleLines(raw).filter((line) => !isCommentLine(line.text)).length;
}

/** Parses one trimmed rule line. Comments are not rules; callers skip them before parsing. */
export function parseRuleLine(line: string): ParsedRule {
	const text = line.trim();
	const action: RuleAction = text.startsWith('@@') ? 'allow' : 'block';
	const match = DOMAIN_RULE.exec(text);
	if (!match) return { kind: 'advanced', action, text };
	return {
		kind: 'domain',
		action,
		domain: match[3],
		includeSubdomains: match[2] === '||',
	};
}

/**
 * Removes one rule line and leaves every other line byte-identical. The line at `index` is removed
 * when its text still matches `text`; otherwise the first line with that text is (the set may have
 * changed since the caller read the index). `removed` is false when no line matches.
 */
export function removeRuleLine(
	raw: string,
	index: number,
	text: string,
): { raw: string; removed: boolean } {
	const lines = raw.split('\n');
	const at =
		lines[index] !== undefined && lines[index].trim() === text
			? index
			: lines.findIndex((line) => line.trim() === text);
	if (at < 0) return { raw, removed: false };
	return { raw: lines.filter((_, position) => position !== at).join('\n'), removed: true };
}

/** Why a typed domain cannot be written as a rule, or null when it can. */
export function ruleDomainProblem(value: string): 'empty' | 'invalid' | null {
	const domain = value.trim();
	if (domain === '') return 'empty';
	return RESERVED.test(domain) ? 'invalid' : null;
}
