// The Regeln page's rows: every rule of every filter set, whether it is a line of the set's custom
// rules or an MCP-managed rule. Pure functions only; the page does the reads and the writes.

import { buildRuleText, type FilterSet } from '$lib/api/filtering';
import type { McpRuleRow } from '$lib/api/mcp-rules';
import { isCommentLine, parseRuleLine, ruleLines, type RuleAction } from '$lib/policy/rule-lines';

export type RuleSource = 'text' | 'mcp';

export interface RuleEntry {
	key: string;
	source: RuleSource;
	setId: string;
	setName: string;
	action: RuleAction;
	/** An advanced line (modifier, regex, hosts syntax) keeps its raw text here and is not a domain rule. */
	advanced: boolean;
	/** The domain of a plain rule; the raw line text of an advanced rule. */
	domain: string;
	/** The rule as written: the custom-rules line, or the MCP rule's rule text. */
	ruleText: string;
	/** Null for advanced rules, where the scope is part of the raw text. */
	includeSubdomains: boolean | null;
	/** Position of the line in the set's custom rules (text rules only). */
	lineIndex: number;
	/** Expiry instant of an MCP rule; null means it does not expire. */
	expiresAt: string | null;
}

export type ActionFilter = 'all' | RuleAction;

export interface EntryFilter {
	query: string;
	action: ActionFilter;
	/** 'all' or one filter set id. */
	setId: string;
}

/** Every rule of every set, sorted by domain (then set name). Comment lines are not rules. */
export function buildRuleEntries(
	sets: FilterSet[],
	mcpBySet: ReadonlyMap<string, McpRuleRow[]>,
): RuleEntry[] {
	const entries: RuleEntry[] = [];
	for (const set of sets) {
		const setName = set.name || set.id;
		for (const line of ruleLines(set.custom_rules)) {
			if (isCommentLine(line.text)) continue;
			const parsed = parseRuleLine(line.text);
			entries.push({
				key: `text:${set.id}:${line.index}`,
				source: 'text',
				setId: set.id,
				setName,
				action: parsed.action,
				advanced: parsed.kind === 'advanced',
				domain: parsed.kind === 'domain' ? parsed.domain : line.text,
				ruleText: line.text,
				includeSubdomains: parsed.kind === 'domain' ? parsed.includeSubdomains : null,
				lineIndex: line.index,
				expiresAt: null,
			});
		}
	}

	const names = new Map(sets.map((set) => [set.id, set.name || set.id]));
	for (const [setId, rows] of mcpBySet) {
		rows.forEach((row, position) => {
			const includeSubdomains = row.include_subdomains === true;
			entries.push({
				key: `mcp:${setId}:${row.id ?? position}`,
				source: 'mcp',
				setId,
				setName: names.get(setId) ?? setId,
				action: 'block',
				advanced: false,
				domain: row.domain,
				ruleText:
					row.rule_text ??
					buildRuleText({
						action: 'block',
						domain: row.domain,
						include_subdomains: includeSubdomains,
					}),
				includeSubdomains,
				lineIndex: -1,
				expiresAt: row.expires_at ?? null,
			});
		});
	}

	return entries.sort(compareEntries);
}

export function compareEntries(a: RuleEntry, b: RuleEntry): number {
	return (
		a.domain.localeCompare(b.domain) ||
		a.setName.localeCompare(b.setName) ||
		a.key.localeCompare(b.key)
	);
}

/** Rows that match the search text (domain substring, case-insensitive), action and filter set. */
export function filterEntries(entries: RuleEntry[], filter: EntryFilter): RuleEntry[] {
	const query = filter.query.trim().toLowerCase();
	return entries.filter(
		(entry) =>
			(filter.action === 'all' || entry.action === filter.action) &&
			(filter.setId === 'all' || entry.setId === filter.setId) &&
			(query === '' || entry.domain.toLowerCase().includes(query)),
	);
}

/** Whole minutes left until an instant, rounded up and never below one. */
export function minutesLeft(instant: string, now: Date): number {
	const minutes = Math.ceil((Date.parse(instant) - now.getTime()) / 60_000);
	return Math.max(1, minutes);
}

/** True while the instant is in the future; an unreadable instant is not live. */
export function isLive(instant: string, now: Date): boolean {
	const time = Date.parse(instant);
	return !Number.isNaN(time) && time > now.getTime();
}
