// Turns a query-detail decision into a write. Temporary allows go through the MCP-phase endpoint;
// permanent rules (allow or block) are lines in a filter set's custom rules, written with the
// same PUT the filter-sets page uses. The dedupe and routing rules live here so they stay testable.

import { buildRuleText, listFilterSets, saveFilterSet, type GuidedRule } from '$lib/api/filtering';
import type { TempAllowDuration, TempAllowResult } from '$lib/api/query-log';
import { removeRuleLine } from '$lib/policy/rule-lines';
import type { RecordStatus } from './view';

export type RuleAction = GuidedRule['action'];
export type RuleValidity = TempAllowDuration | 'permanent';

export interface PermanentRuleResult {
	status: 'added' | 'exists' | 'unknown_set';
	ruleText: string;
	filterSetId: string;
	filterSetName: string;
}

export type RuleOutcome =
	| { kind: 'temporary'; result: TempAllowResult }
	| { kind: 'permanent'; result: PermanentRuleResult };

/** Opposite of the verdict the query got. Anything that was neither blocked nor allowed gets "allow". */
export function defaultRuleAction(status: RecordStatus): RuleAction {
	return status === 'allowed' ? 'block' : 'allow';
}

/** Only an allow with a duration is temporary. Blocks and permanent allows become rule lines. */
export function isTemporary(
	action: RuleAction,
	validity: RuleValidity,
): validity is TempAllowDuration {
	return action === 'allow' && validity !== 'permanent';
}

/** Appends `line` unless an identical rule line already exists. Returns the new text and whether it changed. */
export function appendRuleLine(raw: string, line: string): { raw: string; added: boolean } {
	if (raw.split('\n').some((item) => item.trim() === line)) return { raw, added: false };
	return { raw: raw.trim() ? `${raw.trimEnd()}\n${line}` : line, added: true };
}

/** The set the picker starts on: the one that decided the query, else `default`, else the first. */
export function preferredSetId(sets: { id: string }[], decidedBy?: string): string {
	return (
		sets.find((set) => set.id === decidedBy)?.id ??
		sets.find((set) => set.id === 'default')?.id ??
		sets[0]?.id ??
		''
	);
}

/**
 * Adds the rule to a fresh copy of the filter set (never a stale one the page loaded earlier, so
 * concurrent edits are not overwritten). No write happens when the exact rule line is already there.
 */
export async function writePermanentRule(
	rule: GuidedRule,
	setId: string,
): Promise<PermanentRuleResult> {
	const ruleText = buildRuleText(rule);
	const set = (await listFilterSets()).find((item) => item.id === setId);
	if (!set) return { status: 'unknown_set', ruleText, filterSetId: setId, filterSetName: setId };

	const next = appendRuleLine(set.custom_rules, ruleText);
	const filterSetName = set.name || set.id;
	if (!next.added) return { status: 'exists', ruleText, filterSetId: set.id, filterSetName };

	await saveFilterSet({ ...set, custom_rules: next.raw });
	return { status: 'added', ruleText, filterSetId: set.id, filterSetName };
}

/**
 * Removes one rule line from a fresh copy of the filter set. `lineIndex` is only a hint: the line
 * must still carry `ruleText`, otherwise nothing is written ('missing').
 */
export async function removePermanentRule(
	setId: string,
	lineIndex: number,
	ruleText: string,
): Promise<'removed' | 'missing' | 'unknown_set'> {
	const set = (await listFilterSets()).find((item) => item.id === setId);
	if (!set) return 'unknown_set';

	const next = removeRuleLine(set.custom_rules, lineIndex, ruleText);
	if (!next.removed) return 'missing';

	await saveFilterSet({ ...set, custom_rules: next.raw });
	return 'removed';
}
