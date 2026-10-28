import type { ConfigFinding } from '$lib/api/config';
import { errorMessage, errorMessageKey } from '$lib/i18n/locale';

// Pure helpers for the configuration screen: JSON parsing with a location, the mcp_rules comparison
// shown in the check sheet, and the label of a finding (translated when known, raw code otherwise).

export type ParseResult =
	| { ok: true; value: Record<string, unknown> }
	| { ok: false; reason: 'syntax' | 'not_object'; line: number | null; column: number | null };

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Parses the editor text. A configuration is a JSON object; anything else is rejected here, before
 * the request. The position of a syntax error comes from the engine's message when it has one.
 */
export function parseConfigText(text: string): ParseResult {
	let value: unknown;
	try {
		value = JSON.parse(text);
	} catch (cause) {
		const position = cause instanceof SyntaxError ? /position (\d+)/.exec(cause.message) : null;
		if (!position) return { ok: false, reason: 'syntax', line: null, column: null };
		const before = text.slice(0, Number(position[1])).split('\n');
		const line = before.length;
		const column = (before[before.length - 1] ?? '').length + 1;
		return { ok: false, reason: 'syntax', line, column };
	}
	if (!isRecord(value)) return { ok: false, reason: 'not_object', line: null, column: null };
	return { ok: true, value };
}

/** Translated label for a finding, or its raw code when no message exists for that code. */
export function findingLabel(finding: ConfigFinding): string {
	if (errorMessageKey(finding.code) === 'error_unknown') return finding.code;
	return errorMessage(finding.code, finding.params ?? {});
}

/** Whether a finding is the version conflict, which the screen answers with a reload offer. */
export function isVersionConflict(finding: ConfigFinding): boolean {
	return finding.code === 'control_api.config.version';
}

export type McpRuleChange =
	| { set: string; kind: 'carried'; count: number }
	| { set: string; kind: 'deleted'; count: number }
	| { set: string; kind: 'replaced'; count: number };

function filterSets(config: unknown): Record<string, unknown>[] {
	if (!isRecord(config) || !isRecord(config.filtering)) return [];
	const sets = config.filtering.sets;
	return Array.isArray(sets) ? sets.filter(isRecord) : [];
}

/**
 * How the candidate treats each filter set's `mcp_rules` compared with the stored snapshot.
 * An omitted field carries the stored rules over; an explicit empty array deletes them; a non-empty
 * array replaces them. Only sets that have stored rules, or that send rules, are reported.
 */
export function mcpRuleChanges(stored: unknown, candidate: unknown): McpRuleChange[] {
	const storedRules = new Map<string, unknown[]>();
	for (const set of filterSets(stored)) {
		if (typeof set.id === 'string' && Array.isArray(set.mcp_rules)) {
			storedRules.set(set.id, set.mcp_rules);
		}
	}
	const changes: McpRuleChange[] = [];
	for (const set of filterSets(candidate)) {
		const id = typeof set.id === 'string' ? set.id : '';
		const before = storedRules.get(id) ?? [];
		if (!('mcp_rules' in set)) {
			if (before.length > 0) changes.push({ set: id, kind: 'carried', count: before.length });
		} else if (Array.isArray(set.mcp_rules)) {
			const after = set.mcp_rules;
			if (after.length === 0) {
				if (before.length > 0) changes.push({ set: id, kind: 'deleted', count: before.length });
			} else if (JSON.stringify(after) !== JSON.stringify(before)) {
				changes.push({ set: id, kind: 'replaced', count: after.length });
			}
		}
	}
	return changes;
}
