import { del, get, post } from './client';

export type McpRuleKind = 'rules' | 'temporary_allows' | 'pauses';

export interface McpRuleRow {
	id?: string;
	domain: string;
	include_subdomains?: boolean;
	rule_text?: string;
	created_at?: string;
	expires_at?: string | null;
	filter_set_id?: string;
	paused_until?: string;
}

export interface McpRulesPage {
	filter_set_id: string;
	kind: McpRuleKind;
	rules?: McpRuleRow[];
	temporary_allows?: McpRuleRow[];
	pauses?: McpRuleRow[];
	has_more: boolean;
	next_offset: number | null;
}

export const listMcpRules = (
	kind: McpRuleKind,
	filterSetId = 'default',
	limit = 100,
	offset = 0,
): Promise<McpRulesPage> =>
	get(
		`/filtering/mcp-rules?kind=${encodeURIComponent(kind)}&filter_set_id=${encodeURIComponent(filterSetId)}&limit=${limit}&offset=${offset}`,
	);

export const removeMcpRule = (domain: string, filterSetId = 'default'): Promise<unknown> =>
	del('/filtering/custom-rules', { body: { domain, filter_set_id: filterSetId } });

export const resumeFilterSet = (filterSetId = 'default'): Promise<{ filter_set_id: string }> =>
	post('/filtering/resume', { body: { filter_set_id: filterSetId } });
