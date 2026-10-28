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

/** Every entry of one kind in one filter set, read page by page. */
export async function listAllMcpRules(
	kind: McpRuleKind,
	filterSetId: string,
): Promise<McpRuleRow[]> {
	const rows: McpRuleRow[] = [];
	let offset = 0;
	for (;;) {
		const page = await listMcpRules(kind, filterSetId, 500, offset);
		const items =
			kind === 'temporary_allows'
				? page.temporary_allows
				: kind === 'pauses'
					? page.pauses
					: page.rules;
		rows.push(...(items ?? []));
		// Stop on the last page, and on a cursor that does not move (never loop forever).
		if (!page.has_more || page.next_offset === null || page.next_offset <= offset) return rows;
		offset = page.next_offset;
	}
}

export const removeMcpRule = (domain: string, filterSetId = 'default'): Promise<unknown> =>
	del('/filtering/custom-rules', { body: { domain, filter_set_id: filterSetId } });

export const resumeFilterSet = (filterSetId = 'default'): Promise<{ filter_set_id: string }> =>
	post('/filtering/resume', { body: { filter_set_id: filterSetId } });
