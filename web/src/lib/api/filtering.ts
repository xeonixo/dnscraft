import { del, get, post, put, type RequestOptions } from './client';

export type BlockMode = 'refused' | 'nxdomain' | 'null_ip' | { custom_ip: string };

export interface FilterSet {
	id: string;
	name: string;
	lists: string[];
	custom_rules: string;
	services: string[];
	block_mode: BlockMode;
}

export interface FilterList {
	id: string;
	name: string;
	source: { url?: string; file?: string };
	enabled: boolean;
}

export interface GuidedRule {
	action: 'block' | 'allow';
	domain: string;
	include_subdomains: boolean;
}

export interface CustomRuleBody {
	domain: string;
	include_subdomains: boolean;
	filter_set_id: string;
	reason?: string;
}

export function buildRuleText(rule: GuidedRule): string {
	const suffix = rule.include_subdomains ? '^' : '';
	const body = `${rule.domain}${suffix}`;
	return rule.action === 'allow' ? `@@||${body}` : `||${body}`;
}

function parseSet(value: unknown): FilterSet | null {
	if (typeof value !== 'object' || value === null) return null;
	const row = value as FilterSet;
	if (typeof row.id !== 'string') return null;
	return {
		id: row.id,
		name: typeof row.name === 'string' ? row.name : '',
		lists: Array.isArray(row.lists) ? row.lists.map(String) : [],
		custom_rules:
			typeof row.custom_rules === 'string'
				? row.custom_rules
				: Array.isArray(row.custom_rules)
					? (row.custom_rules as string[]).join('\n')
					: '',
		services: Array.isArray(row.services) ? row.services.map(String) : [],
		block_mode: row.block_mode ?? 'refused',
	};
}

function parseList(value: unknown): FilterList | null {
	if (typeof value !== 'object' || value === null) return null;
	const row = value as FilterList;
	if (typeof row.id !== 'string') return null;
	const source =
		typeof row.source === 'object' && row.source !== null
			? (row.source as FilterList['source'])
			: {};
	return {
		id: row.id,
		name: typeof row.name === 'string' ? row.name : '',
		source,
		enabled: row.enabled !== false,
	};
}

export const listFilterSets = (): Promise<FilterSet[]> =>
	get<{ filter_sets: unknown }>('/filter-sets').then((data) =>
		Array.isArray(data.filter_sets)
			? data.filter_sets.map(parseSet).filter((s): s is FilterSet => s !== null)
			: [],
	);

export const saveFilterSet = (
	body: FilterSet,
	options?: RequestOptions,
): Promise<{ version: number; filter_set: FilterSet; created: boolean }> =>
	put('/filter-sets', { body, ...options });

export const deleteFilterSet = (
	id: string,
	options?: RequestOptions,
): Promise<{ version: number }> => del('/filter-sets', { body: { id }, ...options });

export const listFilterLists = (): Promise<FilterList[]> =>
	get<{ filter_lists: unknown }>('/filter-lists').then((data) =>
		Array.isArray(data.filter_lists)
			? data.filter_lists.map(parseList).filter((l): l is FilterList => l !== null)
			: [],
	);

export const saveFilterList = (
	body: FilterList,
	options?: RequestOptions,
): Promise<{ version: number; filter_list: FilterList; created: boolean }> =>
	put('/filter-lists', { body, ...options });

export const deleteFilterList = (
	id: string,
	options?: RequestOptions,
): Promise<{ version: number }> => del('/filter-lists', { body: { id }, ...options });

export const addCustomRule = (
	body: CustomRuleBody,
): Promise<{ rule_text: string; domain: string; include_subdomains: boolean }> =>
	post('/filtering/custom-rules', { body });
