import type { IconName, StatusTone } from '$lib/components/icons';
import type { DecisionStep, QueryAnswer, QueryRecord } from '$lib/api/query-log';
import { answerSourceLabel } from '$lib/dashboard/view';
import { m } from '$lib/paraglide/messages';

// Presentation rules for query records. The record JSON carries no `status` field: the outcome is
// derived here exactly as the server derives its own `status` column (blocked when a filter hit has
// a block mode, then SERVFAIL, then bogus DNSSEC, otherwise allowed).

export type RecordStatus = 'allowed' | 'blocked' | 'servfail' | 'dnssec_bogus';

export function statusOf(record: Pick<QueryRecord, 'filter' | 'rcode' | 'dnssec'>): RecordStatus {
	if (record.filter?.block_mode) return 'blocked';
	if (record.rcode === 'SERVFAIL') return 'servfail';
	if (record.dnssec === 'bogus') return 'dnssec_bogus';
	return 'allowed';
}

export interface StatusStyle {
	tone: StatusTone;
	icon: IconName;
	label: string;
}

export function statusStyle(status: RecordStatus): StatusStyle {
	switch (status) {
		case 'allowed':
			return { tone: 'ok', icon: 'check-circle', label: m.querylog_status_allowed() };
		case 'blocked':
			return { tone: 'danger', icon: 'ban', label: m.querylog_status_blocked() };
		case 'servfail':
			return { tone: 'danger', icon: 'x-circle', label: m.querylog_status_servfail() };
		case 'dnssec_bogus':
			return { tone: 'warn', icon: 'alert-triangle', label: m.querylog_status_dnssec_bogus() };
	}
}

/** Translated tracker category; an id the UI does not know reads as itself. */
export function trackerCategoryLabel(category: string): string {
	const messages = m as unknown as Record<string, (() => string) | undefined>;
	const key = `tracker_category_${category}`;
	return Object.hasOwn(messages, key) ? (messages[key]?.() ?? category) : category;
}

/** Translated provenance of the rule that decided a query (stable identifier when unknown). */
export function provenanceLabel(reason: string): string {
	switch (reason) {
		case 'list':
			return m.querylog_provenance_list();
		case 'custom':
			return m.querylog_provenance_custom();
		case 'service':
			return m.querylog_provenance_service();
		case 'temporary_allow':
			return m.querylog_provenance_temporary_allow();
		case 'mcp':
			return m.querylog_provenance_mcp();
		default:
			return reason;
	}
}

/**
 * One line for a list row: the first two answer values joined by ", ", then "+N" for the rest.
 * An answer without data shows its type instead. Empty for no answers.
 */
export function answerSummary(answers: QueryAnswer[]): string {
	const labels = answers.map((answer) => (answer.data === '' ? answer.type : answer.data));
	const head = labels.slice(0, 2).join(', ');
	return labels.length > 2
		? `${head} ${m.query_log_answers_more({ count: String(labels.length - 2) })}`
		: head;
}

export function dnssecLabel(value: string | null): string {
	switch (value) {
		case null:
			return m.querylog_not_checked();
		case 'secure':
			return m.querylog_dnssec_secure();
		case 'insecure':
			return m.querylog_dnssec_insecure();
		case 'bogus':
			return m.querylog_dnssec_bogus();
		case 'indeterminate':
			return m.querylog_dnssec_indeterminate();
		default:
			return value;
	}
}

export function selectionLabel(selection: QueryRecord['selection']): string {
	switch (selection.cause) {
		case 'subnet':
			return m.querylog_cause_subnet({ prefix: selection.prefix ?? '' });
		case 'client_id':
			return m.querylog_cause_client_id();
		default:
			return m.querylog_cause_default();
	}
}

/**
 * Translated label for a query-log value: an answer origin (record answer_source) or a resolve
 * step source (cache, recursion, stale). Unknown values keep their identifier.
 */
export function answerLabel(source: string): string {
	switch (source) {
		case 'cache':
			return m.source_cache();
		case 'recursion':
			return m.source_recursion();
		case 'stale':
			return m.source_stale();
		default:
			return answerSourceLabel(source);
	}
}

/** Translated stage name; an unknown stage keeps its identifier. */
export function stageLabel(stage: string): string {
	switch (stage) {
		case 'select':
			return m.querylog_stage_select();
		case 'any_synth':
			return m.querylog_stage_any_synth();
		case 'local_view':
			return m.querylog_stage_local_view();
		case 'local_client':
			return m.querylog_stage_local_client();
		case 'special_use_nxdomain':
			return m.querylog_stage_special_use();
		case 'bypass':
			return m.querylog_stage_bypass();
		case 'protection_paused':
			return m.querylog_stage_paused();
		case 'filter_qname':
			return m.querylog_stage_filter_qname();
		case 'answer_chain':
			return m.querylog_stage_answer_chain();
		case 'cname_chain':
			return m.querylog_stage_cname_chain();
		case 'answer_ip':
			return m.querylog_stage_answer_ip();
		case 'rebind':
			return m.querylog_stage_rebind();
		case 'aaaa_suppressed':
			return m.querylog_stage_aaaa();
		case 'resolve':
			return m.querylog_stage_resolve();
		case 'safesearch':
			return m.querylog_stage_safesearch();
		case 'schedule':
			return m.querylog_stage_schedule();
		default:
			return stage;
	}
}

/** Translated verdict; an unknown verdict keeps its identifier. */
export function verdictLabel(verdict: string): string {
	switch (verdict) {
		case 'selected':
			return m.querylog_verdict_selected();
		case 'synth':
			return m.querylog_verdict_synth();
		case 'answered':
			return m.querylog_verdict_answered();
		case 'nxdomain':
			return m.querylog_verdict_nxdomain();
		case 'paused':
			return m.querylog_verdict_paused();
		case 'blocked':
			return m.querylog_verdict_blocked();
		case 'rewritten':
			return m.querylog_verdict_rewritten();
		case 'skipped':
			return m.querylog_verdict_skipped();
		case 'stripped':
			return m.querylog_verdict_stripped();
		case 'suppressed':
			return m.querylog_verdict_suppressed();
		case 'resolved':
			return m.querylog_verdict_resolved();
		case 'pass':
			return m.querylog_verdict_pass();
		case 'allowed':
			return m.querylog_verdict_allowed();
		case 'failed':
			return m.querylog_verdict_failed();
		case 'active':
			return m.querylog_verdict_active();
		default:
			return verdict;
	}
}

/** Icon and tone for a verdict: blocking verdicts are danger, pass-through verdicts are ok. */
export function verdictStyle(verdict: string): { tone: StatusTone; icon: IconName } {
	if (verdict === 'blocked' || verdict === 'nxdomain' || verdict === 'failed') {
		return { tone: 'danger', icon: 'ban' };
	}
	if (verdict === 'paused' || verdict === 'stripped' || verdict === 'suppressed') {
		return { tone: 'warn', icon: 'alert-triangle' };
	}
	if (verdict === 'skipped') return { tone: 'neutral', icon: 'info' };
	return { tone: 'ok', icon: 'check-circle' };
}

/** One secondary line for a step, when the step carries a value worth showing. */
export function stepDetail(step: DecisionStep): { text: string; mono: boolean } | null {
	const text = (key: string): string | null => {
		const value = step[key];
		return typeof value === 'string' ? value : null;
	};
	switch (step.stage) {
		case 'resolve': {
			const source = text('source');
			if (step.verdict === 'failed') {
				const code = text('cause_code');
				return code === null ? null : { text: m.querylog_step_error({ code }), mono: true };
			}
			if (source === null) return null;
			return { text: m.querylog_step_from({ source: answerLabel(source) }), mono: false };
		}
		case 'select': {
			const selection = step.selection as QueryRecord['selection'] | undefined;
			return selection?.cause ? { text: selectionLabel(selection), mono: false } : null;
		}
		case 'rebind':
			return typeof step.count === 'number'
				? { text: m.querylog_step_removed({ count: String(step.count) }), mono: false }
				: null;
		case 'filter_qname': {
			const reason = text('reason');
			return reason === null ? null : { text: reason, mono: true };
		}
		case 'safesearch': {
			const target = text('target');
			return target === null ? null : { text: target, mono: true };
		}
		case 'schedule': {
			const id = text('id');
			return id === null ? null : { text: id, mono: true };
		}
		default:
			return null;
	}
}

/** Microseconds as milliseconds, for formatMilliseconds (which adds a decimal below 10 ms). */
export function microsToMilliseconds(us: number): number {
	return us / 1000;
}

const BLOCKING_VERDICTS = new Set(['blocked', 'nxdomain', 'failed', 'paused']);

/**
 * Index of the step that decided the answer: the first blocking step, otherwise the last step
 * (the one that produced the answer). -1 for an empty chain.
 */
export function decisiveIndex(steps: DecisionStep[]): number {
	const blocking = steps.findIndex((step) => BLOCKING_VERDICTS.has(step.verdict));
	return blocking >= 0 ? blocking : steps.length - 1;
}
