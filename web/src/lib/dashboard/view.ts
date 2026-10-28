import type { IconName, StatusTone } from '$lib/components/icons';
import type { Result } from '$lib/api/result';
import { NOT_READY_CODE } from '$lib/api/result';
import type { TlsMode, TopDomain, Upstream, UpstreamState } from '$lib/api/stats';
import { errorMessage } from '$lib/i18n/locale';
import { m } from '$lib/paraglide/messages';

export interface Verdict {
	tone: StatusTone;
	icon: IconName;
	label: string;
}

/** Icon, tone and translated word for an upstream health state. */
export function upstreamVerdict(state: UpstreamState): Verdict {
	switch (state) {
		case 'up':
			return { tone: 'ok', icon: 'check-circle', label: m.status_ok() };
		case 'degraded':
			return { tone: 'warn', icon: 'alert-triangle', label: m.status_degraded() };
		case 'down':
			return { tone: 'danger', icon: 'x-circle', label: m.status_down() };
		case 'unknown':
			return unknownVerdict();
	}
}

/** Self-signed is a warning the owner must act on; ACME and uploaded certificates are in place. */
export function tlsVerdict(mode: TlsMode): Verdict {
	if (mode === 'self_signed') {
		return { tone: 'warn', icon: 'alert-triangle', label: m.status_warn() };
	}
	return { tone: 'ok', icon: 'check-circle', label: m.status_ok() };
}

export function tlsModeLabel(mode: TlsMode): string {
	switch (mode) {
		case 'acme':
			return m.tls_mode_acme();
		case 'manual':
			return m.tls_mode_manual();
		case 'self_signed':
			return m.tls_mode_self_signed();
	}
}

/** Ready or not for queries; a not-ready node names what is still starting. */
export function readinessVerdict(ready: boolean): Verdict {
	return ready
		? { tone: 'ok', icon: 'check-circle', label: m.status_ok() }
		: { tone: 'danger', icon: 'x-circle', label: m.status_down() };
}

export function unknownVerdict(): Verdict {
	return { tone: 'neutral', icon: 'help-circle', label: m.status_unknown() };
}

/** One line of text for a read that did not produce data; empty for `ok`. */
export function resultText(result: Result<unknown>): string {
	switch (result.kind) {
		case 'loading':
			return m.state_loading();
		case 'unavailable':
			return result.code === NOT_READY_CODE
				? errorMessage(result.code)
				: m.dashboard_unavailable_title();
		case 'error':
			return errorMessage(result.code, result.params);
		case 'ok':
			return '';
	}
}

/** `part` as a fraction of `whole` in 0..1; zero when the whole is zero. */
export function shareOf(part: number, whole: number): number {
	return whole > 0 ? part / whole : 0;
}

/**
 * Domains with at least one blocked query, most blocked first. The API ranks domains by query
 * count, so this is computed from the returned window only (see the report on the endpoint).
 */
export function topBlockedDomains(domains: TopDomain[], limit: number): TopDomain[] {
	return domains
		.filter((domain) => domain.blocked > 0)
		.sort(
			(a, b) => b.blocked - a.blocked || b.queries - a.queries || a.domain.localeCompare(b.domain),
		)
		.slice(0, limit);
}

/** Translated name of an answer origin (what answered the query); unknown ids are kept as they are. */
export function answerSourceLabel(source: string): string {
	switch (source) {
		case 'resolver':
			return m.source_resolver();
		case 'filter_block':
			return m.source_filter_block();
		case 'local_view':
			return m.source_local_view();
		case 'local_client':
			return m.source_local_client();
		case 'synth_any':
			return m.source_synth_any();
		case 'bypass':
			return m.source_bypass();
		case 'resolve_error':
			return m.source_resolve_error();
		case 'listener_ddr':
			return m.source_listener_ddr();
		default:
			return source;
	}
}

/** Answer sources, largest first, with their share of the total. */
export function answerSourceRows(
	counts: Record<string, number>,
): { source: string; count: number; share: number }[] {
	const total = Object.values(counts).reduce((sum, value) => sum + value, 0);
	return Object.entries(counts)
		.filter(([, count]) => count > 0)
		.sort(([a, x], [b, y]) => y - x || a.localeCompare(b))
		.map(([source, count]) => ({ source, count, share: total > 0 ? count / total : 0 }));
}

/** Upstreams in order: `healthy` are up; `affected` are anything else and go in front of the owner. */
export function splitUpstreams(items: Upstream[]): { healthy: Upstream[]; affected: Upstream[] } {
	return {
		healthy: items.filter((item) => item.state === 'up'),
		affected: items.filter((item) => item.state !== 'up'),
	};
}

export interface HealthProblem {
	label: string;
	verdict: string;
	/** Extra context, such as the modules a node is still waiting for. */
	detail?: string;
}

/**
 * What the status strip counts as a problem: a node that is not ready, a self-signed certificate,
 * and upstreams that are degraded or down. Unknown states are not counted.
 */
export function healthProblems(input: {
	ready: boolean | null;
	modulesNotReady: string[];
	tlsMode: TlsMode | null;
	upstreams: Upstream[];
}): HealthProblem[] {
	const problems: HealthProblem[] = [];
	if (input.ready === false) {
		problems.push({
			label: m.dashboard_node_label(),
			verdict: m.status_down(),
			detail:
				input.modulesNotReady.length > 0
					? m.dashboard_modules_pending({ modules: input.modulesNotReady.join(', ') })
					: undefined,
		});
	}
	if (input.tlsMode === 'self_signed') {
		problems.push({ label: m.dashboard_tls_label(), verdict: m.status_warn() });
	}
	for (const item of input.upstreams) {
		if (item.state === 'degraded' || item.state === 'down') {
			problems.push({
				label: item.kind === 'recursion' ? m.dashboard_recursion() : item.name,
				verdict: upstreamVerdict(item.state).label,
			});
		}
	}
	return problems;
}

/** Legend and segment colour of an answer origin; the legend text names it too. */
export function answerSourceTone(source: string): 'accent' | 'ok' | 'warn' | 'danger' | 'neutral' {
	switch (source) {
		case 'resolver':
			return 'ok';
		case 'filter_block':
			return 'danger';
		case 'resolve_error':
			return 'warn';
		case 'local_view':
		case 'local_client':
			return 'accent';
		default:
			return 'neutral';
	}
}
