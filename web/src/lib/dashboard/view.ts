import type { IconName, StatusTone } from '$lib/components/icons';
import type { Result } from '$lib/api/result';
import { NOT_READY_CODE } from '$lib/api/result';
import type { TlsMode, TopDomain, UpstreamState } from '$lib/api/stats';
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

/** Translated name of an answer source; unknown sources keep their stable identifier. */
export function answerSourceLabel(source: string): string {
	switch (source) {
		case 'cache':
			return m.source_cache();
		case 'recursion':
			return m.source_recursion();
		case 'stale':
			return m.source_stale();
		case 'filter_block':
			return m.source_filter_block();
		case 'resolver':
			return m.source_resolver();
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
