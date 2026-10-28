import { describe, expect, it } from 'vitest';
import {
	answerSourceLabel,
	answerSourceRows,
	resultText,
	shareOf,
	tlsVerdict,
	topBlockedDomains,
	upstreamVerdict,
} from './view';

describe('verdicts pair an icon and a word with the tone', () => {
	it.each([
		['up', 'check-circle', 'ok', 'OK'],
		['degraded', 'alert-triangle', 'warn', 'Degraded'],
		['down', 'x-circle', 'danger', 'Down'],
		['unknown', 'help-circle', 'neutral', 'Unknown'],
	] as const)('upstream %s', (state, icon, tone, label) => {
		expect(upstreamVerdict(state)).toEqual({ icon, tone, label });
	});

	it('marks a self-signed certificate as a warning and ACME as in place', () => {
		expect(tlsVerdict('self_signed')).toMatchObject({ tone: 'warn', icon: 'alert-triangle' });
		expect(tlsVerdict('acme')).toMatchObject({ tone: 'ok', icon: 'check-circle' });
	});
});

describe('shareOf', () => {
	it('is the part as a fraction of the whole', () => {
		expect(shareOf(200, 1000)).toBe(0.2);
	});

	it('is zero for an empty window', () => {
		expect(shareOf(0, 0)).toBe(0);
	});
});

describe('resultText', () => {
	it('explains a read that has no data yet, failed or is not offered here', () => {
		expect(resultText({ kind: 'loading' })).toBe('Loading…');
		expect(resultText({ kind: 'unavailable', code: 'control_api.not_found' })).toBe(
			'Not available on this node',
		);
		expect(resultText({ kind: 'unavailable', code: 'control_api.not_ready' })).toBe(
			'The node is still starting. Try again shortly.',
		);
		expect(resultText({ kind: 'error', code: 'client.network', params: {} })).toMatch(
			/could not be reached/,
		);
		expect(resultText({ kind: 'ok', data: null })).toBe('');
	});
});

describe('topBlockedDomains', () => {
	it('keeps only domains with blocked queries, most blocked first, capped', () => {
		const rows = topBlockedDomains(
			[
				{ domain: 'a.test', queries: 50, blocked: 0 },
				{ domain: 'b.test', queries: 10, blocked: 7 },
				{ domain: 'c.test', queries: 90, blocked: 7 },
				{ domain: 'd.test', queries: 5, blocked: 1 },
			],
			2,
		);
		expect(rows.map((row) => row.domain)).toEqual(['c.test', 'b.test']);
	});
});

describe('answer sources', () => {
	it('lists non-empty sources largest first with shares', () => {
		expect(answerSourceRows({ recursion: 1, cache: 3, empty: 0 })).toEqual([
			{ source: 'cache', count: 3, share: 0.75 },
			{ source: 'recursion', count: 1, share: 0.25 },
		]);
	});

	it('names known sources and keeps unknown identifiers as they are', () => {
		expect(answerSourceLabel('filter_block')).toBe('Filter');
		expect(answerSourceLabel('listener_ddr')).toBe('listener_ddr');
	});
});
