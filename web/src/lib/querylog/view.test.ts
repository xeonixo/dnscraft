import { describe, expect, it } from 'vitest';
import type { DecisionStep, QueryRecord } from '$lib/api/query-log';
import { m } from '$lib/paraglide/messages';
import {
	dnssecLabel,
	statusOf,
	stageLabel,
	stepDetail,
	trackerCategoryLabel,
	verdictLabel,
	verdictStyle,
} from './view';

const base = { filter: null, rcode: 'NOERROR', dnssec: 'secure' } as const;

describe('statusOf', () => {
	it('derives the outcome the way the server does', () => {
		expect(statusOf(base)).toBe('allowed');
		expect(
			statusOf({
				...base,
				filter: {
					reason: 'list',
					block_mode: 'nxdomain',
					rule_text: '||ads^',
					list_id: 'l',
					important: false,
				},
			}),
		).toBe('blocked');
		expect(statusOf({ ...base, rcode: 'SERVFAIL' })).toBe('servfail');
		expect(statusOf({ ...base, dnssec: 'bogus' })).toBe('dnssec_bogus');
	});

	it('does not call a filter hit without a block mode blocked', () => {
		const hit = {
			reason: 'temporary_allow',
			block_mode: null,
			rule_text: null,
			list_id: null,
			important: false,
		};
		expect(statusOf({ ...base, filter: hit })).toBe('allowed');
	});
});

describe('labels', () => {
	it('translates known stages and verdicts and keeps unknown identifiers', () => {
		expect(stageLabel('filter_qname')).toBe(m.querylog_stage_filter_qname());
		expect(stageLabel('future_stage')).toBe('future_stage');
		expect(verdictLabel('nxdomain')).toBe(m.querylog_verdict_nxdomain());
		expect(verdictLabel('future_verdict')).toBe('future_verdict');
	});

	it('pairs blocking verdicts with the danger tone and an icon', () => {
		expect(verdictStyle('blocked')).toEqual({ tone: 'danger', icon: 'ban' });
		expect(verdictStyle('answered')).toEqual({ tone: 'ok', icon: 'check-circle' });
	});

	it('reports a missing DNSSEC status as not checked', () => {
		expect(dnssecLabel(null)).toBe(m.querylog_not_checked());
		expect(dnssecLabel('bogus')).toBe(m.querylog_dnssec_bogus());
	});
});

describe('stepDetail', () => {
	const step = (value: Partial<DecisionStep>): DecisionStep =>
		({ stage: 'x', verdict: 'y', ...value }) as DecisionStep;

	it('shows the source of a resolution and the cause of a failed one', () => {
		expect(stepDetail(step({ stage: 'resolve', verdict: 'resolved', source: 'cache' }))).toEqual({
			text: m.querylog_step_from({ source: 'Cache' }),
			mono: false,
		});
		expect(
			stepDetail(step({ stage: 'resolve', verdict: 'failed', cause_code: 'timeout' })),
		).toEqual({ text: m.querylog_step_error({ code: 'timeout' }), mono: true });
	});

	it('returns nothing for a step without a useful value', () => {
		expect(stepDetail(step({ stage: 'bypass', verdict: 'answered' }))).toBeNull();
	});
});

describe('record shape used in tests', () => {
	it('accepts the documented base fields', () => {
		const record: Pick<QueryRecord, 'filter' | 'rcode' | 'dnssec'> = base;
		expect(record.rcode).toBe('NOERROR');
	});
});

describe('trackerCategoryLabel', () => {
	it('translates known categories and echoes unknown ones', () => {
		expect(trackerCategoryLabel('advertising')).toBe(m.tracker_category_advertising());
		expect(trackerCategoryLabel('brand_new')).toBe('brand_new');
		expect(trackerCategoryLabel('constructor')).toBe('constructor');
	});
});
