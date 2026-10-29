<script lang="ts">
	import { page } from '$app/state';
	import { resolve } from '$app/paths';
	import Button from '$lib/components/Button.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import Icon from '$lib/components/Icon.svelte';
	import ResultNotice from '$lib/components/ResultNotice.svelte';
	import { announce } from '$lib/live.svelte';
	import { auth } from '$lib/auth/state.svelte';
	import { answersOf, getQueryRecord, type QueryRecord } from '$lib/api/query-log';
	import { settle, type Result } from '$lib/api/result';
	import DecisionSteps from '$lib/querylog/DecisionSteps.svelte';
	import FieldRow from '$lib/querylog/FieldRow.svelte';
	import RuleSheet from '$lib/querylog/RuleSheet.svelte';
	import StatusMark from '$lib/querylog/StatusMark.svelte';
	import Value from '$lib/querylog/Value.svelte';
	import { defaultRuleAction, type RuleOutcome } from '$lib/querylog/rule-write';
	import { unicodeName } from '$lib/querylog/domain-display';
	import {
		answerLabel,
		dnssecLabel,
		microsToMilliseconds,
		provenanceLabel,
		selectionLabel,
		statusOf,
		statusStyle,
	} from '$lib/querylog/view';
	import { formatDateTime, formatMilliseconds, formatNumber } from '$lib/format';
	import { getLocale } from '$lib/i18n/locale';
	import { domainLabel } from '$lib/policy/display';
	import { m } from '$lib/paraglide/messages';
	import { displayText, FULL_LIMIT } from '$lib/safe-text';

	const locale = getLocale();
	const isAdmin = $derived(auth.role === 'admin');
	const id = $derived(page.params.id ?? '');

	let result = $state<Result<QueryRecord>>({ kind: 'loading' });
	let ruleOpen = $state(false);
	let outcome = $state<RuleOutcome | null>(null);
	let runs = 0;

	async function load(recordId: string): Promise<void> {
		const run = ++runs;
		const next = await settle(getQueryRecord(recordId));
		if (run === runs) result = next;
	}

	$effect(() => {
		const current = id;
		void load(current);
	});

	function openRule(): void {
		outcome = null;
		ruleOpen = true;
	}

	function saved(next: RuleOutcome): void {
		ruleOpen = false;
		outcome = next;
		const text =
			next.kind === 'temporary'
				? m.querylog_allow_success({
						domain: next.result.domain,
						time: formatDateTime(new Date(next.result.expires_at), locale),
					})
				: outcomeText(next);
		announce(text);
	}

	function outcomeText(next: Extract<RuleOutcome, { kind: 'permanent' }>): string {
		const params = { rule: next.result.ruleText, set: next.result.filterSetName };
		return next.result.status === 'exists'
			? m.querylog_rule_exists(params)
			: m.querylog_rule_saved(params);
	}
</script>

<div class="top-row">
	<a class="back" href={resolve('/query-log')}>
		<Icon name="chevron-right" size="1rem" />
		<span>{m.querylog_back()}</span>
	</a>
	{#if isAdmin && result.kind === 'ok'}
		<Button variant="primary" onclick={openRule}>{m.querylog_rule_create()}</Button>
	{/if}
</div>

{#if outcome}
	<p class="outcome">
		{#if outcome.kind === 'temporary'}
			{m.querylog_allow_success({
				domain: outcome.result.domain,
				time: formatDateTime(new Date(outcome.result.expires_at), locale),
			})}
		{:else}
			{outcomeText(outcome)}
			<a class="link" href={resolve('/filter-sets')}>{m.querylog_rule_view()}</a>
		{/if}
	</p>
{/if}

{#if result.kind === 'ok'}
	{@const record = result.data}
	{@const answers = answersOf(record)}
	{@const style = statusStyle(statusOf(record))}
	{@const unicode = unicodeName(record.query.name)}
	{@const device = record.client?.display_name ?? record.client_id ?? record.source_ip}
	<div class="detail">
		<header class="head">
			<div class="title-row">
				<h2 class="domain"><Value value={unicode} limit={FULL_LIMIT} /></h2>
				<StatusMark icon={style.icon} tone={style.tone} label={style.label} />
			</div>
			{#if unicode !== record.query.name}
				<p class="ascii"><Value value={record.query.name} mono limit={FULL_LIMIT} /></p>
			{/if}
			<p class="meta">
				<span class="item">{record.query.type}</span>
				<a class="item link" href={resolve('/clients')}>{displayText(device, 60).text}</a>
				<span class="item">{formatDateTime(new Date(record.time), locale)}</span>
				<span class="item"
					>{record.filter
						? displayText(provenanceLabel(record.filter.reason), 60).text
						: m.querylog_meta_no_rule()}</span
				>
			</p>
		</header>

		<div class="columns">
			<div class="column">
				<GroupedList header={m.querylog_section_decision()} footer={m.querylog_steps_footer()}>
					<DecisionSteps steps={record.steps} />
				</GroupedList>

				{#if record.filter}
					<GroupedList header={m.querylog_section_rule()}>
						<FieldRow label={m.querylog_row_rule()}>
							<Value value={record.filter.rule_text ?? m.querylog_none()} mono oneLine />
						</FieldRow>
						<FieldRow
							label={m.querylog_row_block_mode()}
							value={record.filter.block_mode ?? m.querylog_none()}
							mono
						/>
						{#if record.filter.list_id !== null}
							<FieldRow label={m.querylog_row_list()}>
								<a class="link" href={resolve('/filter-lists')}>
									<Value value={record.filter.list_id} mono />
								</a>
							</FieldRow>
						{/if}
						<FieldRow
							label={m.querylog_row_important()}
							value={record.filter.important ? m.querylog_yes() : m.querylog_no()}
						/>
					</GroupedList>
				{/if}

				{#if answers.length > 0}
					<GroupedList header={m.query_log_answers_title()}>
						{#each answers as answer}
							<div class="answer">
								<span class="type">{answer.type}</span>
								<div class="data">
									<Value value={answer.data} mono />
								</div>
								<span class="ttl">
									{m.query_log_answer_ttl({ ttl: formatNumber(answer.ttl, locale) })}
								</span>
							</div>
						{/each}
					</GroupedList>
				{/if}
			</div>

			<div class="column">
				<GroupedList header={m.querylog_section_details()}>
					<FieldRow label={m.querylog_row_rcode()} value={record.rcode} mono />
					<FieldRow label={m.querylog_row_selection()} value={selectionLabel(record.selection)} />
					<FieldRow
						label={m.querylog_row_answer_source()}
						value={answerLabel(record.answer_source)}
					/>
					<FieldRow label={m.querylog_row_dnssec()} value={dnssecLabel(record.dnssec)} />
					<FieldRow
						label={m.querylog_row_forward_zone()}
						value={record.forward_zone ? domainLabel(record.forward_zone) : m.querylog_none()}
						mono
					/>
					<FieldRow label={m.querylog_row_view()} value={record.view_id} mono />
					<FieldRow label={m.querylog_row_profile()} value={record.profile_id} mono />
					{#if record.filter_set}
						<FieldRow label={m.querylog_row_filter_set()}>
							<a class="link" href={resolve('/filter-sets')}>
								<Value value={record.filter_set} mono />
							</a>
						</FieldRow>
					{/if}
					<FieldRow label={m.querylog_row_protocol()} value={record.protocol} mono />
					<FieldRow label={m.querylog_row_listener()} value={record.listener_id} mono />
					<FieldRow label={m.querylog_row_node()} value={record.node_id} mono />
				</GroupedList>

				<GroupedList header={m.querylog_section_device()}>
					<FieldRow label={m.querylog_row_source_ip()} value={record.source_ip} mono />
					<FieldRow
						label={m.querylog_row_client_id()}
						value={record.client_id ?? m.querylog_none()}
						mono
					/>
					{#if record.client}
						<FieldRow label={m.querylog_row_client_source()} value={record.client.source} />
						{#if record.client.macs.length > 0}
							<FieldRow label={m.querylog_row_macs()} value={record.client.macs.join(', ')} mono />
						{/if}
						{#if record.client.vlan_name !== null}
							<FieldRow label={m.querylog_row_vlan()} value={record.client.vlan_name} />
						{/if}
					{/if}
				</GroupedList>

				<GroupedList header={m.querylog_section_timing()}>
					<FieldRow
						label={m.querylog_timing_select()}
						value={formatMilliseconds(microsToMilliseconds(record.timings.select_us), locale)}
						mono
					/>
					<FieldRow
						label={m.querylog_timing_filter()}
						value={formatMilliseconds(microsToMilliseconds(record.timings.filter_us), locale)}
						mono
					/>
					<FieldRow
						label={m.querylog_timing_resolve()}
						value={formatMilliseconds(microsToMilliseconds(record.timings.resolve_us), locale)}
						mono
					/>
					<FieldRow
						label={m.querylog_timing_total()}
						value={formatMilliseconds(microsToMilliseconds(record.timings.total_us), locale)}
						mono
					/>
				</GroupedList>
			</div>
		</div>
	</div>

	{#if ruleOpen}
		<RuleSheet
			domain={record.query.name}
			filterSet={record.filter_set}
			defaultAction={defaultRuleAction(statusOf(record))}
			onclose={() => (ruleOpen = false)}
			onsaved={saved}
		/>
	{/if}
{:else if result.kind === 'unavailable'}
	<GroupedList>
		<GroupedRow label={m.querylog_unavailable_title()} detail={m.querylog_unavailable_body()} />
	</GroupedList>
{:else}
	<ResultNotice {result} onretry={() => void load(id)} />
{/if}

<style>
	.top-row {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		justify-content: space-between;
		gap: 0.625rem;
	}

	.back {
		display: inline-flex;
		align-items: center;
		gap: 0.25rem;
		min-height: 2.75rem;
		color: var(--accent);
		text-decoration: none;
	}

	.back :global(svg) {
		transform: rotate(180deg);
	}

	.back:hover {
		text-decoration: underline;
	}

	/* Named container for the detail page: FieldRow switches its label column on the same query. */
	.detail {
		container: detail / inline-size;
		display: flex;
		flex-direction: column;
		gap: var(--gap-stack);
		min-width: 0;
	}

	.head {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
		padding: 0 0.25rem;
		min-width: 0;
	}

	.title-row {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 0.5rem 0.875rem;
		min-width: 0;
	}

	.domain {
		min-width: 0;
		margin: 0;
		font-size: 1.5rem;
		font-weight: 700;
		line-height: 1.2;
		color: var(--label);
	}

	@container detail (min-width: 56.25rem) {
		.domain {
			font-size: 1.875rem;
		}
	}

	.ascii {
		margin: 0;
		font-size: 0.875rem;
		color: var(--label-2);
	}

	.meta {
		margin: 0.125rem 0 0;
		font-size: 0.875rem;
		color: var(--label-2);
		overflow-wrap: anywhere;
	}

	.item + .item::before {
		content: '· ';
	}

	.columns {
		display: grid;
		gap: var(--gap-stack);
		grid-template-columns: minmax(0, 1fr);
		align-items: start;
	}

	@container detail (min-width: 56.25rem) {
		.columns {
			grid-template-columns: repeat(2, minmax(0, 1fr));
		}
	}

	.column {
		display: flex;
		flex-direction: column;
		gap: var(--gap-stack);
		min-width: 0;
	}

	.outcome {
		margin: 0;
		padding: 0 0.25rem;
		font-size: 0.875rem;
		color: var(--label-2);
		overflow-wrap: anywhere;
	}

	/* One answer per row: type, rdata, TTL. Wraps on narrow screens, the rdata gets the free width. */
	.answer {
		display: flex;
		flex-wrap: wrap;
		align-items: baseline;
		gap: 0.25rem 0.75rem;
		min-height: 2.75rem;
		padding: 0.625rem 1rem;
		color: var(--label);
	}

	.type {
		min-width: 4.5rem;
		font-family: var(--font-mono);
		font-size: 0.875rem;
		color: var(--label-2);
	}

	.data {
		flex: 1 1 12rem;
		min-width: 0;
		overflow-wrap: anywhere;
	}

	.ttl {
		font-size: 0.8125rem;
		color: var(--label-2);
		font-variant-numeric: tabular-nums;
	}

	.link {
		display: inline-flex;
		align-items: center;
		min-height: 2.75rem;
		max-width: 100%;
		color: var(--accent);
		text-decoration: none;
	}

	.link:hover {
		text-decoration: underline;
	}
</style>
