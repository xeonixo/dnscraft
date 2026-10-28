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
	import { getQueryRecord, type QueryRecord, type TempAllowResult } from '$lib/api/query-log';
	import { settle, type Result } from '$lib/api/result';
	import AllowSheet from '$lib/querylog/AllowSheet.svelte';
	import DecisionSteps from '$lib/querylog/DecisionSteps.svelte';
	import FieldRow from '$lib/querylog/FieldRow.svelte';
	import StatusMark from '$lib/querylog/StatusMark.svelte';
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
	import { m } from '$lib/paraglide/messages';

	const locale = getLocale();
	const isAdmin = $derived(auth.role === 'admin');
	const id = $derived(page.params.id ?? '');

	let result = $state<Result<QueryRecord>>({ kind: 'loading' });
	let allowOpen = $state(false);
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

	function allowed(outcome: TempAllowResult): void {
		allowOpen = false;
		announce(
			m.querylog_allow_success({
				domain: outcome.domain,
				time: formatDateTime(new Date(outcome.expires_at), locale),
			}),
		);
	}
</script>

<div class="top-row">
	<a class="back" href={resolve('/query-log')}>
		<Icon name="chevron-right" size="1rem" />
		<span>{m.querylog_back()}</span>
	</a>
	{#if isAdmin && result.kind === 'ok'}
		<Button variant="primary" onclick={() => (allowOpen = true)}>{m.querylog_allow_action()}</Button
		>
	{/if}
</div>

{#if result.kind === 'ok'}
	{@const record = result.data}
	{@const style = statusStyle(statusOf(record))}
	{@const unicode = unicodeName(record.query.name)}
	<GroupedList>
		<FieldRow label={m.querylog_col_domain()} value={unicode} mono />
		{#if unicode !== record.query.name}
			<FieldRow label={m.querylog_row_domain_ascii()} value={record.query.name} mono />
		{/if}
		<FieldRow label={m.querylog_col_status()}>
			<StatusMark icon={style.icon} tone={style.tone} label={style.label} />
		</FieldRow>
		<FieldRow label={m.querylog_row_time()} value={formatDateTime(new Date(record.time), locale)} />
		<FieldRow label={m.querylog_row_rcode()} value={record.rcode} mono />
		<FieldRow
			label={m.querylog_row_answer_size()}
			value={formatNumber(record.answer_size, locale)}
		/>
	</GroupedList>

	<GroupedList header={m.querylog_section_decision()} footer={m.querylog_steps_footer()}>
		<DecisionSteps steps={record.steps} />
	</GroupedList>

	{#if record.filter}
		<GroupedList header={m.querylog_section_rule()}>
			<FieldRow label={m.querylog_row_provenance()} value={provenanceLabel(record.filter.reason)} />
			<FieldRow
				label={m.querylog_row_block_mode()}
				value={record.filter.block_mode ?? m.querylog_none()}
				mono
			/>
			<FieldRow
				label={m.querylog_row_rule()}
				value={record.filter.rule_text ?? m.querylog_none()}
				mono
			/>
			<FieldRow
				label={m.querylog_row_list()}
				value={record.filter.list_id ?? m.querylog_none()}
				mono
			/>
			<FieldRow
				label={m.querylog_row_important()}
				value={record.filter.important ? m.querylog_yes() : m.querylog_no()}
			/>
		</GroupedList>
	{/if}

	<GroupedList header={m.querylog_section_details()}>
		<FieldRow label={m.querylog_row_selection()} value={selectionLabel(record.selection)} />
		<FieldRow label={m.querylog_row_answer_source()} value={answerLabel(record.answer_source)} />
		<FieldRow label={m.querylog_row_dnssec()} value={dnssecLabel(record.dnssec)} />
		<FieldRow
			label={m.querylog_row_forward_zone()}
			value={record.forward_zone ?? m.querylog_none()}
			mono
		/>
		<FieldRow label={m.querylog_row_view()} value={record.view_id} mono />
		<FieldRow label={m.querylog_row_profile()} value={record.profile_id} mono />
		{#if record.filter_set}
			<FieldRow label={m.querylog_row_filter_set()} value={record.filter_set} mono />
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
			<FieldRow label={m.querylog_section_device()} value={record.client.display_name} />
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

	{#if allowOpen}
		<AllowSheet
			domain={record.query.name}
			filterSet={record.filter_set}
			onclose={() => (allowOpen = false)}
			onallowed={allowed}
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
</style>
