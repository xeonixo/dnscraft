<script lang="ts">
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import DecisionSteps from '$lib/querylog/DecisionSteps.svelte';
	import {
		parseTestQueryRecords,
		runTestQuery,
		type TestQueryResult,
	} from '$lib/api/policy';
	import { failureOf } from '$lib/api/result';
	import { answerLabel } from '$lib/querylog/view';
	import { m } from '$lib/paraglide/messages';

	let sourceIp = $state('192.0.2.10');
	let clientId = $state('');
	let domain = $state('www.example.com');
	let qtype = $state('A');
	let protocol = $state('udp53');
	let busy = $state(false);
	let failure = $state<{ code: string; params: Record<string, unknown> } | null>(null);
	let result = $state<TestQueryResult | null>(null);

	const qtypeOptions = $derived([
		{ value: 'A', label: m.test_query_type_a() },
		{ value: 'AAAA', label: m.test_query_type_aaaa() },
		{ value: 'CNAME', label: m.test_query_type_cname() },
	]);
	const protocolOptions = $derived([
		{ value: 'udp53', label: m.test_query_protocol_udp53() },
		{ value: 'tcp53', label: m.test_query_protocol_tcp53() },
		{ value: 'doh', label: m.test_query_protocol_doh() },
		{ value: 'dot', label: m.test_query_protocol_dot() },
		{ value: 'doq', label: m.test_query_protocol_doq() },
	]);

	const answerRcode = $derived(
		result?.answer?.rcode ?? (typeof result?.rcode === 'string' ? result.rcode : null),
	);
	const records = $derived(parseTestQueryRecords(result?.answer?.records));
	const filterHit = $derived.by(() => {
		const raw = result?.filter;
		if (!raw || typeof raw !== 'object') return null;
		const row = raw as Record<string, unknown>;
		return {
			rule: typeof row.rule === 'string' ? row.rule : typeof row.rule_text === 'string' ? row.rule_text : null,
			list: typeof row.list_id === 'string' ? row.list_id : null,
			mode: typeof row.block_mode === 'string' ? row.block_mode : null,
		};
	});

	function dash(value: unknown): string {
		if (value == null || value === '') return '—';
		return String(value);
	}

	function usLabel(value: number | undefined): string {
		if (value == null || !Number.isFinite(value)) return '—';
		if (value >= 1000) return `${(value / 1000).toFixed(value >= 10_000 ? 0 : 1)} ms`;
		return `${value} µs`;
	}

	async function submit(): Promise<void> {
		busy = true;
		failure = null;
		result = null;
		try {
			result = await runTestQuery({
				domain: domain.trim(),
				qtype,
				source_ip: sourceIp.trim(),
				protocol,
				...(clientId.trim() ? { client_id: clientId.trim() } : {}),
			});
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}
</script>

<p class="lead">{m.test_query_lead()}</p>

<form class="form" onsubmit={(event) => (event.preventDefault(), void submit())}>
	<label class="field-label" for="tq-ip">{m.test_query_source_ip()}</label>
	<input id="tq-ip" class="field mono" bind:value={sourceIp} required />
	<label class="field-label" for="tq-client">{m.test_query_client_id()}</label>
	<input id="tq-client" class="field mono" bind:value={clientId} />
	<label class="field-label" for="tq-name">{m.test_query_domain()}</label>
	<input id="tq-name" class="field mono" bind:value={domain} required />
	<label class="field-label" for="tq-type">{m.test_query_type()}</label>
	<select id="tq-type" class="field" bind:value={qtype}>
		{#each qtypeOptions as option (option.value)}
			<option value={option.value}>{option.label}</option>
		{/each}
	</select>
	<label class="field-label" for="tq-proto">{m.test_query_protocol()}</label>
	<select id="tq-proto" class="field" bind:value={protocol}>
		{#each protocolOptions as option (option.value)}
			<option value={option.value}>{option.label}</option>
		{/each}
	</select>
	<Button variant="primary" type="submit" disabled={busy}>{m.test_query_run()}</Button>
</form>

{#if failure}
	<ErrorNotice code={failure.code} params={failure.params} />
{/if}

{#if result}
	<div class="section-head">{m.test_query_summary()}</div>
	<GroupedList>
		<GroupedRow label={m.querylog_row_view()} detail={dash(result.view_id)} detailMono />
		<GroupedRow label={m.querylog_row_profile()} detail={dash(result.profile_id)} detailMono />
		{#if result.filter_set_id}
			<GroupedRow label={m.querylog_row_filter_set()} detail={dash(result.filter_set_id)} detailMono />
		{/if}
		{#if result.answer_source}
			<GroupedRow
				label={m.querylog_row_answer_source()}
				detail={answerLabel(String(result.answer_source))}
			/>
		{/if}
		{#if result.forward_zone}
			<GroupedRow label={m.querylog_row_forward_zone()} detail={dash(result.forward_zone)} detailMono />
		{/if}
		{#if result.client_id}
			<GroupedRow label={m.querylog_row_client_id()} detail={dash(result.client_id)} detailMono />
		{/if}
		{#if result.dnssec}
			<GroupedRow label={m.querylog_row_dnssec()} detail={dash(result.dnssec)} />
		{/if}
		{#if answerRcode}
			<GroupedRow label={m.querylog_row_rcode()} detail={answerRcode} detailMono />
		{/if}
	</GroupedList>

	{#if filterHit && (filterHit.rule || filterHit.list || filterHit.mode)}
		<div class="section-head">{m.querylog_row_rule()}</div>
		<GroupedList>
			{#if filterHit.rule}
				<GroupedRow label={m.querylog_row_rule()} detail={filterHit.rule} detailMono />
			{/if}
			{#if filterHit.list}
				<GroupedRow label={m.querylog_row_list()} detail={filterHit.list} detailMono />
			{/if}
			{#if filterHit.mode}
				<GroupedRow label={m.querylog_row_block_mode()} detail={filterHit.mode} />
			{/if}
		</GroupedList>
	{/if}

	<div class="section-head">{m.test_query_records()}</div>
	{#if records.length > 0}
		<GroupedList>
			{#each records as rec, index (`${rec.type}:${rec.name}:${rec.data}:${index}`)}
				<GroupedRow
					label={`${rec.type}${rec.name ? ` · ${rec.name}` : ''}`}
					detail={m.test_query_record_detail({ data: rec.data || '—', ttl: String(rec.ttl) })}
					detailMono
				/>
			{/each}
		</GroupedList>
	{:else}
		<p class="empty">{m.test_query_no_records()}</p>
	{/if}

	<div class="section-head">{m.test_query_steps()}</div>
	<div class="steps-panel">
		<DecisionSteps steps={result.steps ?? []} />
	</div>

	{#if result.timings}
		<div class="section-head">{m.querylog_section_timing()}</div>
		<GroupedList>
			<GroupedRow label={m.querylog_timing_select()} detail={usLabel(result.timings.select_us)} detailMono />
			<GroupedRow label={m.querylog_timing_filter()} detail={usLabel(result.timings.filter_us)} detailMono />
			<GroupedRow label={m.querylog_timing_resolve()} detail={usLabel(result.timings.resolve_us)} detailMono />
			<GroupedRow label={m.querylog_timing_total()} detail={usLabel(result.timings.total_us)} detailMono />
		</GroupedList>
	{/if}
{/if}

<p class="footnote">{m.test_query_footnote()}</p>

<style>
	.lead {
		margin: 0 0 1rem;
		color: var(--label-2);
	}
	.form {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
		max-width: 28rem;
		margin-bottom: 1rem;
	}
	.field-label {
		font-size: 0.8125rem;
		color: var(--label-2);
	}
	.field {
		min-height: 2.75rem;
		padding: 0.5rem 0.75rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		font: inherit;
		margin-bottom: 0.5rem;
	}
	.mono {
		font-family: var(--font-mono);
	}
	.section-head {
		margin: 1rem 0 0.5rem;
		font-size: 0.8125rem;
		font-weight: 600;
		color: var(--label-3);
		text-transform: uppercase;
	}
	.empty {
		margin: 0 0 0.5rem;
		font-size: 0.875rem;
		color: var(--label-2);
	}
	.footnote {
		margin-top: 0.75rem;
		font-size: 0.8125rem;
		color: var(--label-3);
	}

	.steps-panel {
		overflow: hidden;
		background: var(--surface);
		border: 1px solid var(--separator);
		border-radius: var(--r-card);
		box-shadow: var(--shadow);
	}
</style>
