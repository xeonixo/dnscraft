<script lang="ts">
	import { resolve } from '$app/paths';
	import Value from './Value.svelte';
	import StatusMark from './StatusMark.svelte';
	import { answersOf, type QueryRecord } from '$lib/api/query-log';
	import { unicodeName } from './domain-display';
	import { displayText, neutralize } from '$lib/safe-text';
	import {
		answerLabel,
		answerSummary,
		dnssecLabel,
		microsToMilliseconds,
		provenanceLabel,
		statusOf,
		statusStyle,
		stepDetail,
	} from './view';
	import {
		formatBytes,
		formatDateTime,
		formatDay,
		formatMilliseconds,
		formatTime,
	} from '$lib/format';
	import { getLocale } from '$lib/i18n/locale';
	import { m } from '$lib/paraglide/messages';

	interface Props {
		rows: QueryRecord[];
		compact: boolean;
		/** Protocol, answer code and latency columns; off by default. */
		technical: boolean;
		/** Query string that filters the list by a client id; without it the name is plain text. */
		clientSearch?: (clientId: string) => string;
	}

	let { rows, compact, technical, clientSearch }: Props = $props();
	const locale = getLocale();
	const day = (iso: string) => formatDay(new Date(iso), locale);

	// One floating card for the hovered or focused domain. It is positioned from the link's box so
	// the scrolling table container cannot clip it.
	let tip = $state<{ record: QueryRecord; left: number; top: number; above: boolean } | null>(null);

	function showTip(record: QueryRecord, element: HTMLElement): void {
		const box = element.getBoundingClientRect();
		const above = window.innerHeight - box.bottom < 220;
		tip = {
			record,
			left: Math.max(8, Math.min(box.left, window.innerWidth - 320)),
			top: above ? box.top : box.bottom,
			above,
		};
	}

	function hideTip(): void {
		tip = null;
	}
	/** Time, domain, client and status, plus the answer and latency columns when shown. */
	const columnCount = $derived(technical ? 6 : 4);
</script>

<div class="inset" class:compact>
	<table>
		<caption class="sr-only">{m.querylog_table_label()}</caption>
		<thead>
			<tr>
				<th scope="col">{m.querylog_col_time()}</th>
				<th scope="col">{m.querylog_col_domain()}</th>
				<th scope="col">{m.querylog_col_client()}</th>
				<th scope="col">{m.querylog_col_status()}</th>
				{#if technical}
					<th scope="col">{m.querylog_col_answer()}</th>
					<th scope="col" class="end">{m.querylog_col_latency()}</th>
				{/if}
			</tr>
		</thead>
		<tbody>
			{#each rows as record, i (record.id)}
				{@const status = statusOf(record)}
				{@const style = statusStyle(status)}
				{@const unicode = unicodeName(record.query.name)}
				{@const clientName = record.client?.display_name ?? record.client_id ?? record.source_ip}
				{@const answers = answerSummary(answersOf(record))}
				{#if i === 0 || day(record.time) !== day(rows[i - 1].time)}
					<tr class="day">
						<th scope="colgroup" colspan={columnCount}>{day(record.time)}</th>
					</tr>
				{/if}
				<tr>
					<td class="time mono">
						<time datetime={record.time} title={formatDateTime(new Date(record.time), locale)}
							>{formatTime(new Date(record.time), locale)}</time
						>
					</td>
					<td class="domain">
						<a
							class="name"
							href={resolve('/query-log/[id]', { id: record.id })}
							aria-label={m.querylog_open_row({ domain: neutralize(unicode) })}
							aria-describedby={tip?.record.id === record.id ? 'query-tip' : undefined}
							onmouseenter={(event) => showTip(record, event.currentTarget)}
							onmouseleave={hideTip}
							onfocus={(event) => showTip(record, event.currentTarget)}
							onblur={hideTip}
						>
							<Value value={unicode} mono />
						</a>
						<span class="sub mono"
							>{record.query.type}{#if unicode !== record.query.name}<span class="alias"
									><Value value={record.query.name} mono /></span
								>{/if}</span
						>
						{#if answers !== ''}
							<span class="sub answers mono">{displayText(answers, 80).text}</span>
						{/if}
					</td>
					<td class="client">
						<span class="cname">
							{#if clientSearch && record.client_id}
								<a
									class="client-link"
									href={resolve(`/query-log?${clientSearch(record.client_id)}`)}
									title={neutralize(clientName)}
									aria-label={m.querylog_filter_by_client({ client: neutralize(clientName) })}
									>{displayText(clientName, 32).text}</a
								>
							{:else}
								<Value value={clientName} limit={32} />
							{/if}
						</span>
						<span class="sub mono"
							><Value value={record.source_ip} mono /> · {record.protocol}{#if record.node_id}
								· <Value value={record.node_id} mono />{/if}</span
						>
					</td>
					<td>
						<StatusMark icon={style.icon} tone={style.tone} label={style.label} />
						{#if record.filter}
							<span class="sub">{provenanceLabel(record.filter.reason)}</span>
						{/if}
					</td>
					{#if technical}
						<td class="mono">{record.rcode}</td>
						<td class="end mono">
							{formatMilliseconds(microsToMilliseconds(record.timings.total_us), locale)}
							<span class="count">{formatBytes(record.answer_size, locale)}</span>
						</td>
					{/if}
				</tr>
			{/each}
		</tbody>
	</table>
</div>

{#if tip}
	{@const hit = tip.record}
	{@const resolved = hit.steps.find((step) => step.stage === 'resolve')}
	{@const from = resolved ? stepDetail(resolved)?.text : null}
	<div
		id="query-tip"
		role="tooltip"
		class="tip"
		class:above={tip.above}
		style:left="{tip.left}px"
		style:top="{tip.top}px"
	>
		<dl>
			{#if hit.node_id}
				<dt>{m.querylog_row_node()}</dt>
				<dd class="mono">{hit.node_id}</dd>
			{/if}
			<dt>{m.querylog_row_rcode()}</dt>
			<dd class="mono">{hit.rcode}</dd>
			<dt>{m.querylog_row_answer_source()}</dt>
			<dd>
				{answerLabel(hit.answer_source)}{#if from}<span class="muted"> · {from}</span>{/if}
			</dd>
			<dt>{m.querylog_row_dnssec()}</dt>
			<dd>{dnssecLabel(hit.dnssec)}</dd>
			<dt>{m.querylog_summary_latency()}</dt>
			<dd>
				{formatMilliseconds(microsToMilliseconds(hit.timings.total_us), locale)}<span class="muted">
					· {formatBytes(hit.answer_size, locale)}</span
				>
			</dd>
			{#if hit.filter}
				<dt>{m.querylog_row_rule()}</dt>
				<dd>
					{provenanceLabel(hit.filter.reason)}
					{#if hit.filter.rule_text}<span class="mono rule"
							>{displayText(hit.filter.rule_text, 60).text}</span
						>{/if}
				</dd>
			{/if}
		</dl>
	</div>
{/if}

<style>
	.inset {
		overflow-x: auto;
		background: var(--surface);
		border: 1px solid var(--separator);
		border-radius: var(--r-card);
		box-shadow: var(--shadow);
	}

	table {
		width: 100%;
		border-collapse: collapse;
		font-size: 0.875rem;
	}

	th,
	td {
		padding: 0.5rem 0.75rem;
		text-align: start;
		vertical-align: top;
		min-width: 0;
	}

	th {
		padding-top: 0.625rem;
		font-size: 0.75rem;
		font-weight: 500;
		color: var(--label-2);
		white-space: nowrap;
	}

	tbody tr + tr {
		border-top: 1px solid var(--separator);
	}

	tbody tr:hover {
		background: var(--surface-2);
	}

	td {
		min-height: 2.75rem;
		color: var(--label);
	}

	.compact td {
		padding-top: 0.25rem;
		padding-bottom: 0.25rem;
	}

	.time {
		white-space: nowrap;
		color: var(--label-2);
	}

	.mono {
		font-family: var(--font-mono);
		font-size: 0.8125rem;
	}

	.domain {
		min-width: 12rem;
	}

	.client {
		min-width: 9rem;
	}

	.client-link {
		display: inline-block;
		padding-block: 0.125rem;
		overflow-wrap: anywhere;
		color: var(--label);
		text-decoration: none;
	}

	.client-link:hover {
		color: var(--accent);
		text-decoration: underline;
	}

	tbody tr.day {
		border-top: 0;
		background: var(--surface-2);
	}

	tbody tr.day:hover {
		background: var(--surface-2);
	}

	tr.day th {
		padding-block: 0.375rem;
		font-size: 0.75rem;
		color: var(--label-2);
	}

	.name {
		display: inline-block;
		padding-block: 0.125rem;
		color: var(--label);
		text-decoration: none;
	}

	.name:hover {
		text-decoration: underline;
	}

	/* Query type as a muted tag on the domain's line. */
	/* The resolved answer under the query type, one line; the full set is on the detail page. */
	.answers {
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.alias::before {
		content: '\00a0·\00a0';
	}

	.sub {
		display: block;
		font-size: 0.75rem;
		color: var(--label-2);
		overflow-wrap: anywhere;
	}

	.cname {
		display: block;
		overflow-wrap: anywhere;
	}

	.end {
		text-align: end;
		white-space: nowrap;
	}

	.count {
		display: block;
		font-size: 0.75rem;
		color: var(--label-3);
	}

	.tip {
		position: fixed;
		z-index: 50;
		box-sizing: border-box;
		width: 20rem;
		max-width: calc(100vw - 1rem);
		margin-top: 0.25rem;
		padding: var(--space-3);
		background: var(--surface);
		border: 1px solid var(--separator);
		border-radius: var(--r-card);
		box-shadow: var(--shadow);
		font-size: 0.8125rem;
		pointer-events: none;
	}

	.tip.above {
		margin-top: 0;
		margin-bottom: 0.25rem;
		transform: translateY(-100%);
	}

	.tip dl {
		display: grid;
		grid-template-columns: max-content minmax(0, 1fr);
		gap: 0.25rem var(--space-3);
		margin: 0;
	}

	.tip dt {
		color: var(--label-2);
	}

	.tip dd {
		margin: 0;
		overflow-wrap: anywhere;
	}

	.tip .muted {
		color: var(--label-2);
	}

	.tip .rule {
		display: block;
		color: var(--label-2);
	}
</style>
