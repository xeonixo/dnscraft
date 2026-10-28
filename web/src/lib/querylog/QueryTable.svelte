<script lang="ts">
	import { resolve } from '$app/paths';
	import Value from './Value.svelte';
	import StatusMark from './StatusMark.svelte';
	import type { QueryRecord } from '$lib/api/query-log';
	import { unicodeName } from './domain-display';
	import { neutralize } from '$lib/safe-text';
	import { provenanceLabel, microsToMilliseconds, statusOf, statusStyle } from './view';
	import { formatBytes, formatDateTime, formatMilliseconds } from '$lib/format';
	import { getLocale } from '$lib/i18n/locale';
	import { m } from '$lib/paraglide/messages';

	interface Props {
		rows: QueryRecord[];
		compact: boolean;
	}

	let { rows, compact }: Props = $props();
	const locale = getLocale();
</script>

<div class="inset" class:compact>
	<table>
		<caption class="sr-only">{m.querylog_table_label()}</caption>
		<thead>
			<tr>
				<th scope="col">{m.querylog_col_time()}</th>
				<th scope="col">{m.querylog_col_domain()}</th>
				<th scope="col">{m.querylog_col_type()}</th>
				<th scope="col">{m.querylog_col_client()}</th>
				<th scope="col">{m.querylog_col_protocol()}</th>
				<th scope="col">{m.querylog_col_status()}</th>
				<th scope="col">{m.querylog_col_answer()}</th>
				<th scope="col" class="end">{m.querylog_col_latency()}</th>
			</tr>
		</thead>
		<tbody>
			{#each rows as record (record.id)}
				{@const status = statusOf(record)}
				{@const style = statusStyle(status)}
				{@const unicode = unicodeName(record.query.name)}
				<tr>
					<td class="time mono">{formatDateTime(new Date(record.time), locale)}</td>
					<td class="domain">
						<a
							class="name"
							href={resolve('/query-log/[id]', { id: record.id })}
							aria-label={m.querylog_open_row({ domain: neutralize(unicode) })}
						>
							<Value value={unicode} mono />
						</a>
						{#if unicode !== record.query.name}
							<span class="sub mono"><Value value={record.query.name} mono /></span>
						{/if}
						{#if record.filter}
							<span class="sub">{provenanceLabel(record.filter.reason)}</span>
						{/if}
					</td>
					<td class="mono">{record.query.type}</td>
					<td class="client">
						<span class="cname">
							<Value value={record.client?.display_name ?? record.client_id ?? record.source_ip} />
						</span>
						<span class="sub mono"><Value value={record.source_ip} mono /></span>
					</td>
					<td class="mono">{record.protocol}</td>
					<td><StatusMark icon={style.icon} tone={style.tone} label={style.label} /></td>
					<td class="mono">{record.rcode}</td>
					<td class="end mono">
						{formatMilliseconds(microsToMilliseconds(record.timings.total_us), locale)}
						<span class="count">{formatBytes(record.answer_size, locale)}</span>
					</td>
				</tr>
			{/each}
		</tbody>
	</table>
</div>

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

	.name {
		display: inline-flex;
		align-items: center;
		min-height: 2.75rem;
		color: var(--label);
		text-decoration: none;
	}

	.name:hover {
		text-decoration: underline;
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
</style>
