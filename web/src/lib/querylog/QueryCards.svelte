<script lang="ts">
	import { resolve } from '$app/paths';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import Icon from '$lib/components/Icon.svelte';
	import StatusMark from './StatusMark.svelte';
	import Value from './Value.svelte';
	import type { QueryRecord } from '$lib/api/query-log';
	import { unicodeName } from './domain-display';
	import { neutralize } from '$lib/safe-text';
	import { formatDateTime } from '$lib/format';
	import { getLocale } from '$lib/i18n/locale';
	import { statusOf, statusStyle } from './view';
	import { m } from '$lib/paraglide/messages';

	interface Props {
		rows: QueryRecord[];
	}

	let { rows }: Props = $props();
	const locale = getLocale();
</script>

<GroupedList>
	{#each rows as record (record.id)}
		{@const style = statusStyle(statusOf(record))}
		{@const unicode = unicodeName(record.query.name)}
		<a class="card" href={resolve('/query-log/[id]', { id: record.id })}>
			<span class="top">
				<StatusMark icon={style.icon} tone={style.tone} label={style.label} />
				<span class="time mono">{formatDateTime(new Date(record.time), locale)}</span>
			</span>
			<span class="domain mono"><Value value={unicode} mono /></span>
			<span class="meta">
				<span>{record.client?.display_name ?? record.client_id ?? record.source_ip}</span>
				<span class="mono">{record.query.type} · {record.protocol}</span>
			</span>
			<span class="chev" aria-hidden="true"><Icon name="chevron-right" size="1rem" /></span>
			<span class="sr-only">{m.querylog_open_row({ domain: neutralize(unicode) })}</span>
		</a>
	{/each}
</GroupedList>

<style>
	.card {
		position: relative;
		display: grid;
		grid-template-columns: minmax(0, 1fr) auto;
		gap: 0.25rem 0.75rem;
		min-height: 2.75rem;
		padding: 0.75rem 2.25rem 0.75rem 1rem;
		color: var(--label);
		text-decoration: none;
	}

	.card:hover {
		background: var(--surface-2);
	}

	.top {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 0.5rem;
		grid-column: 1 / -1;
		min-width: 0;
	}

	.time {
		font-size: 0.75rem;
		color: var(--label-2);
		white-space: nowrap;
	}

	.domain {
		min-width: 0;
		font-size: 0.9375rem;
		overflow-wrap: anywhere;
	}

	.meta {
		display: flex;
		flex-direction: column;
		min-width: 0;
		font-size: 0.8125rem;
		color: var(--label-2);
		overflow-wrap: anywhere;
	}

	.mono {
		font-family: var(--font-mono);
	}

	.chev {
		position: absolute;
		inset-inline-end: 0.75rem;
		top: 50%;
		transform: translateY(-50%);
		color: var(--label-3);
	}
</style>
