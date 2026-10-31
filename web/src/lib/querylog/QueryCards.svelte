<script lang="ts">
	import { resolve } from '$app/paths';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import Icon from '$lib/components/Icon.svelte';
	import StatusMark from './StatusMark.svelte';
	import Value from './Value.svelte';
	import { answersOf, type QueryRecord } from '$lib/api/query-log';
	import { unicodeName } from './domain-display';
	import { displayText, neutralize } from '$lib/safe-text';
	import { formatDateTime } from '$lib/format';
	import { getLocale } from '$lib/i18n/locale';
	import { answerSummary, statusOf, statusStyle } from './view';
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
		{@const answers = answerSummary(answersOf(record))}
		<a class="card" href={resolve('/query-log/[id]', { id: record.id })}>
			<span class="top">
				<StatusMark icon={style.icon} tone={style.tone} label={style.label} />
				<span class="time mono">{formatDateTime(new Date(record.time), locale)}</span>
			</span>
			<span class="domain mono"><Value value={unicode} mono /></span>
			{#if answers !== ''}
				<span class="answers mono">{displayText(answers, 80).text}</span>
			{/if}
			<span class="meta">
				<span class="client"
					>{displayText(record.client?.display_name ?? record.client_id ?? record.source_ip, 32)
						.text}</span
				>
				<span class="mono"
					>{record.query.type} · {record.protocol}{#if record.node_id}
						· {record.node_id}{/if}</span
				>
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
		grid-template-columns: minmax(0, 1fr);
		gap: 0.1875rem;
		min-height: 2.75rem;
		padding: 0.5rem 2.25rem 0.5rem 1rem;
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

	/* Client on the left, type and protocol right-aligned under the time, so both edges line up. */
	/* Resolved answer on one line under the domain; the full set is on the detail page. */
	.answers {
		min-width: 0;
		overflow: hidden;
		font-size: 0.8125rem;
		color: var(--label-2);
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.meta {
		display: flex;
		align-items: baseline;
		justify-content: space-between;
		gap: 0.5rem;
		min-width: 0;
		font-size: 0.8125rem;
		color: var(--label-2);
		overflow-wrap: anywhere;
	}

	.client {
		min-width: 0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.meta > span:last-child {
		flex: 0 0 auto;
		text-align: end;
	}

	@media (max-width: 54.99rem) {
		.card {
			gap: 0.0625rem;
			padding-block: 0.375rem;
		}

		.domain {
			font-size: 0.8125rem;
		}

		.time,
		.answers,
		.meta {
			font-size: 0.6875rem;
		}
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
