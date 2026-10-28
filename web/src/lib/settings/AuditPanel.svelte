<script lang="ts">
	import { onMount } from 'svelte';
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import UnavailableNotice from '$lib/components/UnavailableNotice.svelte';
	import Sheet from '$lib/components/Sheet.svelte';
	import { listAudit, type AuditRow } from '$lib/api/audit';
	import { settle, type Result } from '$lib/api/result';
	import { displayText } from '$lib/safe-text';
	import { formatDateTime } from '$lib/format';
	import { getLocale } from '$lib/i18n/locale';
	import { m } from '$lib/paraglide/messages';

	interface Props {
		isAdmin: boolean;
	}

	let { isAdmin }: Props = $props();

	const locale = getLocale();
	let result = $state<Result<AuditRow[]>>({ kind: 'loading' });
	let search = $state('');
	let detail = $state<AuditRow | null>(null);

	const filtered = $derived.by(() => {
		if (result.kind !== 'ok') return [];
		const needle = search.trim().toLowerCase();
		if (!needle) return result.data;
		return result.data.filter(
			(row) =>
				row.action.toLowerCase().includes(needle) ||
				row.actor_id.toLowerCase().includes(needle) ||
				(row.object_id ?? '').toLowerCase().includes(needle),
		);
	});

	async function load(): Promise<void> {
		if (!isAdmin) return;
		result = await settle(listAudit());
	}

	onMount(() => {
		void load();
	});

	function jsonBlock(value: unknown): string {
		if (value === null || value === undefined) return '—';
		try {
			return JSON.stringify(value, null, 2);
		} catch {
			return String(value);
		}
	}
</script>

{#if !isAdmin}
	<!-- Admin-only section hidden for viewers. -->
{:else if result.kind === 'loading'}
	<p class="state">{m.state_loading()}</p>
{:else if result.kind === 'unavailable'}
	<UnavailableNotice />
{:else if result.kind === 'error'}
	<ErrorNotice code={result.code} params={result.params} />
{:else}
	<label class="search-label" for="audit-search">{m.audit_search_label()}</label>
	<input
		id="audit-search"
		class="search field"
		bind:value={search}
		placeholder={m.audit_search_placeholder()}
	/>

	<GroupedList header={m.settings_group_audit()}>
		{#each filtered as row (row.id)}
			<GroupedRow
				label={displayText(row.action).text}
				detail={`${displayText(row.actor_id).text} · ${formatDateTime(new Date(row.time), locale)}`}
				detailMono
			>
				{#snippet trailing()}
					<Button onclick={() => (detail = row)}>{m.audit_detail()}</Button>
				{/snippet}
			</GroupedRow>
		{:else}
			<GroupedRow label={m.audit_empty()} />
		{/each}
	</GroupedList>
{/if}

{#if detail}
	<Sheet open={true} title={m.audit_detail_title()} onclose={() => (detail = null)}>
		<p class="meta mono">{displayText(detail.action).text} · {displayText(detail.actor_id).text}</p>
		<p class="section-label">{m.audit_before()}</p>
		<pre class="mono block">{jsonBlock(detail.before)}</pre>
		<p class="section-label">{m.audit_after()}</p>
		<pre class="mono block">{jsonBlock(detail.after)}</pre>
		<div class="actions">
			<Button onclick={() => (detail = null)}>{m.action_close()}</Button>
		</div>
	</Sheet>
{/if}

<style>
	.state {
		margin: 0;
		color: var(--label-2);
	}

	.search-label {
		display: block;
		margin-bottom: 0.375rem;
		font-size: 0.84375rem;
		color: var(--label-2);
	}

	.search {
		width: 100%;
		max-width: 24rem;
		min-height: 2.75rem;
		margin-bottom: 1rem;
		padding: 0.5rem 0.75rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-control);
		background: var(--surface);
	}

	.meta {
		margin: 0 0 1rem;
		font-size: 0.84375rem;
		color: var(--label-2);
		overflow-wrap: anywhere;
	}

	.section-label {
		margin: 0.75rem 0 0.375rem;
		font-size: 0.78125rem;
		font-weight: 600;
		letter-spacing: 0.04em;
		text-transform: uppercase;
		color: var(--label-2);
	}

	.block {
		margin: 0;
		padding: 0.75rem;
		overflow-x: auto;
		font-size: 0.8125rem;
		background: var(--surface-2);
		border-radius: var(--r-control);
		white-space: pre-wrap;
		overflow-wrap: anywhere;
	}

	.actions {
		display: flex;
		justify-content: flex-end;
		margin-top: 1rem;
	}
</style>
