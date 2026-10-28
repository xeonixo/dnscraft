<script lang="ts">
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import { API_CATALOG, type ApiCatalogEntry } from '$lib/api/catalog';
	import { get } from '$lib/api/client';
	import { failureOf } from '$lib/api/result';
	import { auth } from '$lib/auth/state.svelte';
	import { m } from '$lib/paraglide/messages';

	const isAdmin = $derived(auth.role === 'admin');

	let selected = $state<ApiCatalogEntry | null>(null);
	let tryResult = $state<string | null>(null);
	let tryFailure = $state<{ code: string; params: Record<string, unknown> } | null>(null);
	let tryBusy = $state(false);

	function summary(entry: ApiCatalogEntry): string {
		const map: Record<ApiCatalogEntry['summaryKey'], () => string> = {
			api_cat_auth_me: () => m.api_cat_auth_me(),
			api_cat_status: () => m.api_cat_status(),
			api_cat_config: () => m.api_cat_config(),
			api_cat_listeners: () => m.api_cat_listeners(),
			api_cat_tls_status: () => m.api_cat_tls_status(),
			api_cat_query_log: () => m.api_cat_query_log(),
			api_cat_audit: () => m.api_cat_audit(),
			api_cat_tokens: () => m.api_cat_tokens(),
		};
		return map[entry.summaryKey]();
	}

	function canTry(entry: ApiCatalogEntry): boolean {
		return (
			entry.method === 'GET' && entry.tryPath !== undefined && (entry.role === 'viewer' || isAdmin)
		);
	}

	async function runTry(): Promise<void> {
		if (!selected?.tryPath) return;
		tryBusy = true;
		tryFailure = null;
		tryResult = null;
		try {
			const data = await get<unknown>(selected.tryPath);
			tryResult = JSON.stringify(data, null, 2);
		} catch (cause) {
			tryFailure = failureOf(cause);
		} finally {
			tryBusy = false;
		}
	}
</script>

<p class="lead">{m.api_explorer_lead()}</p>

<GroupedList header={m.api_explorer_catalog()}>
	{#each API_CATALOG as entry (entry.path)}
		<GroupedRow
			label={`${entry.method} ${entry.path}`}
			detail={summary(entry)}
			mono
			detailMono={false}
		>
			{#snippet trailing()}
				<Button onclick={() => ((selected = entry), (tryResult = null), (tryFailure = null))}>
					{m.api_explorer_inspect()}
				</Button>
			{/snippet}
		</GroupedRow>
	{/each}
</GroupedList>

{#if selected}
	<GroupedList header={m.api_explorer_detail()}>
		<GroupedRow label={m.api_explorer_method()} detail={selected.method} detailMono />
		<GroupedRow label={m.api_explorer_path()} detail={selected.path} detailMono />
		<GroupedRow label={m.api_explorer_role()} detail={selected.role} detailMono />
		<GroupedRow label={m.api_explorer_summary()} detail={summary(selected)} />
	</GroupedList>

	{#if canTry(selected)}
		<div class="try">
			<Button disabled={tryBusy} onclick={() => void runTry()}>{m.api_explorer_try()}</Button>
		</div>
	{/if}

	{#if tryFailure}
		<ErrorNotice code={tryFailure.code} params={tryFailure.params} />
	{/if}
	{#if tryResult}
		<pre class="mono preview">{tryResult}</pre>
	{/if}
{/if}

<style>
	.lead {
		margin: 0 0 1rem;
		color: var(--label-2);
	}

	.try {
		margin: 0.75rem 0;
	}

	.preview {
		margin: 0.75rem 0 0;
		padding: 0.75rem;
		overflow-x: auto;
		font-size: 0.8125rem;
		background: var(--surface-2);
		border-radius: var(--r-control);
		white-space: pre-wrap;
		overflow-wrap: anywhere;
	}
</style>
