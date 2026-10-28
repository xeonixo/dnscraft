<script lang="ts">
	import { onMount } from 'svelte';
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import ResultNotice from '$lib/components/ResultNotice.svelte';
	import Sheet from '$lib/components/Sheet.svelte';
	import Switch from '$lib/components/Switch.svelte';
	import UnavailableNotice from '$lib/components/UnavailableNotice.svelte';
	import {
		deleteFilterList,
		listFilterLists,
		saveFilterList,
		type FilterList,
	} from '$lib/api/filtering';
	import { failureOf, settle, type Result } from '$lib/api/result';
	import { auth } from '$lib/auth/state.svelte';
	import { m } from '$lib/paraglide/messages';

	const isAdmin = $derived(auth.role === 'admin');
	let result = $state<Result<FilterList[]>>({ kind: 'loading' });
	let sheetOpen = $state(false);
	let busy = $state(false);
	let failure = $state<{ code: string; params: Record<string, unknown> } | null>(null);
	let editing = $state<FilterList | null>(null);
	let formId = $state('');
	let formName = $state('');
	let formUrl = $state('');
	let formEnabled = $state(true);

	const rows = $derived(result.kind === 'ok' ? result.data : []);

	function sourceDetail(list: FilterList): string {
		if (list.source.url) return list.source.url;
		if (list.source.file) return list.source.file;
		return m.querylog_none();
	}

	async function load(): Promise<void> {
		result = await settle(listFilterLists());
	}

	function openCreate(): void {
		editing = null;
		formId = '';
		formName = '';
		formUrl = '';
		formEnabled = true;
		failure = null;
		sheetOpen = true;
	}

	function openEdit(list: FilterList): void {
		editing = list;
		formId = list.id;
		formName = list.name;
		formUrl = list.source.url ?? list.source.file ?? '';
		formEnabled = list.enabled;
		failure = null;
		sheetOpen = true;
	}

	async function submit(): Promise<void> {
		busy = true;
		const id = editing?.id ?? formId.trim();
		const source = formUrl.startsWith('http') ? { url: formUrl.trim() } : { file: formUrl.trim() };
		try {
			await saveFilterList({ id, name: formName, source, enabled: formEnabled });
			sheetOpen = false;
			await load();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	async function removeList(id: string): Promise<void> {
		busy = true;
		try {
			await deleteFilterList(id);
			await load();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	onMount(() => {
		void load();
	});
</script>

<p class="lead">{m.filter_lists_lead()}</p>

{#if result.kind === 'loading'}
	<p class="state">{m.state_loading()}</p>
{:else if result.kind === 'unavailable'}
	<UnavailableNotice />
{:else if result.kind === 'error'}
	<ResultNotice {result} onretry={() => void load()} />
{:else}
	<GroupedList>
		{#each rows as list (list.id)}
			<GroupedRow label={list.name || list.id} detail={sourceDetail(list)} mono detailMono>
				{#snippet trailing()}
					<span class="status"
						>{list.enabled ? m.filter_list_enabled() : m.filter_list_disabled()}</span
					>
					{#if isAdmin}
						<div class="actions">
							<Button onclick={() => openEdit(list)}>{m.action_edit()}</Button>
							<Button variant="danger" disabled={busy} onclick={() => void removeList(list.id)}>
								{m.action_delete()}
							</Button>
						</div>
					{/if}
				{/snippet}
			</GroupedRow>
		{:else}
			<GroupedRow label={m.state_empty()} />
		{/each}
		{#if isAdmin}
			<button type="button" class="add-row" onclick={openCreate}>{m.filter_lists_add()}</button>
		{/if}
	</GroupedList>
	<p class="footnote">{m.filter_lists_refresh_unavailable()}</p>
{/if}

{#if sheetOpen && isAdmin}
	<Sheet
		open={sheetOpen}
		title={editing ? m.filter_lists_edit_title() : m.filter_lists_add_title()}
		onclose={() => (sheetOpen = false)}
	>
		{#if !editing}
			<label class="field-label" for="fl-id">{m.filter_lists_id_label()}</label>
			<input id="fl-id" class="field mono" bind:value={formId} />
		{/if}
		<label class="field-label" for="fl-name">{m.filter_lists_name_label()}</label>
		<input id="fl-name" class="field" bind:value={formName} />
		<label class="field-label" for="fl-source">{m.filter_lists_source_label()}</label>
		<input id="fl-source" class="field mono" bind:value={formUrl} />
		<div class="switch-row">
			<span>{m.filter_list_enabled()}</span>
			<Switch bind:checked={formEnabled} aria-label={m.filter_list_enabled()} />
		</div>
		{#if failure}<ErrorNotice code={failure.code} params={failure.params} />{/if}
		<div class="sheet-actions">
			<Button variant="secondary" onclick={() => (sheetOpen = false)}>{m.action_cancel()}</Button>
			<Button variant="primary" disabled={busy} onclick={() => void submit()}
				>{m.action_save()}</Button
			>
		</div>
	</Sheet>
{/if}

<style>
	.lead {
		margin: 0 0 1rem;
		color: var(--label-2);
	}
	.state {
		color: var(--label-2);
	}
	.footnote {
		margin-top: 0.75rem;
		font-size: 0.8125rem;
		color: var(--label-3);
	}
	.status {
		font-size: 0.75rem;
		color: var(--label-2);
		margin-right: 0.5rem;
	}
	.add-row {
		display: flex;
		min-height: 2.75rem;
		width: 100%;
		padding: 0.75rem 1rem;
		border: none;
		border-top: 1px solid var(--separator);
		background: transparent;
		color: var(--accent);
		font: inherit;
		font-weight: 500;
		cursor: pointer;
	}
	.actions {
		display: flex;
		gap: 0.375rem;
	}
	.field-label {
		display: block;
		margin: 0.75rem 0 0.25rem;
		font-size: 0.8125rem;
		color: var(--label-2);
	}
	.field {
		width: 100%;
		min-height: 2.75rem;
		padding: 0.5rem 0.75rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		font: inherit;
	}
	.mono {
		font-family: var(--font-mono);
	}
	.switch-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		min-height: 2.75rem;
	}
	.sheet-actions {
		display: flex;
		justify-content: flex-end;
		gap: 0.5rem;
		margin-top: 1rem;
	}
</style>
