<script lang="ts">
	import { onMount } from 'svelte';
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import ResultNotice from '$lib/components/ResultNotice.svelte';
	import Segmented from '$lib/components/Segmented.svelte';
	import Sheet from '$lib/components/Sheet.svelte';
	import Switch from '$lib/components/Switch.svelte';
	import UnavailableNotice from '$lib/components/UnavailableNotice.svelte';
	import {
		buildRuleText,
		deleteFilterSet,
		listFilterSets,
		saveFilterSet,
		type FilterSet,
		type GuidedRule,
	} from '$lib/api/filtering';
	import { failureOf, settle, type Result } from '$lib/api/result';
	import { auth } from '$lib/auth/state.svelte';
	import { m } from '$lib/paraglide/messages';

	const isAdmin = $derived(auth.role === 'admin');
	let result = $state<Result<FilterSet[]>>({ kind: 'loading' });
	let sheetOpen = $state(false);
	let busy = $state(false);
	let failure = $state<{ code: string; params: Record<string, unknown> } | null>(null);
	let editing = $state<FilterSet | null>(null);
	let formId = $state('');
	let formName = $state('');
	let formBlockMode = $state<'refused' | 'nxdomain' | 'null_ip'>('refused');
	let formRaw = $state('');
	let showRaw = $state(false);
	let ruleAction = $state<'block' | 'allow'>('block');
	let ruleDomain = $state('');
	let ruleSubs = $state(true);

	const rows = $derived(result.kind === 'ok' ? result.data : []);
	const actionOptions = $derived([
		{ value: 'block', label: m.filter_rule_block() },
		{ value: 'allow', label: m.filter_rule_allow() },
	]);
	const blockOptions = $derived([
		{ value: 'refused', label: m.filter_block_refused() },
		{ value: 'nxdomain', label: m.filter_block_nxdomain() },
		{ value: 'null_ip', label: m.filter_block_null() },
	]);

	async function load(): Promise<void> {
		result = await settle(listFilterSets());
	}

	function openCreate(): void {
		editing = null;
		formId = '';
		formName = '';
		formBlockMode = 'refused';
		formRaw = '';
		ruleDomain = '';
		failure = null;
		sheetOpen = true;
	}

	function openEdit(set: FilterSet): void {
		editing = set;
		formId = set.id;
		formName = set.name;
		formBlockMode =
			set.block_mode === 'nxdomain' || set.block_mode === 'null_ip' ? set.block_mode : 'refused';
		formRaw = set.custom_rules;
		failure = null;
		sheetOpen = true;
	}

	function appendGuidedRule(): void {
		const domain = ruleDomain.trim();
		if (!domain) return;
		const rule: GuidedRule = {
			action: ruleAction,
			domain,
			include_subdomains: ruleSubs,
		};
		const line = buildRuleText(rule);
		formRaw = formRaw ? `${formRaw}\n${line}` : line;
		ruleDomain = '';
	}

	async function submit(): Promise<void> {
		busy = true;
		const id = editing?.id ?? formId.trim();
		try {
			await saveFilterSet({
				id,
				name: formName,
				lists: editing?.lists ?? [],
				custom_rules: formRaw,
				services: editing?.services ?? [],
				block_mode: formBlockMode,
			});
			sheetOpen = false;
			await load();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	async function removeSet(id: string): Promise<void> {
		busy = true;
		try {
			await deleteFilterSet(id);
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

<p class="lead">{m.filter_sets_lead()}</p>

{#if result.kind === 'loading'}
	<p class="state">{m.state_loading()}</p>
{:else if result.kind === 'unavailable'}
	<UnavailableNotice />
{:else if result.kind === 'error'}
	<ResultNotice {result} onretry={() => void load()} />
{:else}
	<GroupedList>
		{#each rows as set (set.id)}
			<GroupedRow
				label={set.name || set.id}
				detail={m.filter_sets_lists({ count: set.lists.length })}
			>
				{#snippet trailing()}
					{#if isAdmin}
						<div class="actions">
							<Button onclick={() => openEdit(set)}>{m.action_edit()}</Button>
							<Button variant="danger" disabled={busy} onclick={() => void removeSet(set.id)}>
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
			<button type="button" class="add-row" onclick={openCreate}>{m.filter_sets_add()}</button>
		{/if}
	</GroupedList>
{/if}

{#if sheetOpen && isAdmin}
	<Sheet
		open={sheetOpen}
		title={editing ? m.filter_sets_edit_title() : m.filter_sets_add_title()}
		onclose={() => (sheetOpen = false)}
	>
		{#if !editing}
			<label class="field-label" for="fs-id">{m.filter_sets_id_label()}</label>
			<input id="fs-id" class="field mono" bind:value={formId} />
		{/if}
		<label class="field-label" for="fs-name">{m.filter_sets_name_label()}</label>
		<input id="fs-name" class="field" bind:value={formName} />
		<span class="field-label">{m.filter_sets_block_mode()}</span>
		<Segmented
			options={blockOptions}
			bind:value={formBlockMode}
			label={m.filter_sets_block_mode()}
		/>
		<span class="field-label">{m.filter_rule_action()}</span>
		<Segmented options={actionOptions} bind:value={ruleAction} label={m.filter_rule_action()} />
		<label class="field-label" for="rule-domain">{m.filter_rule_domain()}</label>
		<input id="rule-domain" class="field mono" bind:value={ruleDomain} />
		<div class="switch-row">
			<span>{m.filter_rule_subdomains()}</span>
			<Switch bind:checked={ruleSubs} aria-label={m.filter_rule_subdomains()} />
		</div>
		<Button variant="secondary" onclick={appendGuidedRule}>{m.filter_rule_add()}</Button>
		<button type="button" class="expert-toggle" onclick={() => (showRaw = !showRaw)}>
			{showRaw ? m.filter_rule_hide_raw() : m.filter_rule_show_raw()}
		</button>
		{#if showRaw}
			<label class="field-label" for="fs-raw">{m.filter_rule_raw()}</label>
			<textarea id="fs-raw" class="field area mono" bind:value={formRaw} rows="6"></textarea>
		{/if}
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
	.area {
		min-height: 6rem;
	}
	.switch-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		min-height: 2.75rem;
	}
	.expert-toggle {
		min-height: 2.75rem;
		margin-top: 0.5rem;
		border: none;
		background: transparent;
		color: var(--accent);
		font: inherit;
		cursor: pointer;
	}
	.sheet-actions {
		display: flex;
		justify-content: flex-end;
		gap: 0.5rem;
		margin-top: 1rem;
	}
</style>
