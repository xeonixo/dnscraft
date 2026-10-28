<script lang="ts">
	import { onMount } from 'svelte';
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import ResultNotice from '$lib/components/ResultNotice.svelte';
	import Sheet from '$lib/components/Sheet.svelte';
	import UnavailableNotice from '$lib/components/UnavailableNotice.svelte';
	import { deleteRecord, listRecords, saveRecord, type PolicyRecord } from '$lib/api/policy';
	import { failureOf, settle, type Result } from '$lib/api/result';
	import { auth } from '$lib/auth/state.svelte';
	import { domainLabel } from '$lib/policy/display';
	import { m } from '$lib/paraglide/messages';

	const RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'TXT', 'SRV', 'MX', 'PTR'];
	const isAdmin = $derived(auth.role === 'admin');
	let result = $state<Result<PolicyRecord[]>>({ kind: 'loading' });
	let sheetOpen = $state(false);
	let deleteOpen = $state(false);
	let busy = $state(false);
	let failure = $state<{ code: string; params: Record<string, unknown> } | null>(null);
	let editing = $state<PolicyRecord | null>(null);
	let deleting = $state<PolicyRecord | null>(null);
	let formName = $state('');
	let formType = $state('A');
	let formTtl = $state('60');
	let formRdata = $state('');
	let formOverrides = $state('');

	const rows = $derived(result.kind === 'ok' ? result.data : []);

	async function load(): Promise<void> {
		result = await settle(listRecords());
	}

	function openCreate(): void {
		editing = null;
		formName = '';
		formType = 'A';
		formTtl = '60';
		formRdata = '';
		formOverrides = '';
		failure = null;
		sheetOpen = true;
	}

	function openEdit(record: PolicyRecord): void {
		editing = record;
		formName = record.name;
		formType = record.type;
		formTtl = String(record.ttl);
		formRdata = record.rdata;
		formOverrides = Object.entries(record.overrides)
			.map(([view, value]) => `${view}=${value}`)
			.join('\n');
		failure = null;
		sheetOpen = true;
	}

	function parseOverrides(text: string): Record<string, string> {
		const map: Record<string, string> = {};
		for (const line of text.split('\n')) {
			const trimmed = line.trim();
			if (!trimmed) continue;
			const eq = trimmed.indexOf('=');
			if (eq <= 0) continue;
			map[trimmed.slice(0, eq).trim()] = trimmed.slice(eq + 1).trim();
		}
		return map;
	}

	async function submit(): Promise<void> {
		busy = true;
		failure = null;
		try {
			await saveRecord({
				name: formName.trim(),
				type: formType,
				ttl: Number(formTtl) || 60,
				rdata: formRdata.trim(),
				overrides: parseOverrides(formOverrides),
			});
			sheetOpen = false;
			await load();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	async function confirmDelete(): Promise<void> {
		if (!deleting) return;
		busy = true;
		try {
			await deleteRecord({ name: deleting.name, type: deleting.type });
			deleteOpen = false;
			deleting = null;
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

<p class="lead">{m.names_lead()}</p>

{#if result.kind === 'loading'}
	<p class="state">{m.state_loading()}</p>
{:else if result.kind === 'unavailable'}
	<UnavailableNotice />
{:else if result.kind === 'error'}
	<ResultNotice {result} onretry={() => void load()} />
{:else}
	<div class="section-head">{m.names_section()}</div>
	<GroupedList>
		{#each rows as record (record.name + record.type)}
			<GroupedRow
				label={domainLabel(record.name)}
				detail="{record.type} · TTL {record.ttl} · {record.rdata}"
				mono
			>
				{#snippet trailing()}
					{#if isAdmin}
						<div class="actions">
							<Button onclick={() => openEdit(record)}>{m.action_edit()}</Button>
							<Button variant="danger" onclick={() => ((deleting = record), (deleteOpen = true))}>
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
			<button type="button" class="add-row" onclick={openCreate}>{m.names_add()}</button>
		{/if}
	</GroupedList>
	<p class="footnote">{m.names_footnote()}</p>
{/if}

{#if sheetOpen && isAdmin}
	<Sheet
		open={sheetOpen}
		title={editing ? m.names_edit_title() : m.names_add_title()}
		onclose={() => (sheetOpen = false)}
	>
		<label class="field-label" for="rec-name">{m.names_field_name()}</label>
		<input id="rec-name" class="field mono" bind:value={formName} disabled={editing !== null} />
		<label class="field-label" for="rec-type">{m.names_field_type()}</label>
		<select id="rec-type" class="field" bind:value={formType} disabled={editing !== null}>
			{#each RECORD_TYPES as type (type)}
				<option value={type}>{type}</option>
			{/each}
		</select>
		<label class="field-label" for="rec-ttl">{m.names_field_ttl()}</label>
		<input id="rec-ttl" class="field" bind:value={formTtl} inputmode="numeric" />
		<label class="field-label" for="rec-rdata">{m.names_field_rdata()}</label>
		<input id="rec-rdata" class="field mono" bind:value={formRdata} />
		<label class="field-label" for="rec-overrides">{m.names_field_overrides()}</label>
		<textarea id="rec-overrides" class="field area mono" bind:value={formOverrides} rows="3"
		></textarea>
		{#if failure}<ErrorNotice code={failure.code} params={failure.params} />{/if}
		<div class="sheet-actions">
			<Button variant="secondary" onclick={() => (sheetOpen = false)}>{m.action_cancel()}</Button>
			<Button variant="primary" disabled={busy} onclick={() => void submit()}
				>{m.action_save()}</Button
			>
		</div>
	</Sheet>
{/if}

{#if deleteOpen && deleting && isAdmin}
	<Sheet open={deleteOpen} title={m.names_delete_title()} onclose={() => (deleteOpen = false)}>
		<p>{m.names_delete_body({ name: domainLabel(deleting.name), type: deleting.type })}</p>
		<div class="sheet-actions">
			<Button variant="secondary" onclick={() => (deleteOpen = false)}>{m.action_cancel()}</Button>
			<Button variant="danger" disabled={busy} onclick={() => void confirmDelete()}
				>{m.action_delete()}</Button
			>
		</div>
	</Sheet>
{/if}

<style>
	.lead {
		margin: 0 0 1rem;
		color: var(--label-2);
		font-size: 0.9375rem;
	}
	.section-head {
		margin: 0 0 0.5rem;
		font-size: 0.8125rem;
		font-weight: 600;
		color: var(--label-3);
		text-transform: uppercase;
		letter-spacing: 0.04em;
	}
	.state {
		margin: 0;
		color: var(--label-2);
	}
	.footnote {
		margin: 0.75rem 0 0;
		font-size: 0.8125rem;
		color: var(--label-3);
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
		background: var(--surface);
		font: inherit;
	}
	.mono {
		font-family: var(--font-mono);
	}
	.area {
		min-height: 4rem;
	}
	.sheet-actions {
		display: flex;
		justify-content: flex-end;
		gap: 0.5rem;
		margin-top: 1rem;
	}
</style>
