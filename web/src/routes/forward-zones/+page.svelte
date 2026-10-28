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
		forwardZoneIdFromApex,
		loadForwardZones,
		saveForwardZones,
		type ForwardZoneEntry,
	} from '$lib/api/policy';
	import { failureOf, settle, type Result } from '$lib/api/result';
	import { auth } from '$lib/auth/state.svelte';
	import { domainLabel } from '$lib/policy/display';
	import { m } from '$lib/paraglide/messages';

	const isAdmin = $derived(auth.role === 'admin');
	let result = $state<Result<{ version: number | null; zones: ForwardZoneEntry[] }>>({
		kind: 'loading',
	});
	let sheetOpen = $state(false);
	let busy = $state(false);
	let failure = $state<{ code: string; params: Record<string, unknown> } | null>(null);
	let editing = $state<ForwardZoneEntry | null>(null);
	let formZone = $state('');
	let formTargets = $state('');
	let formValidate = $state(false);

	const rows = $derived(result.kind === 'ok' ? result.data.zones : []);
	const version = $derived(result.kind === 'ok' ? result.data.version : null);

	async function load(): Promise<void> {
		result = await settle(loadForwardZones());
	}

	function openCreate(): void {
		editing = null;
		formZone = '';
		formTargets = '';
		formValidate = false;
		failure = null;
		sheetOpen = true;
	}

	function openEdit(zone: ForwardZoneEntry): void {
		editing = zone;
		formZone = zone.zone;
		formTargets = zone.targets.join('\n');
		formValidate = zone.validate;
		sheetOpen = true;
	}

	async function submit(): Promise<void> {
		if (result.kind !== 'ok') return;
		busy = true;
		const zone = formZone.trim();
		const next: ForwardZoneEntry = {
			// Id is internal only — derived from the apex, never asked of the user.
			id: editing?.id || forwardZoneIdFromApex(zone),
			zone,
			targets: formTargets
				.split(/\n|,/)
				.map((t) => t.trim())
				.filter(Boolean),
			validate: formValidate,
		};
		const editId = editing?.id;
		const zones = editId ? rows.map((z) => (z.id === editId ? next : z)) : [...rows, next];
		try {
			await saveForwardZones(zones, version);
			sheetOpen = false;
			await load();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	async function removeZone(id: string): Promise<void> {
		if (result.kind !== 'ok') return;
		busy = true;
		try {
			await saveForwardZones(
				rows.filter((z) => z.id !== id),
				version,
			);
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

<p class="lead">{m.forward_lead()}</p>

{#if result.kind === 'loading'}
	<p class="state">{m.state_loading()}</p>
{:else if result.kind === 'unavailable'}
	<UnavailableNotice />
{:else if result.kind === 'error'}
	<ResultNotice {result} onretry={() => void load()} />
{:else}
	<div class="section-head">{m.forward_section()}</div>
	<GroupedList>
		{#each rows as zone (zone.id)}
			<GroupedRow label={domainLabel(zone.zone)} detail={zone.targets.join(' · ')} mono detailMono>
				{#snippet trailing()}
					{#if isAdmin}
						<div class="actions">
							<Button onclick={() => openEdit(zone)}>{m.action_edit()}</Button>
							<Button variant="danger" disabled={busy} onclick={() => void removeZone(zone.id)}>
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
			<button type="button" class="add-row" onclick={openCreate}>{m.forward_add()}</button>
		{/if}
	</GroupedList>
	<p class="footnote">{m.forward_footnote()}</p>
{/if}

{#if sheetOpen && isAdmin}
	<Sheet
		open={sheetOpen}
		title={editing ? m.forward_edit_title() : m.forward_add_title()}
		onclose={() => (sheetOpen = false)}
	>
		<label class="field-label" for="fz-zone">{m.forward_domain_label()}</label>
		<input id="fz-zone" class="field mono" bind:value={formZone} autocomplete="off" />
		<label class="field-label" for="fz-targets">{m.forward_targets_label()}</label>
		<textarea id="fz-targets" class="field area mono" bind:value={formTargets} rows="3"></textarea>
		<div class="switch-row">
			<span>{m.forward_validate_label()}</span>
			<Switch bind:checked={formValidate} aria-label={m.forward_validate_label()} />
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
	.section-head {
		margin: 0 0 0.5rem;
		font-size: 0.8125rem;
		font-weight: 600;
		color: var(--label-3);
		text-transform: uppercase;
	}
	.state {
		color: var(--label-2);
	}
	.footnote {
		margin-top: 0.75rem;
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
		font: inherit;
	}
	.mono {
		font-family: var(--font-mono);
	}
	.area {
		min-height: 4rem;
	}
	.switch-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		min-height: 2.75rem;
		margin-top: 0.75rem;
	}
	.sheet-actions {
		display: flex;
		justify-content: flex-end;
		gap: 0.5rem;
		margin-top: 1rem;
	}
</style>
