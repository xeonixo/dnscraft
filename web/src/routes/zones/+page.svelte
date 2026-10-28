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
		deleteView,
		listProfiles,
		listViews,
		saveView,
		type PolicyProfile,
		type PolicyView,
	} from '$lib/api/policy';
	import { failureOf, settle, type Result } from '$lib/api/result';
	import { auth } from '$lib/auth/state.svelte';
	import { subnetDetail } from '$lib/policy/display';
	import { m } from '$lib/paraglide/messages';

	const isAdmin = $derived(auth.role === 'admin');
	let result = $state<Result<PolicyView[]>>({ kind: 'loading' });
	let profiles = $state<PolicyProfile[]>([]);
	let sheetOpen = $state(false);
	let deleteOpen = $state(false);
	let busy = $state(false);
	let failure = $state<{ code: string; params: Record<string, unknown> } | null>(null);
	let editing = $state<PolicyView | null>(null);
	let deleting = $state<PolicyView | null>(null);

	let formId = $state('');
	let formDefault = $state(false);
	let formSubnets = $state('');
	let formNodes = $state('');
	let formProfile = $state('default');

	const rows = $derived(result.kind === 'ok' ? result.data : []);

	async function load(): Promise<void> {
		result = { kind: 'loading' };
		const views = await settle(listViews());
		result = views;
		if (views.kind === 'ok') {
			const prof = await settle(listProfiles());
			if (prof.kind === 'ok') profiles = prof.data;
		}
	}

	function openCreate(): void {
		editing = null;
		formId = '';
		formDefault = false;
		formSubnets = '';
		formNodes = '';
		formProfile = profiles[0]?.id ?? 'default';
		failure = null;
		sheetOpen = true;
	}

	function openEdit(view: PolicyView): void {
		editing = view;
		formId = view.id;
		formDefault = view.is_default;
		formSubnets = view.subnets.join('\n');
		formNodes = view.nodes.join('\n');
		formProfile = view.profile;
		failure = null;
		sheetOpen = true;
	}

	function openDelete(view: PolicyView): void {
		deleting = view;
		failure = null;
		deleteOpen = true;
	}

	function parseLines(text: string): string[] {
		return text
			.split(/\n|,/)
			.map((line) => line.trim())
			.filter((line) => line.length > 0);
	}

	async function submit(): Promise<void> {
		busy = true;
		failure = null;
		const id = editing?.id ?? formId.trim();
		const body = {
			is_default: formDefault,
			subnets: parseLines(formSubnets),
			nodes: parseLines(formNodes),
			profile: formProfile,
		};
		try {
			await saveView(id, body);
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
		failure = null;
		try {
			await deleteView(deleting.id);
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

<p class="lead">{m.zones_lead()}</p>

{#if result.kind === 'loading'}
	<p class="state">{m.state_loading()}</p>
{:else if result.kind === 'unavailable'}
	<UnavailableNotice />
{:else if result.kind === 'error'}
	<ResultNotice {result} onretry={() => void load()} />
{:else}
	<div class="section-head">{m.zones_section()}</div>
	<GroupedList>
		{#each rows as view (view.id)}
			<GroupedRow
				label={view.id}
				detail={subnetDetail(
					view.subnets,
					view.is_default ? m.zones_default_no_subnets() : m.zones_no_subnets(),
				) +
					' · ' +
					m.zones_profile_link({ profile: view.profile })}
				mono
				detailMono
			>
				{#snippet trailing()}
					{#if isAdmin}
						<div class="actions">
							<Button onclick={() => openEdit(view)}>{m.action_edit()}</Button>
							{#if !view.is_default}
								<Button variant="danger" onclick={() => openDelete(view)}
									>{m.action_delete()}</Button
								>
							{/if}
						</div>
					{/if}
				{/snippet}
			</GroupedRow>
		{:else}
			<GroupedRow label={m.state_empty()} />
		{/each}
		{#if isAdmin}
			<button type="button" class="add-row" onclick={openCreate}>{m.zones_add()}</button>
		{/if}
	</GroupedList>
	<p class="footnote">{m.zones_footnote()}</p>
{/if}

{#if sheetOpen && isAdmin}
	<Sheet
		open={sheetOpen}
		title={editing ? m.zones_edit_title() : m.zones_add_title()}
		onclose={() => (sheetOpen = false)}
	>
		{#if !editing}
			<label class="field-label" for="zone-id">{m.zones_id_label()}</label>
			<input id="zone-id" class="field" bind:value={formId} autocomplete="off" />
		{/if}
		<label class="field-label" for="zone-profile">{m.zones_profile_label()}</label>
		<select id="zone-profile" class="field" bind:value={formProfile}>
			{#each profiles as profile (profile.id)}
				<option value={profile.id}>{profile.id}</option>
			{/each}
		</select>
		<label class="field-label" for="zone-subnets">{m.zones_subnets_label()}</label>
		<textarea id="zone-subnets" class="field area" bind:value={formSubnets} rows="4"></textarea>
		<label class="field-label" for="zone-nodes">{m.zones_nodes_label()}</label>
		<textarea id="zone-nodes" class="field area" bind:value={formNodes} rows="2"></textarea>
		<div class="switch-row">
			<span>{m.zones_default_label()}</span>
			<Switch bind:checked={formDefault} aria-label={m.zones_default_label()} />
		</div>
		{#if failure}
			<ErrorNotice code={failure.code} params={failure.params} />
		{/if}
		<div class="sheet-actions">
			<Button variant="secondary" onclick={() => (sheetOpen = false)}>{m.action_cancel()}</Button>
			<Button variant="primary" disabled={busy} onclick={() => void submit()}
				>{m.action_save()}</Button
			>
		</div>
	</Sheet>
{/if}

{#if deleteOpen && deleting && isAdmin}
	<Sheet open={deleteOpen} title={m.zones_delete_title()} onclose={() => (deleteOpen = false)}>
		<p>{m.zones_delete_body({ id: deleting.id })}</p>
		{#if failure}
			<ErrorNotice code={failure.code} params={failure.params} />
		{/if}
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
		line-height: 1.45;
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
		line-height: 1.45;
	}

	.add-row {
		display: flex;
		align-items: center;
		min-height: 2.75rem;
		width: 100%;
		padding: 0.75rem 1rem;
		border: none;
		border-top: 1px solid var(--separator);
		background: transparent;
		color: var(--accent);
		font: inherit;
		font-weight: 500;
		text-align: left;
		cursor: pointer;
	}

	.actions {
		display: flex;
		flex-wrap: wrap;
		gap: 0.375rem;
	}

	.field-label {
		display: block;
		margin: 0.75rem 0 0.25rem;
		font-size: 0.8125rem;
		color: var(--label-2);
	}

	.field {
		display: block;
		width: 100%;
		min-height: 2.75rem;
		padding: 0.5rem 0.75rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		background: var(--surface);
		color: var(--label);
		font: inherit;
	}

	.area {
		min-height: 5rem;
		resize: vertical;
		font-family: var(--font-mono);
		font-size: 0.8125rem;
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
