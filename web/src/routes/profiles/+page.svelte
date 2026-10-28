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
	import { deleteProfile, listProfiles, saveProfile, type PolicyProfile } from '$lib/api/policy';
	import { listFilterSets, type FilterSet } from '$lib/api/filtering';
	import { failureOf, settle, type Result } from '$lib/api/result';
	import { auth } from '$lib/auth/state.svelte';
	import { m } from '$lib/paraglide/messages';

	const isAdmin = $derived(auth.role === 'admin');
	let result = $state<Result<PolicyProfile[]>>({ kind: 'loading' });
	let sets = $state<FilterSet[]>([]);
	let sheetOpen = $state(false);
	let busy = $state(false);
	let failure = $state<{ code: string; params: Record<string, unknown> } | null>(null);
	let editing = $state<PolicyProfile | null>(null);
	let expert = $state(false);
	let formId = $state('');
	let formFilterSet = $state('default');
	let formSafeSearch = $state(false);
	let formRebind = $state(true);
	let formAaaa = $state(false);
	let formFirefox = $state(false);
	let formIcloud = $state(false);

	const rows = $derived(result.kind === 'ok' ? result.data : []);

	async function load(): Promise<void> {
		result = await settle(listProfiles());
		const setResult = await settle(listFilterSets());
		if (setResult.kind === 'ok') sets = setResult.data;
	}

	function summary(profile: PolicyProfile): string {
		const parts = [m.profiles_filter_set({ set: profile.filter_set })];
		if (profile.safesearch) parts.push(m.profiles_safesearch_on());
		if (profile.rebind === false) parts.push(m.profiles_rebind_off());
		return parts.join(' · ');
	}

	function openCreate(): void {
		editing = null;
		formId = '';
		formFilterSet = sets[0]?.id ?? 'default';
		formSafeSearch = false;
		formRebind = true;
		formAaaa = false;
		formFirefox = false;
		formIcloud = false;
		failure = null;
		sheetOpen = true;
	}

	function openEdit(profile: PolicyProfile): void {
		editing = profile;
		formId = profile.id;
		formFilterSet = profile.filter_set;
		formSafeSearch = profile.safesearch !== null && profile.safesearch !== false;
		formRebind = profile.rebind !== false;
		formAaaa = profile.suppress_aaaa;
		formFirefox = profile.firefox_canary;
		formIcloud = profile.icloud_private_relay;
		failure = null;
		sheetOpen = true;
	}

	function bodyFromForm(): Omit<PolicyProfile, 'id'> {
		return {
			filter_set: formFilterSet,
			suppress_aaaa: formAaaa,
			firefox_canary: formFirefox,
			icloud_private_relay: formIcloud,
			rebind: formRebind ? true : false,
			rebind_exceptions: editing?.rebind_exceptions ?? [],
			forward_zones: editing?.forward_zones ?? null,
			safesearch: formSafeSearch ? 'strict' : null,
			schedules: editing?.schedules ?? [],
		};
	}

	async function submit(): Promise<void> {
		busy = true;
		const id = editing?.id ?? formId.trim();
		try {
			await saveProfile(id, bodyFromForm());
			sheetOpen = false;
			await load();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	async function removeProfile(id: string): Promise<void> {
		busy = true;
		try {
			await deleteProfile(id);
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

<p class="lead">{m.profiles_lead()}</p>

{#if result.kind === 'loading'}
	<p class="state">{m.state_loading()}</p>
{:else if result.kind === 'unavailable'}
	<UnavailableNotice />
{:else if result.kind === 'error'}
	<ResultNotice {result} onretry={() => void load()} />
{:else}
	<GroupedList>
		{#each rows as profile (profile.id)}
			<GroupedRow label={profile.id} detail={summary(profile)}>
				{#snippet trailing()}
					{#if isAdmin}
						<div class="actions">
							<Button onclick={() => openEdit(profile)}>{m.action_edit()}</Button>
							<Button
								variant="danger"
								disabled={busy}
								onclick={() => void removeProfile(profile.id)}
							>
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
			<button type="button" class="add-row" onclick={openCreate}>{m.profiles_add()}</button>
		{/if}
	</GroupedList>
	<p class="footnote">{m.profiles_footnote()}</p>
{/if}

{#if sheetOpen && isAdmin}
	<Sheet
		open={sheetOpen}
		title={editing ? m.profiles_edit_title() : m.profiles_add_title()}
		onclose={() => (sheetOpen = false)}
	>
		{#if !editing}
			<label class="field-label" for="profile-id">{m.profiles_id_label()}</label>
			<input id="profile-id" class="field" bind:value={formId} />
		{/if}
		<label class="field-label" for="profile-set">{m.profiles_filter_set_label()}</label>
		<select id="profile-set" class="field" bind:value={formFilterSet}>
			{#each sets as set (set.id)}
				<option value={set.id}>{set.name || set.id}</option>
			{/each}
		</select>
		<div class="switch-row">
			<span>{m.profiles_safesearch_label()}</span>
			<Switch bind:checked={formSafeSearch} aria-label={m.profiles_safesearch_label()} />
		</div>
		<div class="switch-row">
			<span>{m.profiles_rebind_label()}</span>
			<Switch bind:checked={formRebind} aria-label={m.profiles_rebind_label()} />
		</div>
		<button type="button" class="expert-toggle" onclick={() => (expert = !expert)}>
			{expert ? m.profiles_basic_mode() : m.profiles_expert_mode()}
		</button>
		{#if expert}
			<div class="switch-row">
				<span>{m.profiles_aaaa_label()}</span>
				<Switch bind:checked={formAaaa} aria-label={m.profiles_aaaa_label()} />
			</div>
			<div class="switch-row">
				<span>{m.profiles_firefox_label()}</span>
				<Switch bind:checked={formFirefox} aria-label={m.profiles_firefox_label()} />
			</div>
			<div class="switch-row">
				<span>{m.profiles_icloud_label()}</span>
				<Switch bind:checked={formIcloud} aria-label={m.profiles_icloud_label()} />
			</div>
			<p class="hint">{m.profiles_schedules_hint()}</p>
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
	.footnote,
	.hint {
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
	.switch-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		min-height: 2.75rem;
	}
	.expert-toggle {
		min-height: 2.75rem;
		margin-top: 0.5rem;
		padding: 0;
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
