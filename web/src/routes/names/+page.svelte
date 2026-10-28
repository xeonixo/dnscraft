<script lang="ts">
	import { onMount } from 'svelte';
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import Icon from '$lib/components/Icon.svelte';
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
	let confirmDelete = $state(false);
	let busy = $state(false);
	let failure = $state<{ code: string; params: Record<string, unknown> } | null>(null);
	let editing = $state<PolicyRecord | null>(null);
	let query = $state('');
	let formName = $state('');
	let formType = $state('A');
	let formTtl = $state('60');
	let formRdata = $state('');
	let formOverrides = $state('');

	const rows = $derived(result.kind === 'ok' ? result.data : []);

	/** One card per owner; A/AAAA for the same name stay together. */
	const groups = $derived.by(() => {
		const needle = query.trim().toLowerCase();
		const filtered = needle
			? rows.filter((record) => {
					const hay = `${record.name} ${record.type} ${record.rdata}`.toLowerCase();
					return hay.includes(needle);
				})
			: rows;
		const byName = new Map<string, PolicyRecord[]>();
		for (const record of filtered) {
			const list = byName.get(record.name) ?? [];
			list.push(record);
			byName.set(record.name, list);
		}
		return [...byName.entries()].map(([name, records]) => ({
			name,
			records: [...records].sort((a, b) => a.type.localeCompare(b.type)),
		}));
	});

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
		confirmDelete = false;
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
		confirmDelete = false;
		failure = null;
		sheetOpen = true;
	}

	function closeSheet(): void {
		sheetOpen = false;
		confirmDelete = false;
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

	function overrideCount(record: PolicyRecord): number {
		return Object.keys(record.overrides).length;
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
			closeSheet();
			await load();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	async function confirmRemove(): Promise<void> {
		if (!editing) return;
		busy = true;
		failure = null;
		try {
			await deleteRecord({ name: editing.name, type: editing.type });
			closeSheet();
			editing = null;
			await load();
		} catch (cause) {
			failure = failureOf(cause);
			confirmDelete = false;
		} finally {
			busy = false;
		}
	}

	onMount(() => {
		void load();
	});
</script>

<div class="names">
	<div class="page-head">
		<p class="lead">{m.names_lead()}</p>
		{#if isAdmin && result.kind === 'ok'}
			<Button variant="primary" onclick={openCreate}>{m.names_add()}</Button>
		{/if}
	</div>

	{#if result.kind === 'loading'}
		<p class="state">{m.state_loading()}</p>
	{:else if result.kind === 'unavailable'}
		<UnavailableNotice />
	{:else if result.kind === 'error'}
		<ResultNotice {result} onretry={() => void load()} />
	{:else}
		<label class="sr-only" for="names-search">{m.names_search_label()}</label>
		<input
			id="names-search"
			class="search mono"
			type="search"
			bind:value={query}
			placeholder={m.names_search_placeholder()}
			autocomplete="off"
		/>

		{#if groups.length === 0}
			<section class="empty">
				<p>{query.trim() ? m.names_search_empty() : m.state_empty()}</p>
			</section>
		{:else}
			{#each groups as group (group.name)}
				<section class="owner">
					<header class="owner-head">
						<span class="owner-name mono">{domainLabel(group.name)}</span>
						<span class="owner-meta"
							>{group.records.length === 1
								? m.names_record_count_one({ count: '1' })
								: m.names_record_count_other({ count: String(group.records.length) })}</span
						>
					</header>
					<GroupedList>
						{#each group.records as record (record.name + record.type)}
							<button
								type="button"
								class="rec-row"
								onclick={() => (isAdmin ? openEdit(record) : undefined)}
								disabled={!isAdmin}
							>
								<span class="type">{record.type}</span>
								<span class="rdata mono">{record.rdata}</span>
								<span class="meta">
									TTL {record.ttl}{#if overrideCount(record) > 0}
										· {overrideCount(record) === 1
											? m.names_overrides_badge_one({ count: '1' })
											: m.names_overrides_badge_other({
													count: String(overrideCount(record)),
												})}{/if}
								</span>
								{#if isAdmin}
									<span class="chevron" aria-hidden="true">
										<Icon name="chevron-right" size="1rem" />
									</span>
								{/if}
							</button>
						{/each}
					</GroupedList>
				</section>
			{/each}
		{/if}
		<p class="footnote">{m.names_footnote()}</p>
	{/if}
</div>

{#if sheetOpen && isAdmin}
	<Sheet
		open={sheetOpen}
		title={editing ? m.names_edit_title() : m.names_add_title()}
		onclose={closeSheet}
		centeredOnWide
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

		{#snippet footer()}
			{#if failure}
				<div class="footer-error">
					<ErrorNotice code={failure.code} params={failure.params} />
				</div>
			{/if}
			{#if editing && confirmDelete}
				<p class="confirm-text">
					{m.names_delete_body({ name: domainLabel(editing.name), type: editing.type })}
				</p>
				<div class="actions">
					<Button variant="secondary" onclick={() => (confirmDelete = false)}
						>{m.action_cancel()}</Button
					>
					<Button variant="danger" disabled={busy} onclick={() => void confirmRemove()}
						>{m.action_delete()}</Button
					>
				</div>
			{:else}
				{#if editing}
					<button type="button" class="danger-text" onclick={() => (confirmDelete = true)}>
						{m.names_delete()}
					</button>
				{/if}
				<div class="actions">
					<Button variant="secondary" onclick={closeSheet}>{m.action_cancel()}</Button>
					<Button variant="primary" disabled={busy} onclick={() => void submit()}
						>{m.action_save()}</Button
					>
				</div>
			{/if}
		{/snippet}
	</Sheet>
{/if}

<style>
	.names {
		display: flex;
		flex-direction: column;
		gap: 1rem;
		max-width: 44rem;
	}
	.page-head {
		display: flex;
		flex-wrap: wrap;
		align-items: flex-start;
		justify-content: space-between;
		gap: 0.75rem;
	}
	.lead {
		margin: 0;
		flex: 1 1 16rem;
		color: var(--label-2);
		font-size: 0.9375rem;
	}
	.state,
	.empty {
		margin: 0;
		color: var(--label-2);
	}
	.search {
		width: 100%;
		min-height: 2.75rem;
		padding: 0.5rem 0.75rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		background: var(--surface);
		font: inherit;
	}
	.owner {
		display: flex;
		flex-direction: column;
		gap: 0.375rem;
	}
	.owner-head {
		display: flex;
		flex-wrap: wrap;
		align-items: baseline;
		justify-content: space-between;
		gap: 0.5rem;
		padding: 0 0.25rem;
	}
	.owner-name {
		font-size: 0.9375rem;
		font-weight: 600;
		overflow-wrap: anywhere;
	}
	.owner-meta {
		font-size: 0.75rem;
		color: var(--label-3);
	}
	.rec-row {
		display: grid;
		grid-template-columns: 3.5rem minmax(0, 1fr) auto auto;
		align-items: center;
		gap: 0.5rem 0.75rem;
		width: 100%;
		min-height: 2.75rem;
		padding: 0.5rem 1rem;
		border: none;
		border-top: 1px solid var(--separator);
		background: transparent;
		color: var(--label);
		font: inherit;
		text-align: start;
		cursor: pointer;
	}
	.rec-row:first-child {
		border-top: none;
	}
	.rec-row:hover:not(:disabled) {
		background: var(--surface-2);
	}
	.rec-row:disabled {
		cursor: default;
	}
	.type {
		font-size: 0.75rem;
		font-weight: 700;
		letter-spacing: 0.04em;
		color: var(--accent);
	}
	.rdata {
		min-width: 0;
		font-size: 0.875rem;
		overflow-wrap: anywhere;
	}
	.meta {
		font-size: 0.75rem;
		color: var(--label-3);
		white-space: nowrap;
	}
	.chevron {
		display: inline-flex;
		color: var(--label-3);
	}
	.footnote {
		margin: 0;
		font-size: 0.8125rem;
		color: var(--label-3);
	}
	.mono {
		font-family: var(--font-mono);
	}
	.sr-only {
		position: absolute;
		width: 1px;
		height: 1px;
		padding: 0;
		margin: -1px;
		overflow: hidden;
		clip: rect(0, 0, 0, 0);
		white-space: nowrap;
		border: 0;
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
	.area {
		min-height: 4rem;
	}
	.footer-error {
		margin-bottom: 0.75rem;
	}
	.confirm-text {
		margin: 0 0 0.75rem;
		color: var(--label-2);
	}
	.danger-text {
		display: block;
		margin: 0 0 0.75rem;
		padding: 0;
		border: none;
		background: transparent;
		color: var(--danger);
		font: inherit;
		font-weight: 600;
		cursor: pointer;
		text-align: start;
	}
	.actions {
		display: flex;
		justify-content: flex-end;
		gap: 0.5rem;
	}
</style>
