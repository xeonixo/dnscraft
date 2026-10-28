<script lang="ts">
	import { onMount } from 'svelte';
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import ResultNotice from '$lib/components/ResultNotice.svelte';
	import Sheet from '$lib/components/Sheet.svelte';
	import UnavailableNotice from '$lib/components/UnavailableNotice.svelte';
	import { createClientId, listClientIds, listViews, revokeClientId } from '$lib/api/policy';
	import { get } from '$lib/api/client';
	import { failureOf, settle, type Result } from '$lib/api/result';
	import { auth } from '$lib/auth/state.svelte';
	import { m } from '$lib/paraglide/messages';

	const isAdmin = $derived(auth.role === 'admin');
	let result = $state<Result<string[]>>({ kind: 'loading' });
	let tlsHost = $state('dns.example.test');
	let sheetOpen = $state(false);
	let busy = $state(false);
	let failure = $state<{ code: string; params: Record<string, unknown> } | null>(null);
	let newId = $state('');

	async function load(): Promise<void> {
		result = await settle(listClientIds());
		try {
			const status = await get<{ tls?: { identifiers?: string[] } }>('/status');
			const names = status.tls?.identifiers;
			if (names?.[0]) tlsHost = names[0];
		} catch {
			// keep default host label
		}
		await settle(listViews());
	}

	function generateId(): void {
		const chars = 'abcdefghijklmnopqrstuvwxyz0123456789-';
		let id = '';
		for (let i = 0; i < 12; i++) id += chars[Math.floor(Math.random() * chars.length)];
		newId = id;
	}

	function endpoints(id: string): { doh: string; dot: string } {
		return {
			doh: `https://${tlsHost}/dns-query/${id}`,
			dot: `${id}.${tlsHost}`,
		};
	}

	async function submit(): Promise<void> {
		busy = true;
		failure = null;
		try {
			await createClientId(newId.trim());
			sheetOpen = false;
			await load();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	async function revoke(id: string): Promise<void> {
		busy = true;
		try {
			await revokeClientId(id);
			await load();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	onMount(() => {
		void load();
		generateId();
	});
</script>

<p class="lead">{m.doh_lead()}</p>

{#if result.kind === 'loading'}
	<p class="state">{m.state_loading()}</p>
{:else if result.kind === 'unavailable'}
	<UnavailableNotice />
{:else if result.kind === 'error'}
	<ResultNotice {result} onretry={() => void load()} />
{:else}
	<div class="section-head">{m.doh_section()}</div>
	<GroupedList>
		{#each result.data as id (id)}
			<GroupedRow label={id} detail={endpoints(id).doh} mono detailMono>
				{#snippet trailing()}
					{#if isAdmin}
						<Button variant="danger" disabled={busy} onclick={() => void revoke(id)}>
							{m.action_delete()}
						</Button>
					{/if}
				{/snippet}
			</GroupedRow>
		{:else}
			<GroupedRow label={m.state_empty()} />
		{/each}
		{#if isAdmin}
			<button
				type="button"
				class="add-row"
				onclick={() => {
					generateId();
					sheetOpen = true;
				}}
			>
				{m.doh_add()}
			</button>
		{/if}
	</GroupedList>
	<p class="footnote">{m.doh_footnote()}</p>
{/if}

{#if sheetOpen && isAdmin}
	<Sheet open={sheetOpen} title={m.doh_add()} onclose={() => (sheetOpen = false)}>
		<label class="field-label" for="doh-id">{m.doh_id_label()}</label>
		<div class="id-row">
			<input id="doh-id" class="field mono" bind:value={newId} />
			<Button variant="secondary" onclick={generateId}>{m.doh_regenerate()}</Button>
		</div>
		<p class="hint">{m.doh_endpoints_label()}</p>
		<GroupedList>
			<GroupedRow label={m.doh_endpoint_doh()} detail={endpoints(newId).doh} mono detailMono />
			<GroupedRow label={m.doh_endpoint_dot()} detail={endpoints(newId).dot} mono detailMono />
		</GroupedList>
		<p class="warn">{m.doh_unknown_warn()}</p>
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
	.footnote,
	.hint,
	.warn {
		margin-top: 0.75rem;
		font-size: 0.8125rem;
		color: var(--label-3);
	}
	.warn {
		color: var(--warn);
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
	.field-label {
		display: block;
		margin: 0.75rem 0 0.25rem;
		font-size: 0.8125rem;
		color: var(--label-2);
	}
	.field {
		flex: 1;
		min-height: 2.75rem;
		padding: 0.5rem 0.75rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		font: inherit;
	}
	.mono {
		font-family: var(--font-mono);
	}
	.id-row {
		display: flex;
		gap: 0.5rem;
		align-items: center;
	}
	.sheet-actions {
		display: flex;
		justify-content: flex-end;
		gap: 0.5rem;
		margin-top: 1rem;
	}
</style>
