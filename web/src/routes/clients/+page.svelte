<script lang="ts">
	import { onMount } from 'svelte';
	import { resolve } from '$app/paths';
	import Button from '$lib/components/Button.svelte';
	import ConfirmSheet from '$lib/components/ConfirmSheet.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import ResultNotice from '$lib/components/ResultNotice.svelte';
	import Sheet from '$lib/components/Sheet.svelte';
	import UnavailableNotice from '$lib/components/UnavailableNotice.svelte';
	import {
		createManualClient,
		deleteManualClient,
		listClients,
		syncClients,
		type ClientsPage,
		type DirectoryClient,
	} from '$lib/api/clients';
	import { ApiError } from '$lib/api/client';
	import { failureOf, settle, type Result } from '$lib/api/result';
	import { auth } from '$lib/auth/state.svelte';
	import { parseCidr, parseIp } from '$lib/policy/cidr';
	import { displayText } from '$lib/safe-text';
	import { m } from '$lib/paraglide/messages';

	const isAdmin = $derived(auth.role === 'admin');
	let result = $state<Result<ClientsPage>>({ kind: 'loading' });
	let search = $state('');
	let sheetOpen = $state(false);
	let busy = $state(false);
	let failure = $state<{ code: string; params: Record<string, unknown> } | null>(null);
	let syncNote = $state<string | null>(null);
	let formName = $state('');
	let formIp = $state('');
	let formDomain = $state('');
	let deleteTarget = $state<string | null>(null);
	let submitted = $state(false);

	const nameError = $derived(
		submitted && formName.trim() === '' ? m.clients_name_required() : null,
	);
	const ipError = $derived.by(() => {
		const ip = formIp.trim();
		if (ip === '') return submitted ? m.clients_ip_invalid() : null;
		return ip.includes('/')
			? parseCidr(ip)
				? null
				: m.clients_ip_invalid()
			: parseIp(ip)
				? null
				: m.clients_ip_invalid();
	});

	const filtered = $derived.by(() => {
		if (result.kind !== 'ok') return { synced: [] as DirectoryClient[], manual: [] };
		const needle = search.trim().toLowerCase();
		const match = (text: string) => !needle || text.toLowerCase().includes(needle);
		// A manual entry also shows up in the directory after a sync: list it under manual only.
		const manualNames = new Set(result.data.manual.map((c) => c.name));
		return {
			synced: result.data.clients
				.filter((c) => !(c.source === 'manual' && manualNames.has(c.name)))
				.filter((c) => match(c.name) || c.ips.some((ip) => match(ip)) || match(c.id)),
			manual: result.data.manual.filter((c) => match(c.name)),
		};
	});

	async function load(): Promise<void> {
		result = await settle(listClients());
	}

	async function sync(): Promise<void> {
		busy = true;
		syncNote = null;
		failure = null;
		try {
			const summary = await syncClients();
			syncNote = m.clients_sync_ok({
				count: summary.client_count,
				conflicts: summary.ip_conflicts,
			});
			await load();
		} catch (cause) {
			if (cause instanceof ApiError && cause.status === 404) {
				syncNote = m.dashboard_unavailable_title();
			} else {
				failure = failureOf(cause);
			}
		} finally {
			busy = false;
		}
	}

	function openManual(): void {
		formName = '';
		formIp = '';
		formDomain = '';
		submitted = false;
		failure = null;
		sheetOpen = true;
	}

	async function submitManual(): Promise<void> {
		submitted = true;
		if (formName.trim() === '' || ipError || formIp.trim() === '') return;
		busy = true;
		failure = null;
		const body = formIp.includes('/')
			? { name: formName.trim(), cidr: formIp.trim(), domain: formDomain.trim() || undefined }
			: { name: formName.trim(), ip: formIp.trim(), domain: formDomain.trim() || undefined };
		try {
			await createManualClient(body);
			sheetOpen = false;
			await load();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	async function removeManual(name: string): Promise<void> {
		busy = true;
		failure = null;
		try {
			await deleteManualClient(name);
			deleteTarget = null;
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

<p class="lead">{m.clients_lead()}</p>
<label class="search-label" for="client-search">{m.clients_search_label()}</label>
<input
	id="client-search"
	class="search field"
	bind:value={search}
	placeholder={m.clients_search_placeholder()}
/>

{#if result.kind === 'loading'}
	<p class="state">{m.state_loading()}</p>
{:else if result.kind === 'unavailable'}
	<UnavailableNotice />
{:else if result.kind === 'error'}
	<ResultNotice {result} onretry={() => void load()} />
{:else}
	{#if isAdmin}
		<div class="toolbar">
			<Button disabled={busy} onclick={() => void sync()}>{m.clients_sync()}</Button>
			<Button onclick={openManual}>{m.clients_add_manual()}</Button>
		</div>
	{/if}
	{#if syncNote}<p class="note">{syncNote}</p>{/if}
	{#if failure && !sheetOpen && !deleteTarget}<ErrorNotice
			code={failure.code}
			params={failure.params}
		/>{/if}

	<div class="section-head">{m.clients_section_synced()}</div>
	<GroupedList>
		{#each filtered.synced as client (client.id)}
			<GroupedRow
				label={displayText(client.name).text}
				detail="{client.source} · {client.ips.join(' · ')}"
				mono
				detailMono
			>
				{#snippet trailing()}
					<span class="tag">{client.source}</span>
				{/snippet}
			</GroupedRow>
		{:else}
			<GroupedRow label={search.trim() ? m.clients_nothing_found() : m.clients_empty()} />
		{/each}
	</GroupedList>

	<div class="section-head">{m.clients_section_manual()}</div>
	<GroupedList>
		{#each filtered.manual as entry (entry.name)}
			<GroupedRow
				label={displayText(entry.name).text}
				detail={entry.identity ?? entry.ip ?? entry.cidr ?? ''}
				mono
			>
				{#snippet trailing()}
					{#if isAdmin}
						<Button variant="danger" disabled={busy} onclick={() => (deleteTarget = entry.name)}>
							{m.action_delete()}
						</Button>
					{/if}
				{/snippet}
			</GroupedRow>
		{:else}
			<GroupedRow label={search.trim() ? m.clients_nothing_found() : m.clients_empty()} />
		{/each}
	</GroupedList>
	<p class="footnote">{m.clients_footnote()}</p>
	{#if isAdmin}
		<p class="footnote">
			<a href={resolve('/settings')}>{m.clients_unifi_settings_link()}</a>
		</p>
	{/if}
{/if}

{#if sheetOpen && isAdmin}
	<Sheet open={sheetOpen} title={m.clients_add_manual()} onclose={() => (sheetOpen = false)}>
		<label class="field-label" for="mc-name">{m.clients_field_name()}</label>
		<input
			id="mc-name"
			class="field"
			bind:value={formName}
			aria-invalid={nameError ? 'true' : undefined}
		/>
		{#if nameError}<p class="error-text" role="alert">{nameError}</p>{/if}
		<label class="field-label" for="mc-ip">{m.clients_field_ip()}</label>
		<input
			id="mc-ip"
			class="field mono"
			bind:value={formIp}
			aria-invalid={ipError ? 'true' : undefined}
		/>
		{#if ipError}<p class="error-text" role="alert">{ipError}</p>{/if}
		<label class="field-label" for="mc-domain">{m.clients_field_domain()}</label>
		<input id="mc-domain" class="field mono" bind:value={formDomain} />
		{#if failure}<ErrorNotice code={failure.code} params={failure.params} />{/if}
		<div class="sheet-actions">
			<Button variant="secondary" onclick={() => (sheetOpen = false)}>{m.action_cancel()}</Button>
			<Button variant="primary" disabled={busy} onclick={() => void submitManual()}
				>{m.action_save()}</Button
			>
		</div>
	</Sheet>
{/if}

{#if deleteTarget !== null && isAdmin}
	<ConfirmSheet
		title={m.clients_delete_title()}
		body={m.clients_delete_body({ name: displayText(deleteTarget).text })}
		{busy}
		{failure}
		oncancel={() => (deleteTarget = null)}
		onconfirm={() => void removeManual(deleteTarget ?? '')}
	/>
{/if}

<style>
	.error-text {
		margin: 0.25rem 0 0;
		font-size: 0.8125rem;
		color: var(--danger);
	}
	.lead {
		margin: 0 0 0.75rem;
		color: var(--label-2);
	}
	.search-label {
		display: block;
		font-size: 0.8125rem;
		color: var(--label-2);
		margin-bottom: 0.25rem;
	}
	.search {
		width: 100%;
		min-height: 2.75rem;
		margin-bottom: 1rem;
		padding: 0.5rem 0.75rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		font: inherit;
	}
	.toolbar {
		display: flex;
		flex-wrap: wrap;
		gap: 0.5rem;
		margin-bottom: 0.75rem;
	}
	.section-head {
		margin: 1rem 0 0.5rem;
		font-size: 0.8125rem;
		font-weight: 600;
		color: var(--label-3);
		text-transform: uppercase;
	}
	.tag {
		font-size: 0.75rem;
		color: var(--label-2);
	}
	.note {
		margin: 0 0 0.75rem;
		color: var(--label-2);
		font-size: 0.875rem;
	}
	.footnote {
		margin-top: 0.75rem;
		font-size: 0.8125rem;
		color: var(--label-3);
	}
	.footnote a {
		color: var(--accent);
		text-decoration: none;
	}
	.footnote a:hover {
		text-decoration: underline;
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
	.sheet-actions {
		display: flex;
		justify-content: flex-end;
		gap: 0.5rem;
		margin-top: 1rem;
	}
	.state {
		color: var(--label-2);
	}
</style>
