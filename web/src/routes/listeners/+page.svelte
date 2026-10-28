<script lang="ts">
	import { onMount } from 'svelte';
	import Banner from '$lib/components/Banner.svelte';
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import Sheet from '$lib/components/Sheet.svelte';
	import Switch from '$lib/components/Switch.svelte';
	import UnavailableNotice from '$lib/components/UnavailableNotice.svelte';
	import { listClusterNodes } from '$lib/api/cluster';
	import { getConfig, ifMatchFor } from '$lib/api/config';
	import {
		deleteListener,
		listListeners,
		saveListener,
		type Listener,
		type ListenerBody,
	} from '$lib/api/listeners';
	import { failureOf, settle, type Result } from '$lib/api/result';
	import { auth } from '$lib/auth/state.svelte';
	import { displayText } from '$lib/safe-text';
	import { m } from '$lib/paraglide/messages';

	const isAdmin = $derived(auth.role === 'admin');
	const protocols: ListenerBody['protocol'][] = ['udp53', 'tcp53', 'dot', 'doh', 'doq'];

	let result = $state<Result<Listener[]>>({ kind: 'loading' });
	let configVersion = $state<number | null>(null);
	let clusterNodeIds = $state<string[]>([]);
	let sheetOpen = $state(false);
	let editing = $state<Listener | null>(null);
	let busy = $state(false);
	let failure = $state<{ code: string; params: Record<string, unknown> } | null>(null);

	let formId = $state('');
	let formProtocol = $state<ListenerBody['protocol']>('doh');
	let formAddress = $state('127.0.0.1:443');
	let formPublic = $state(false);
	let formH3 = $state(false);
	/** Empty = every node. */
	let formNodes = $state<string[]>([]);

	const hasPublic = $derived(
		result.kind === 'ok' && result.data.some((l) => l.exposure === 'public'),
	);

	const nodeChoices = $derived.by(() => {
		const ids = [...clusterNodeIds];
		for (const id of formNodes) {
			if (!ids.includes(id)) ids.push(id);
		}
		return ids;
	});

	const grouped = $derived.by(() => {
		if (result.kind !== 'ok') return [] as { protocol: Listener['protocol']; rows: Listener[] }[];
		const rows = result.data;
		return protocols.map((protocol) => ({
			protocol,
			rows: rows.filter((listener: Listener) => listener.protocol === protocol),
		}));
	});

	function protocolLabel(protocol: string): string {
		const labels: Record<string, () => string> = {
			udp53: () => m.listeners_protocol_udp53(),
			tcp53: () => m.listeners_protocol_tcp53(),
			dot: () => m.listeners_protocol_dot(),
			doh: () => m.listeners_protocol_doh(),
			doq: () => m.listeners_protocol_doq(),
		};
		return labels[protocol]?.() ?? protocol;
	}

	function nodesDetail(listener: Listener): string {
		if (listener.nodes.length === 0) return m.listeners_nodes_all();
		return listener.nodes.join(', ');
	}

	function toggleNode(id: string, checked: boolean): void {
		if (checked) {
			if (!formNodes.includes(id)) formNodes = [...formNodes, id];
			return;
		}
		formNodes = formNodes.filter((node) => node !== id);
	}

	function rowDetail(listener: Listener): string {
		const exposure =
			listener.exposure === 'public'
				? m.listeners_exposure_public()
				: m.listeners_exposure_local();
		const parts = [listener.address, exposure, nodesDetail(listener)];
		if (listener.h3) parts.push('h3');
		return parts.join(' · ');
	}

	async function load(): Promise<void> {
		const [listeners, config, nodes] = await Promise.all([
			settle(listListeners()),
			getConfig().catch(() => null),
			listClusterNodes().catch(() => []),
		]);
		result = listeners;
		configVersion = config?.version ?? null;
		clusterNodeIds = nodes.map((node) => node.node_id);
	}

	function openCreate(): void {
		editing = null;
		formId = '';
		formProtocol = 'doh';
		formAddress = '127.0.0.1:443';
		formPublic = false;
		formH3 = false;
		formNodes = [];
		failure = null;
		sheetOpen = true;
	}

	function openEdit(listener: Listener): void {
		editing = listener;
		formId = listener.id;
		formProtocol = listener.protocol;
		formAddress = listener.address;
		formPublic = listener.exposure === 'public';
		formH3 = listener.h3;
		formNodes = [...listener.nodes];
		failure = null;
		sheetOpen = true;
	}

	async function submit(): Promise<void> {
		if (!isAdmin) return;
		busy = true;
		failure = null;
		const body: ListenerBody = {
			id: formId.trim(),
			protocol: formProtocol,
			address: formAddress.trim(),
			exposure: formPublic ? 'public' : 'local',
			h3: formH3,
			nodes: formNodes,
		};
		try {
			const saved = await saveListener(body, { ifMatch: ifMatchFor(configVersion) });
			configVersion = saved.version;
			sheetOpen = false;
			await load();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	async function remove(listener: Listener): Promise<void> {
		if (!isAdmin || !globalThis.confirm(m.listeners_delete_confirm({ id: listener.id }))) return;
		busy = true;
		try {
			const deleted = await deleteListener(listener.id, { ifMatch: ifMatchFor(configVersion) });
			configVersion = deleted.version;
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

<div class="header">
	<p class="lead">{m.listeners_lead()}</p>
	{#if isAdmin && result.kind === 'ok'}
		<Button variant="primary" onclick={openCreate}>{m.listeners_add()}</Button>
	{/if}
</div>

{#if hasPublic}
	<div class="banner-wrap">
		<Banner title={m.listeners_exposure_banner_title()}>
			<p>{m.listeners_exposure_banner_body()}</p>
		</Banner>
	</div>
{/if}

{#if failure}
	<div class="notice">
		<ErrorNotice code={failure.code} params={failure.params} />
	</div>
{/if}

{#if result.kind === 'loading'}
	<p class="state">{m.state_loading()}</p>
{:else if result.kind === 'unavailable'}
	<UnavailableNotice />
{:else if result.kind === 'error'}
	<ErrorNotice code={result.code} params={result.params} />
{:else}
	{#each grouped as group (group.protocol)}
		{#if group.rows.length > 0}
			<GroupedList header={protocolLabel(group.protocol)}>
				{#each group.rows as listener (listener.id)}
					<GroupedRow
						label={displayText(listener.id).text}
						detail={rowDetail(listener)}
						detailMono
					>
						{#snippet trailing()}
							{#if isAdmin}
								<div class="row-actions">
									<Button onclick={() => openEdit(listener)}>{m.action_edit()}</Button>
									<Button variant="danger" disabled={busy} onclick={() => void remove(listener)}>
										{m.action_delete()}
									</Button>
								</div>
							{/if}
						{/snippet}
					</GroupedRow>
				{/each}
			</GroupedList>
		{/if}
	{/each}

	{#if result.data.length === 0}
		<GroupedList header={m.listeners_empty_title()}>
			<GroupedRow label={m.listeners_empty_body()} />
		</GroupedList>
	{/if}

	<p class="footnote">{m.listeners_footnote()}</p>
{/if}

{#if sheetOpen && isAdmin}
	<Sheet
		open={true}
		title={editing ? m.listeners_edit_title() : m.listeners_add_title()}
		onclose={() => (sheetOpen = false)}
	>
		<label class="field-label" for="listener-id">{m.listeners_id_label()}</label>
		<input id="listener-id" class="field" bind:value={formId} disabled={editing !== null} />

		<label class="field-label" for="listener-protocol">{m.listeners_protocol_label()}</label>
		<select id="listener-protocol" class="field" bind:value={formProtocol}>
			{#each protocols as protocol (protocol)}
				<option value={protocol}>{protocolLabel(protocol)}</option>
			{/each}
		</select>

		<label class="field-label" for="listener-address">{m.listeners_address_label()}</label>
		<input id="listener-address" class="field mono" bind:value={formAddress} />

		{#if nodeChoices.length > 0}
			<p class="field-label" id="listener-nodes-label">{m.listeners_nodes_label()}</p>
			<div class="node-list" role="group" aria-labelledby="listener-nodes-label" aria-describedby="listener-nodes-hint">
				{#each nodeChoices as nodeId (nodeId)}
					<label class="node-row">
						<input
							type="checkbox"
							checked={formNodes.includes(nodeId)}
							onchange={(event) =>
								toggleNode(nodeId, (event.currentTarget as HTMLInputElement).checked)}
						/>
						<span class="mono">{displayText(nodeId).text}</span>
					</label>
				{/each}
			</div>
			<p id="listener-nodes-hint" class="hint">{m.listeners_nodes_hint()}</p>
		{/if}

		<label class="public-row">
			<Switch bind:checked={formPublic} aria-label={m.listeners_exposure_public()} />
			<span>{m.listeners_exposure_public()}</span>
		</label>

		{#if formProtocol === 'doh'}
			<label class="public-row">
				<Switch bind:checked={formH3} aria-label={m.listeners_h3_label()} />
				<span>{m.listeners_h3_label()}</span>
			</label>
		{/if}

		{#if failure}
			<div class="notice">
				<ErrorNotice code={failure.code} params={failure.params} />
			</div>
		{/if}

		<div class="actions">
			<Button onclick={() => (sheetOpen = false)}>{m.action_cancel()}</Button>
			<Button variant="primary" disabled={busy || formId.trim() === ''} onclick={submit}>
				{m.action_save()}
			</Button>
		</div>
	</Sheet>
{/if}

<style>
	.header {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		justify-content: space-between;
		gap: 0.5rem 1rem;
		margin-bottom: 0.75rem;
	}

	.lead {
		margin: 0;
		flex: 1 1 14rem;
		color: var(--label-2);
		font-size: 0.9375rem;
		line-height: 1.35;
	}

	.banner-wrap {
		margin-bottom: 1rem;
	}

	.row-actions {
		display: flex;
		flex-wrap: wrap;
		gap: 0.375rem;
		justify-content: flex-end;
	}

	.state,
	.footnote,
	.hint {
		margin: 0.75rem 0 0;
		color: var(--label-2);
		font-size: 0.84375rem;
	}

	.hint {
		margin: -0.25rem 0 1rem;
	}

	.node-list {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
		margin: 0 0 0.5rem;
	}

	.node-row {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		min-height: 2.25rem;
		cursor: pointer;
	}

	.node-row input {
		width: 1rem;
		height: 1rem;
		accent-color: var(--accent-solid);
	}

	.node-row .mono {
		font-family: var(--font-mono, ui-monospace, SFMono-Regular, Menlo, monospace);
		font-size: 0.875rem;
	}

	.notice {
		margin-bottom: 0.75rem;
	}

	.field-label {
		display: block;
		margin: 0 0 0.375rem;
		font-size: 0.84375rem;
		color: var(--label-2);
	}

	.field {
		width: 100%;
		min-height: 2.75rem;
		margin-bottom: 1rem;
		padding: 0.5rem 0.75rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-control);
		background: var(--surface);
		color: var(--label);
		font: inherit;
		box-sizing: border-box;
	}

	.field.mono {
		font-family: var(--font-mono, ui-monospace, SFMono-Regular, Menlo, monospace);
	}

	.public-row {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		min-height: 2.75rem;
		margin-bottom: 0.5rem;
	}

	.actions {
		display: flex;
		flex-wrap: wrap;
		justify-content: flex-end;
		gap: 0.5rem;
		margin-top: 1rem;
	}
</style>
