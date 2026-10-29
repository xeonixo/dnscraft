<script lang="ts">
	import { onMount } from 'svelte';
	import Banner from '$lib/components/Banner.svelte';
	import Button from '$lib/components/Button.svelte';
	import ConfirmSheet from '$lib/components/ConfirmSheet.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import NodeChecklist from '$lib/components/NodeChecklist.svelte';
	import Segmented from '$lib/components/Segmented.svelte';
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
	import { formatNodesDetail, nodeChoicesFor, toggleNodeId } from '$lib/cluster/nodes';
	import { allowsPublic, suggestListenerId, type AddrFamily } from '$lib/listeners/id';
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
	let deleteTarget = $state<Listener | null>(null);

	let formProtocol = $state<ListenerBody['protocol']>('doh');
	let formFamily = $state<AddrFamily>('ipv4');
	let formAddress = $state('127.0.0.1:443');
	let formPublic = $state(false);
	let formH3 = $state(false);
	/** Empty = every node. */
	let formNodes = $state<string[]>([]);

	const hasPublic = $derived(
		result.kind === 'ok' && result.data.some((l) => l.exposure === 'public'),
	);
	const canBePublic = $derived(allowsPublic(formProtocol));
	const existingIds = $derived(result.kind === 'ok' ? result.data.map((row) => row.id) : []);
	const previewId = $derived(
		editing?.id ??
			suggestListenerId(formProtocol, formFamily, formPublic && canBePublic, existingIds),
	);

	const nodeChoices = $derived(nodeChoicesFor(clusterNodeIds, formNodes));

	const familyOptions: { value: AddrFamily; label: string }[] = [
		{ value: 'ipv4', label: m.listeners_family_ipv4() },
		{ value: 'ipv6', label: m.listeners_family_ipv6() },
	];

	function defaultPort(protocol: ListenerBody['protocol']): string {
		switch (protocol) {
			case 'udp53':
			case 'tcp53':
				return '53';
			case 'dot':
			case 'doq':
				return '853';
			case 'doh':
				return '443';
		}
	}

	function defaultHost(family: AddrFamily, isPublic: boolean): string {
		if (family === 'ipv6') return isPublic ? '[::]' : '[::1]';
		return isPublic ? '0.0.0.0' : '127.0.0.1';
	}

	function composeAddress(
		family: AddrFamily,
		protocol: ListenerBody['protocol'],
		isPublic: boolean,
	): string {
		return `${defaultHost(family, isPublic)}:${defaultPort(protocol)}`;
	}

	function detectFamily(address: string): AddrFamily {
		const trimmed = address.trim();
		if (trimmed.startsWith('[') || trimmed.includes('::')) return 'ipv6';
		return 'ipv4';
	}

	function isStockHost(host: string): boolean {
		return (
			host === '127.0.0.1' ||
			host === '0.0.0.0' ||
			host === '[::1]' ||
			host === '[::]' ||
			host === '::1' ||
			host === '::'
		);
	}

	function splitHostPort(address: string): { host: string; port: string | null } {
		const trimmed = address.trim();
		if (!trimmed) return { host: '', port: null };
		if (trimmed.startsWith('[')) {
			const end = trimmed.indexOf(']');
			if (end > 0) {
				const rest = trimmed.slice(end + 1);
				if (rest.startsWith(':') && /^\d+$/.test(rest.slice(1))) {
					return { host: trimmed.slice(0, end + 1), port: rest.slice(1) };
				}
				return { host: trimmed.slice(0, end + 1), port: null };
			}
		}
		const colon = trimmed.lastIndexOf(':');
		if (colon > 0 && /^\d+$/.test(trimmed.slice(colon + 1))) {
			return { host: trimmed.slice(0, colon), port: trimmed.slice(colon + 1) };
		}
		return { host: trimmed, port: null };
	}

	/** Keep a custom host; rewrite stock hosts and always apply the protocol port. */
	function withProtocolPort(
		address: string,
		protocol: ListenerBody['protocol'],
		family: AddrFamily,
		isPublic: boolean,
	): string {
		const port = defaultPort(protocol);
		const { host } = splitHostPort(address);
		if (!host || isStockHost(host)) {
			return composeAddress(family, protocol, isPublic);
		}
		return `${host}:${port}`;
	}

	function onProtocolChange(protocol: ListenerBody['protocol']): void {
		const nextPublic = allowsPublic(protocol) ? formPublic : false;
		formProtocol = protocol;
		formPublic = nextPublic;
		formAddress = withProtocolPort(formAddress, protocol, formFamily, nextPublic);
		if (protocol !== 'doh') formH3 = false;
	}

	function onFamilyChange(family: AddrFamily): void {
		formFamily = family;
		formAddress = composeAddress(family, formProtocol, formPublic && allowsPublic(formProtocol));
	}

	function onPublicChange(checked: boolean): void {
		formPublic = checked;
		const { host } = splitHostPort(formAddress);
		if (!host || isStockHost(host)) {
			formAddress = composeAddress(formFamily, formProtocol, checked);
		}
	}

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

	function toggleNode(id: string, checked: boolean): void {
		formNodes = toggleNodeId(formNodes, id, checked);
	}

	function rowLabel(listener: Listener): string {
		const exposure =
			listener.exposure === 'public' ? m.listeners_exposure_public() : m.listeners_exposure_local();
		return `${protocolLabel(listener.protocol)} · ${exposure}`;
	}

	function rowDetail(listener: Listener): string {
		const parts = [listener.address, formatNodesDetail(listener.nodes)];
		if (listener.h3) parts.push('h3');
		parts.push(displayText(listener.id).text);
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
		formProtocol = 'doh';
		formFamily = 'ipv4';
		formPublic = false;
		formAddress = composeAddress('ipv4', 'doh', false);
		formH3 = false;
		formNodes = [];
		failure = null;
		sheetOpen = true;
	}

	function openEdit(listener: Listener): void {
		editing = listener;
		formProtocol = listener.protocol;
		formFamily = detectFamily(listener.address);
		formAddress = listener.address;
		formPublic = listener.exposure === 'public' && allowsPublic(listener.protocol);
		formH3 = listener.h3;
		formNodes = [...listener.nodes];
		failure = null;
		sheetOpen = true;
	}

	async function submit(): Promise<void> {
		if (!isAdmin) return;
		busy = true;
		failure = null;
		const isPublic = formPublic && allowsPublic(formProtocol);
		const body: ListenerBody = {
			id: editing?.id ?? suggestListenerId(formProtocol, formFamily, isPublic, existingIds),
			protocol: formProtocol,
			address: formAddress.trim(),
			exposure: isPublic ? 'public' : 'local',
			h3: formProtocol === 'doh' && formH3,
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
		if (!isAdmin) return;
		busy = true;
		failure = null;
		try {
			const deleted = await deleteListener(listener.id, { ifMatch: ifMatchFor(configVersion) });
			configVersion = deleted.version;
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

{#if failure && !deleteTarget}
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
					<GroupedRow label={rowLabel(listener)} detail={rowDetail(listener)} detailMono>
						{#snippet trailing()}
							{#if isAdmin}
								<div class="row-actions">
									<Button onclick={() => openEdit(listener)}>{m.action_edit()}</Button>
									<Button
										variant="danger"
										disabled={busy}
										onclick={() => (deleteTarget = listener)}
									>
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
		<label class="field-label" for="listener-protocol">{m.listeners_protocol_label()}</label>
		<select
			id="listener-protocol"
			class="field"
			value={formProtocol}
			onchange={(event) =>
				onProtocolChange(
					(event.currentTarget as HTMLSelectElement).value as ListenerBody['protocol'],
				)}
		>
			{#each protocols as protocol (protocol)}
				<option value={protocol}>{protocolLabel(protocol)}</option>
			{/each}
		</select>

		<p class="field-label">{m.listeners_family_label()}</p>
		<Segmented
			options={familyOptions}
			bind:value={formFamily}
			label={m.listeners_family_label()}
			onchange={onFamilyChange}
		/>

		<label class="field-label" for="listener-address">{m.listeners_address_label()}</label>
		<input id="listener-address" class="field mono" bind:value={formAddress} />
		<p class="hint tight">{m.listeners_address_hint()}</p>

		<NodeChecklist
			nodeIds={nodeChoices}
			selected={formNodes}
			label={m.listeners_nodes_label()}
			hint={m.listeners_nodes_hint()}
			solo={m.zones_nodes_solo()}
			labelId="listener-nodes-label"
			hintId="listener-nodes-hint"
			ontoggle={toggleNode}
		/>

		{#if canBePublic}
			<label class="public-row">
				<Switch
					bind:checked={formPublic}
					aria-label={m.listeners_exposure_public()}
					onchange={(event) => onPublicChange((event.currentTarget as HTMLInputElement).checked)}
				/>
				<span>{m.listeners_exposure_public()}</span>
			</label>
			<p class="hint tight">{m.listeners_exposure_public_hint()}</p>
		{:else}
			<p class="hint tight">{m.listeners_exposure_plaintext_hint()}</p>
		{/if}

		{#if formProtocol === 'doh'}
			<label class="public-row">
				<Switch bind:checked={formH3} aria-label={m.listeners_h3_label()} />
				<span>{m.listeners_h3_label()}</span>
			</label>
		{/if}

		<p class="hint tight mono" title={m.listeners_id_label()}>
			{m.listeners_id_label()}: {previewId}
		</p>
		{#if editing === null}
			<p class="hint tight">{m.listeners_id_auto()}</p>
		{/if}

		{#if failure}
			<div class="notice">
				<ErrorNotice code={failure.code} params={failure.params} />
			</div>
		{/if}

		<div class="actions">
			<Button onclick={() => (sheetOpen = false)}>{m.action_cancel()}</Button>
			<Button variant="primary" disabled={busy || formAddress.trim() === ''} onclick={submit}>
				{m.action_save()}
			</Button>
		</div>
	</Sheet>
{/if}

{#if deleteTarget && isAdmin}
	<ConfirmSheet
		title={m.listeners_delete_title()}
		body={m.listeners_delete_body({ id: displayText(deleteTarget.id).text })}
		{busy}
		{failure}
		oncancel={() => (deleteTarget = null)}
		onconfirm={() => deleteTarget && void remove(deleteTarget)}
	/>
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
		line-height: 1.35;
	}

	.hint.tight {
		margin: -0.5rem 0 1rem;
	}

	.hint.mono {
		font-family: var(--font-mono, ui-monospace, SFMono-Regular, Menlo, monospace);
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
