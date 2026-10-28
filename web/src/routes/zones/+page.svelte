<script lang="ts">
	import { onMount } from 'svelte';
	import { resolve } from '$app/paths';
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import NodeChecklist from '$lib/components/NodeChecklist.svelte';
	import ResultNotice from '$lib/components/ResultNotice.svelte';
	import Sheet from '$lib/components/Sheet.svelte';
	import Switch from '$lib/components/Switch.svelte';
	import UnavailableNotice from '$lib/components/UnavailableNotice.svelte';
	import { listClusterNodes } from '$lib/api/cluster';
	import { listClients, type DirectoryClient } from '$lib/api/clients';
	import {
		deleteView,
		listClientIds,
		listProfiles,
		listViews,
		saveView,
		type ClientIdEntry,
		type PolicyProfile,
		type PolicyView,
	} from '$lib/api/policy';
	import { failureOf, settle, type Result } from '$lib/api/result';
	import { auth } from '$lib/auth/state.svelte';
	import { formatNodesDetail, nodeChoicesFor, toggleNodeId } from '$lib/cluster/nodes';
	import { m } from '$lib/paraglide/messages';
	import { bestPrefix, findInvalidRange, parseRanges } from '$lib/policy/cidr';
	import { displayText } from '$lib/safe-text';

	type Failure = { code: string; params: Record<string, unknown> };

	/** Ranges / pinned names shown before the rest are counted. */
	const RANGE_PREVIEW = 3;

	const isAdmin = $derived(auth.role === 'admin');
	let result = $state<Result<PolicyView[]>>({ kind: 'loading' });
	let profiles = $state<PolicyProfile[]>([]);
	/** Client IDs with their pinned range; a failed read leaves the pinned lines out. */
	let pinnedIds = $state<ClientIdEntry[]>([]);
	/** Null for viewers or when the directory fails to load: rows then show no device counts. */
	let clients = $state<DirectoryClient[] | null>(null);
	let clusterNodeIds = $state<string[]>([]);
	let sheetOpen = $state(false);
	let busy = $state(false);
	let failure = $state<Failure | null>(null);
	let editing = $state<PolicyView | null>(null);
	let confirmDelete = $state(false);

	let formId = $state('');
	let formDefault = $state(false);
	let formRanges = $state('');
	/** Empty = every node. */
	let formNodes = $state<string[]>([]);
	let formProfile = $state('default');

	/** View ids must match `[a-z0-9-]{1,64}` — same charset as filter-list ids. */
	function slugify(text: string): string {
		return text
			.toLowerCase()
			.replace(/[^a-z0-9]+/g, '-')
			.replace(/^-+|-+$/g, '')
			.slice(0, 64);
	}

	const rows = $derived.by(() => {
		if (result.kind !== 'ok') return [] as PolicyView[];
		return [...result.data].sort((a, b) => Number(b.is_default) - Number(a.is_default));
	});
	const invalidRange = $derived(findInvalidRange(formRanges));
	/** The server refuses to delete a range that a Client ID is pinned to; its error carries the ids. */
	const refusedPinned = $derived(failure?.params.reason === 'view_in_use');
	const canSave = $derived(
		!busy &&
			invalidRange === null &&
			(editing !== null || slugify(formId) !== ''),
	);
	const nodeChoices = $derived(nodeChoicesFor(clusterNodeIds, formNodes));

	function plural(count: number): string {
		return count === 1
			? m.zones_count_devices_one({ count })
			: m.zones_count_devices_other({ count });
	}

	/**
	 * Directory clients served by this range: the most specific range containing the client's IP wins
	 * (as the intro says), so a device in an overlap counts once, for the more specific range.
	 */
	function deviceCount(view: PolicyView): number | null {
		if (clients === null) return null;
		// The default range also serves every address no other range claims, so it may have no ranges.
		if (view.subnets.length === 0 && !view.is_default) return null;
		const own = parseRanges(view.subnets);
		const others = rows.filter((row) => row.id !== view.id).map((row) => parseRanges(row.subnets));
		return clients.filter((client) =>
			client.ips.some((ip) => {
				const mine = bestPrefix(ip, own);
				const best = others.reduce((top, ranges) => Math.max(top, bestPrefix(ip, ranges)), -1);
				return view.is_default ? best < 0 || mine > best : mine >= 0 && mine > best;
			}),
		).length;
	}

	/** Client IDs pinned to this range, in registration order. */
	function pinsOf(viewId: string): ClientIdEntry[] {
		return pinnedIds.filter((entry) => entry.view === viewId);
	}

	/** Names of the first few pinned devices; the caller adds the count of the rest. */
	function pinnedNames(entries: ClientIdEntry[]): string {
		return entries
			.slice(0, RANGE_PREVIEW)
			.map((entry) => displayText(entry.label ?? entry.id, 60).text)
			.join(', ');
	}

	/** Names for the refusal text: the server lists ids, the labels read better when known. */
	function refusedNames(value: unknown): string {
		const ids = Array.isArray(value) ? value.map(String) : [];
		return ids
			.map((id) => displayText(pinnedIds.find((entry) => entry.id === id)?.label ?? id, 60).text)
			.join(', ');
	}

	/** One range per line; blank lines are dropped. */
	function lines(text: string): string[] {
		return text
			.split('\n')
			.map((line) => line.trim())
			.filter((line) => line !== '');
	}

	function rangeParts(view: PolicyView): string[] {
		const parts: string[] = view.subnets
			.slice(0, RANGE_PREVIEW)
			.map((range) => displayText(range, 60).text);
		if (view.subnets.length > RANGE_PREVIEW) {
			parts.push(m.zones_more({ count: view.subnets.length - RANGE_PREVIEW }));
		}
		if (view.is_default) parts.push(m.zones_default_rest());
		return parts;
	}

	function pinSummary(viewId: string): string | null {
		const pins = pinsOf(viewId);
		if (pins.length === 0) return null;
		const names = m.zones_pinned({ names: pinnedNames(pins) });
		if (pins.length > RANGE_PREVIEW) {
			return `${names} ${m.zones_more({ count: pins.length - RANGE_PREVIEW })}`;
		}
		return names;
	}

	function toggleNode(id: string, checked: boolean): void {
		formNodes = toggleNodeId(formNodes, id, checked);
	}

	async function load(): Promise<void> {
		result = { kind: 'loading' };
		const [views, nodes] = await Promise.all([
			settle(listViews()),
			listClusterNodes().catch(() => []),
		]);
		result = views;
		clusterNodeIds = nodes.map((node) => node.node_id);
		if (views.kind === 'ok') {
			const prof = await settle(listProfiles());
			if (prof.kind === 'ok') profiles = prof.data;
		}
		const ids = await settle(listClientIds());
		pinnedIds = ids.kind === 'ok' ? ids.data : [];
	}

	/** The directory is an admin read; any failure just leaves the device counts off. */
	async function loadClients(): Promise<void> {
		try {
			clients = (await listClients()).clients;
		} catch {
			clients = null;
		}
	}

	function resetForm(): void {
		confirmDelete = false;
		failure = null;
		sheetOpen = true;
	}

	function openCreate(): void {
		editing = null;
		formId = '';
		formDefault = false;
		formRanges = '';
		formNodes = [];
		formProfile = profiles[0]?.id ?? 'default';
		resetForm();
	}

	function openEdit(view: PolicyView): void {
		editing = view;
		formId = view.id;
		formDefault = view.is_default;
		formRanges = view.subnets.join('\n');
		formNodes = [...view.nodes];
		formProfile = view.profile;
		resetForm();
	}

	function closeSheet(): void {
		sheetOpen = false;
		confirmDelete = false;
	}

	async function submit(): Promise<void> {
		busy = true;
		failure = null;
		const id = editing?.id ?? slugify(formId);
		if (!id) {
			failure = {
				code: 'policy.config.invalid',
				params: { reason: 'view id must match [a-z0-9-]{1,64}' },
			};
			busy = false;
			return;
		}
		try {
			await saveView(id, {
				is_default: formDefault,
				subnets: lines(formRanges),
				nodes: formNodes,
				profile: formProfile,
			});
			closeSheet();
			await load();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	async function removeView(id: string): Promise<void> {
		busy = true;
		failure = null;
		try {
			await deleteView(id);
			closeSheet();
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
		if (isAdmin) void loadClients();
	});
</script>

<div class="zones">
	<div class="page-head">
		<p class="lead">
			{m.zones_lead()}
			<a href={resolve('/profiles')}>{m.zones_intro_profile()}</a>{m.zones_lead_tail()}
		</p>
		{#if isAdmin && result.kind === 'ok'}
			<Button variant="primary" onclick={openCreate}>{m.zones_add()}</Button>
		{/if}
	</div>

	{#if result.kind === 'loading'}
		<p class="state">{m.state_loading()}</p>
	{:else if result.kind === 'unavailable'}
		<UnavailableNotice />
	{:else if result.kind === 'error'}
		<ResultNotice {result} onretry={() => void load()} />
	{:else if rows.length === 0}
		<section class="empty">
			<p>{m.zones_empty()}</p>
		</section>
	{:else}
		<GroupedList>
			{#each rows as view (view.id)}
				{@const ranges = rangeParts(view)}
				{@const pins = pinSummary(view.id)}
				{@const count = deviceCount(view)}
				{#snippet body()}
					<span class="zone-main">
						<span class="zone-title">
							<span class="zone-name">{displayText(view.id).text}</span>
							{#if view.is_default}
								<span class="badge">{m.zones_badge_default()}</span>
							{/if}
						</span>
						{#if ranges.length > 0}
							<span class="zone-ranges">
								{#each ranges as part, i (part + String(i))}
									{#if i > 0}<span class="sep" aria-hidden="true">·</span>{/if}
									<span class:soft={part === m.zones_default_rest() || part.startsWith('+')}
										>{part}</span
									>
								{/each}
							</span>
						{:else}
							<span class="zone-empty">{m.zones_no_subnets()}</span>
						{/if}
						{#if pins}
							<span class="zone-pins">
								<span class="pins-label">{m.zones_pinned_label()}</span>
								{pins}
							</span>
						{/if}
					</span>
					<span class="zone-meta">
						<span class="zone-profile">{displayText(view.profile, 60).text}</span>
						{#if count !== null}
							<span class="zone-count">{plural(count)}</span>
						{/if}
						<span class="zone-count">{formatNodesDetail(view.nodes)}</span>
					</span>
				{/snippet}
				{#if isAdmin}
					<button type="button" class="zone-row interactive" onclick={() => openEdit(view)}>
						{@render body()}
					</button>
				{:else}
					<div class="zone-row">{@render body()}</div>
				{/if}
			{/each}
		</GroupedList>
		<p class="note">{m.zones_footnote()}</p>
	{/if}

	{#if sheetOpen && isAdmin}
		<Sheet
			open={sheetOpen}
			title={editing ? m.zones_edit_title() : m.zones_add_title()}
			onclose={closeSheet}
			centeredOnWide
		>
			<div class="field-row">
				{#if !editing}
					<label class="field-label" for="zone-id">{m.zones_id_label()}</label>
					<input id="zone-id" class="field" bind:value={formId} autocomplete="off" />
					{#if formId.trim() && slugify(formId)}
						<p class="hint mono">{slugify(formId)}</p>
					{/if}
					<p class="hint">{m.zones_id_hint()}</p>
				{:else}
					<span class="field-label">{m.zones_id_label()}</span>
					<span class="static-value">{displayText(editing.id).text}</span>
				{/if}
			</div>

			<div class="field-row">
				<label class="field-label" for="zone-profile">{m.zones_profile_label()}</label>
				<select id="zone-profile" class="field" bind:value={formProfile}>
					{#each profiles as profile (profile.id)}
						<option value={profile.id}>{displayText(profile.id, 60).text}</option>
					{/each}
				</select>
			</div>

			<div class="field-row">
				<label class="field-label" for="zone-ranges">{m.zones_subnets_label()}</label>
				<textarea
					id="zone-ranges"
					class="field area mono"
					bind:value={formRanges}
					rows="4"
					aria-invalid={invalidRange ? 'true' : undefined}
					aria-describedby="zone-ranges-help"></textarea>
				{#if invalidRange}
					<p id="zone-ranges-help" class="error-text" role="alert">
						{m.zones_range_invalid({ line: invalidRange.line })}
					</p>
				{:else}
					<p id="zone-ranges-help" class="hint">{m.zones_subnets_hint()}</p>
					{#if lines(formRanges).length === 0 && !formDefault}
						<p class="hint">{m.zones_no_subnets()}</p>
					{/if}
				{/if}
			</div>

			<div class="switch-row">
				<span>{m.zones_default_label()}</span>
				<Switch bind:checked={formDefault} aria-label={m.zones_default_label()} />
			</div>
			<p class="muted-note">{m.zones_default_hint()}</p>

			<details class="advanced">
				<summary>{m.zones_advanced()}</summary>
				<NodeChecklist
					nodeIds={nodeChoices}
					selected={formNodes}
					label={m.zones_nodes_label()}
					hint={m.zones_nodes_hint()}
					solo={m.zones_nodes_solo()}
					labelId="zone-nodes-label"
					hintId="zone-nodes-hint"
					ontoggle={toggleNode}
				/>
			</details>

			{#snippet footer()}
				{#if failure && !refusedPinned}
					<div class="footer-error">
						<ErrorNotice code={failure.code} params={failure.params} />
					</div>
				{/if}
				{#if editing && confirmDelete}
					<p class="confirm-text">{m.zones_delete_body({ id: displayText(editing.id).text })}</p>
					<div class="actions">
						<Button variant="secondary" onclick={() => (confirmDelete = false)}>
							{m.action_cancel()}
						</Button>
						<Button
							variant="danger"
							disabled={busy}
							onclick={() => void removeView(editing?.id ?? '')}
						>
							{m.action_delete()}
						</Button>
					</div>
				{:else}
					{#if editing}
						{#if editing.is_default}
							<p class="muted-note">{m.zones_default_delete_blocked()}</p>
						{:else if pinsOf(editing.id).length > 0 || refusedPinned}
							<p class="muted-note">
								{m.zones_pinned_blocked({
									names: refusedPinned
										? refusedNames(failure?.params.client_ids)
										: pinnedNames(pinsOf(editing.id)),
								})}
							</p>
						{:else}
							<button type="button" class="danger-text" onclick={() => (confirmDelete = true)}>
								{m.action_delete()}
							</button>
						{/if}
					{/if}
					<div class="actions">
						<Button variant="secondary" onclick={closeSheet}>{m.action_cancel()}</Button>
						<Button variant="primary" disabled={!canSave} onclick={() => void submit()}>
							{m.action_save()}
						</Button>
					</div>
				{/if}
			{/snippet}
		</Sheet>
	{/if}
</div>

<style>
	.zones {
		max-width: 44rem;
	}

	.page-head {
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
	.lead a {
		color: var(--accent);
	}
	.state {
		color: var(--label-2);
	}
	.note {
		margin: 0.75rem 0 0;
		font-size: 0.8125rem;
		color: var(--label-3);
	}

	.empty {
		display: flex;
		flex-direction: column;
		align-items: flex-start;
		gap: var(--space-3);
		padding: var(--space-5);
		background: var(--surface);
		border: 1px solid var(--separator);
		border-radius: var(--r-card);
	}
	.empty p {
		margin: 0;
		color: var(--label-2);
	}

	.zone-row {
		display: flex;
		align-items: flex-start;
		justify-content: space-between;
		gap: 1rem;
		width: 100%;
		min-height: 3.25rem;
		padding: 0.875rem 1rem;
		border: none;
		background: transparent;
		color: var(--label);
		font: inherit;
		text-align: start;
	}
	.zone-row.interactive {
		cursor: pointer;
	}
	.zone-row.interactive:hover {
		background: var(--surface-2);
	}
	.zone-main {
		display: flex;
		flex: 1 1 auto;
		flex-direction: column;
		gap: 0.2rem;
		min-width: 0;
	}
	.zone-title {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 0.5rem;
	}
	.zone-name {
		font-size: 0.9375rem;
		font-weight: 600;
		overflow-wrap: anywhere;
	}
	.badge {
		padding: 0.05rem 0.4rem;
		border-radius: 999px;
		background: var(--accent-fill);
		font-size: 0.6875rem;
		font-weight: 600;
		color: var(--accent);
		white-space: nowrap;
	}
	.zone-ranges {
		display: flex;
		flex-wrap: wrap;
		align-items: baseline;
		gap: 0.25rem 0.35rem;
		font-family: var(--font-mono);
		font-size: 0.78125rem;
		color: var(--label-2);
		overflow-wrap: anywhere;
	}
	.zone-ranges .sep {
		color: var(--label-3);
	}
	.zone-ranges .soft,
	.zone-empty {
		font-family: inherit;
		font-size: 0.78125rem;
		color: var(--label-3);
	}
	.zone-pins {
		font-size: 0.78125rem;
		color: var(--label-2);
		overflow-wrap: anywhere;
	}
	.pins-label {
		margin-inline-end: 0.25rem;
		color: var(--label-3);
	}
	.zone-meta {
		display: flex;
		flex: 0 0 auto;
		flex-direction: column;
		align-items: flex-end;
		gap: 0.125rem;
		padding-top: 0.1rem;
		text-align: end;
	}
	.zone-profile {
		font-size: 0.8125rem;
		font-weight: 500;
		color: var(--label);
	}
	.zone-count {
		font-size: 0.75rem;
		color: var(--label-3);
		white-space: nowrap;
	}

	.field-row {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		min-width: 0;
		padding: var(--space-3) var(--space-4);
	}
	.field-label {
		font-size: 0.8125rem;
		color: var(--label-2);
	}
	.static-value {
		font-family: var(--font-mono);
		overflow-wrap: anywhere;
	}
	.field {
		box-sizing: border-box;
		width: 100%;
		min-height: var(--control-h);
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
	}
	.mono {
		font-family: var(--font-mono);
	}
	.hint,
	.muted-note {
		margin: 0;
		font-size: 0.8125rem;
		color: var(--label-3);
	}
	.muted-note {
		padding: 0 var(--space-4) var(--space-2);
	}
	.error-text {
		margin: 0;
		font-size: 0.8125rem;
		color: var(--danger);
	}
	.switch-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-3);
		min-height: var(--control-h);
		padding: 0 var(--space-4);
		font-size: 0.875rem;
		color: var(--label-2);
	}
	.advanced {
		padding: var(--space-3) var(--space-4) 0;
	}
	.advanced summary {
		min-height: var(--control-h);
		color: var(--accent);
		cursor: pointer;
	}

	.danger-text {
		align-self: flex-start;
		min-height: var(--control-h);
		padding: 0 0.25rem;
		border: none;
		background: transparent;
		font: inherit;
		font-weight: 500;
		color: var(--danger);
		cursor: pointer;
	}
	.footer-error,
	.confirm-text {
		flex: 0 0 100%;
	}
	.confirm-text {
		margin: 0;
		color: var(--label);
	}
	.actions {
		display: flex;
		flex-wrap: wrap;
		justify-content: flex-end;
		gap: var(--space-2);
		margin-inline-start: auto;
	}
</style>
