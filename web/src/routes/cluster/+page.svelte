<script lang="ts">
	import { onMount } from 'svelte';
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import Icon from '$lib/components/Icon.svelte';
	import Sheet from '$lib/components/Sheet.svelte';
	import {
		listClusterNodes,
		mintJoinToken,
		revokeClusterNode,
		removeClusterNode,
		updateClusterNode,
		type ClusterNode,
	} from '$lib/api/cluster';
	import { failureOf, settle, type Result } from '$lib/api/result';
	import { auth } from '$lib/auth/state.svelte';
	import { nodeLag, nodeRoleLabel, nodeStatusLabel, nodeVerdict } from '$lib/cluster/nodes';
	import { displayText } from '$lib/safe-text';
	import { formatDateTime, formatFingerprint, formatNumber } from '$lib/format';
	import { getLocale } from '$lib/i18n/locale';
	import { m } from '$lib/paraglide/messages';

	const HOST_EXAMPLE = 'ns1.dns.example.com';
	const isAdmin = $derived(auth.role === 'admin');
	const locale = getLocale();

	const nodeRows = $derived.by(() => {
		if (result.kind !== 'ok') return [];
		const lags = nodeLag(result.data);
		return result.data.map((node, index) => ({ node, lag: lags[index] ?? 0 }));
	});
	const activeCount = $derived(nodeRows.filter((row) => !row.node.revoked).length);
	const behindCount = $derived(nodeRows.filter((row) => !row.node.revoked && row.lag > 0).length);

	let result = $state<Result<ClusterNode[]>>({ kind: 'loading' });
	let joinOpen = $state(false);
	let joinNodeId = $state('');
	let joinToken = $state<string | null>(null);
	let joinExpires = $state<string | null>(null);
	let detail = $state<ClusterNode | null>(null);
	let revokeTarget = $state<ClusterNode | null>(null);
	let removeTarget = $state<ClusterNode | null>(null);
	let editTarget = $state<ClusterNode | null>(null);
	let editName = $state('');
	let editHost = $state('');
	const HOST_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/i;
	const hostInvalid = $derived(editHost.trim() !== '' && !HOST_RE.test(editHost.trim()));
	let busy = $state(false);
	let failure = $state<{ code: string; params: Record<string, unknown> } | null>(null);

	/** Config version plus last contact; the node this page runs on has no peer contact to show. */
	function nodeMeta(node: ClusterNode): string {
		const version = node.applied_config_version ?? '—';
		if (!node.last_seen && (node.local === true || node.role === 'master')) {
			return m.cluster_node_meta_local({ version });
		}
		const seen = node.last_seen
			? formatDateTime(new Date(node.last_seen), locale)
			: m.cluster_never_seen();
		return m.cluster_node_meta({ version, seen });
	}

	async function load(): Promise<void> {
		result = await settle(listClusterNodes());
	}

	async function submitJoin(): Promise<void> {
		busy = true;
		failure = null;
		try {
			const issued = await mintJoinToken(joinNodeId.trim());
			joinToken = issued.token;
			joinExpires = issued.expires_at;
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	async function copyToken(): Promise<void> {
		if (!joinToken) return;
		try {
			await globalThis.navigator.clipboard.writeText(joinToken);
		} catch {
			/* denied */
		}
	}

	function openEdit(node: ClusterNode): void {
		editTarget = node;
		editName = node.display_name ?? '';
		editHost = node.hostname ?? '';
		failure = null;
	}

	async function saveEdit(): Promise<void> {
		if (!editTarget) return;
		busy = true;
		failure = null;
		try {
			await updateClusterNode(editTarget.node_id, { display_name: editName, hostname: editHost });
			editTarget = null;
			await load();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	async function confirmRevoke(): Promise<void> {
		if (!revokeTarget) return;
		busy = true;
		failure = null;
		try {
			await revokeClusterNode(revokeTarget.node_id);
			revokeTarget = null;
			await load();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	async function confirmRemove(): Promise<void> {
		if (!removeTarget) return;
		busy = true;
		failure = null;
		try {
			await removeClusterNode(removeTarget.node_id);
			removeTarget = null;
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

<p class="lead">{m.cluster_lead()}</p>

{#if failure && !editTarget}
	<div class="notice">
		<ErrorNotice code={failure.code} params={failure.params} />
	</div>
{/if}

{#if result.kind === 'loading'}
	<p class="state">{m.state_loading()}</p>
{:else if result.kind === 'unavailable'}
	<GroupedList header={m.cluster_standalone_title()}>
		<GroupedRow label={m.cluster_standalone_body()} />
	</GroupedList>
{:else if result.kind === 'error'}
	<ErrorNotice code={result.code} params={result.params} />
{:else}
	{#if isAdmin}
		<div class="toolbar">
			<Button variant="primary" onclick={() => ((joinOpen = true), (joinToken = null))}>
				{m.cluster_join_token()}
			</Button>
		</div>
	{/if}

	<p class="summary">
		{m.cluster_summary({
			nodes: formatNumber(activeCount, locale),
			behind: formatNumber(behindCount, locale),
		})}
	</p>

	<GroupedList header={m.cluster_nodes_group()}>
		{#each nodeRows as { node, lag } (node.node_id)}
			<GroupedRow
				label={displayText(node.display_name || node.node_id).text}
				detail={(node.display_name ? `${displayText(node.node_id).text} · ` : '') +
					(node.revoked
						? `${nodeRoleLabel(node.role)} · ${m.cluster_revoked()}`
						: `${nodeRoleLabel(node.role)} · ${nodeStatusLabel(node, lag, locale)} · ${nodeMeta(node)}`)}
			>
				{#snippet leading()}
					{@const verdict = nodeVerdict(node, lag)}
					<span class="symbol {verdict.tone}">
						<Icon name={verdict.icon} size="1.125rem" strokeWidth={1.7} />
					</span>
				{/snippet}
				{#snippet trailing()}
					<Button onclick={() => (detail = node)}>{m.cluster_detail()}</Button>
					{#if isAdmin && !node.revoked && node.role !== 'master' && node.local !== true}
						<Button variant="danger" disabled={busy} onclick={() => (revokeTarget = node)}>
							{m.cluster_revoke()}
						</Button>
					{/if}
				{/snippet}
			</GroupedRow>
		{:else}
			<GroupedRow label={m.cluster_empty()} />
		{/each}
	</GroupedList>
{/if}

{#if joinOpen}
	<Sheet open={true} title={m.cluster_join_title()} onclose={() => (joinOpen = false)}>
		{#if !joinToken}
			<label class="field-label" for="join-node">{m.cluster_join_node_label()}</label>
			<input id="join-node" class="field mono" bind:value={joinNodeId} />
			{#if failure}
				<div class="notice">
					<ErrorNotice code={failure.code} params={failure.params} />
				</div>
			{/if}
			<div class="actions">
				<Button onclick={() => (joinOpen = false)}>{m.action_cancel()}</Button>
				<Button variant="primary" disabled={busy || joinNodeId.trim() === ''} onclick={submitJoin}>
					{m.cluster_join_mint()}
				</Button>
			</div>
		{:else}
			<p class="hint">{m.cluster_join_once()}</p>
			<code class="mono token">{joinToken}</code>
			{#if joinExpires}
				<p class="hint">
					{m.cluster_join_expires({ time: formatDateTime(new Date(joinExpires), locale) })}
				</p>
			{/if}
			<div class="actions">
				<Button onclick={() => void copyToken()}>{m.action_copy()}</Button>
				<Button onclick={() => (joinOpen = false)}>{m.action_close()}</Button>
			</div>
		{/if}
	</Sheet>
{/if}

{#if detail}
	{@const detailNodeId = detail.node_id}
	{@const detailLag = nodeRows.find((row) => row.node.node_id === detailNodeId)?.lag ?? 0}
	{@const connectionLabel = detail.local
		? m.cluster_connection_local()
		: detail.connected
			? m.cluster_connection_connected()
			: m.cluster_connection_offline()}
	{@const transportLabel =
		detail.transport === 'mtls' ? m.cluster_transport_mtls() : m.cluster_value_unknown()}
	<Sheet open={true} title={m.cluster_detail_title()} onclose={() => (detail = null)}>
		<GroupedList>
			<GroupedRow
				label={m.cluster_field_node_id()}
				detail={displayText(detail.node_id).text}
				detailMono
			/>
			<GroupedRow
				label={m.cluster_field_display_name()}
				detail={detail.display_name || m.cluster_value_unknown()}
			/>
			<GroupedRow
				label={m.cluster_field_hostname()}
				detail={detail.hostname || m.cluster_value_unknown()}
				detailMono
			/>
			<GroupedRow label={m.cluster_field_role()} detail={nodeRoleLabel(detail.role)} />
			<GroupedRow
				label={m.cluster_field_status()}
				detail={nodeStatusLabel(detail, detailLag, locale)}
			/>
			<GroupedRow label={m.cluster_field_connection()} detail={connectionLabel} />
			<GroupedRow
				label={m.cluster_field_remote_addr()}
				detail={detail.remote_addr || m.cluster_value_unknown()}
				detailMono
			/>
			<GroupedRow label={m.cluster_field_transport()} detail={transportLabel} />
			<GroupedRow
				label={m.cluster_field_fingerprint()}
				detail={detail.fingerprint
					? formatFingerprint(detail.fingerprint)
					: m.cluster_value_unknown()}
				detailMono
			/>
			<GroupedRow
				label={m.cluster_field_joined()}
				detail={detail.joined_at
					? formatDateTime(new Date(detail.joined_at), locale)
					: m.cluster_value_unknown()}
				detailMono
			/>
			<GroupedRow
				label={m.cluster_field_last_seen()}
				detail={detail.last_seen
					? formatDateTime(new Date(detail.last_seen), locale)
					: m.cluster_never_seen()}
				detailMono
			/>
			<GroupedRow
				label={m.cluster_field_applied_version()}
				detail={String(detail.applied_config_version ?? '—')}
				detailMono
			/>
		</GroupedList>
		<div class="actions">
			{#if isAdmin && !detail.revoked}
				<Button
					onclick={() => {
						if (detail) openEdit(detail);
						detail = null;
					}}>{m.cluster_edit()}</Button
				>
			{/if}
			{#if isAdmin && detail.revoked && detail.role !== 'master' && detail.local !== true}
				<Button
					variant="danger"
					onclick={() => {
						removeTarget = detail;
						detail = null;
					}}>{m.cluster_remove()}</Button
				>
			{/if}
			<Button onclick={() => (detail = null)}>{m.action_close()}</Button>
		</div>
	</Sheet>
{/if}

{#if removeTarget}
	<Sheet open={true} title={m.cluster_remove_title()} onclose={() => (removeTarget = null)}>
		<p class="hint">{m.cluster_remove_body({ id: displayText(removeTarget.node_id).text })}</p>
		<div class="actions">
			<Button onclick={() => (removeTarget = null)}>{m.action_cancel()}</Button>
			<Button variant="danger" disabled={busy} onclick={confirmRemove}>
				{m.cluster_remove()}
			</Button>
		</div>
	</Sheet>
{/if}

{#if editTarget}
	<Sheet open={true} title={m.cluster_edit_title()} onclose={() => (editTarget = null)}>
		<p class="hint">{m.cluster_edit_id({ id: displayText(editTarget.node_id).text })}</p>
		<label class="field-label" for="edit-name">{m.cluster_field_display_name()}</label>
		<input id="edit-name" class="field" maxlength="64" bind:value={editName} />
		<label class="field-label" for="edit-host">{m.cluster_field_hostname()}</label>
		<input
			id="edit-host"
			class="field mono"
			placeholder={HOST_EXAMPLE}
			autocapitalize="off"
			spellcheck="false"
			aria-invalid={hostInvalid}
			bind:value={editHost}
		/>
		<p class="hint" class:invalid={hostInvalid}>
			{hostInvalid ? m.cluster_edit_host_invalid() : m.cluster_edit_hint()}
		</p>
		{#if failure}
			<div class="notice">
				<ErrorNotice code={failure.code} params={failure.params} />
			</div>
		{/if}
		<div class="actions">
			<Button onclick={() => (editTarget = null)}>{m.action_cancel()}</Button>
			<Button variant="primary" disabled={busy || hostInvalid} onclick={saveEdit}
				>{m.action_save()}</Button
			>
		</div>
	</Sheet>
{/if}

{#if revokeTarget}
	<Sheet open={true} title={m.cluster_revoke_title()} onclose={() => (revokeTarget = null)}>
		<p class="hint">{m.cluster_revoke_body({ id: displayText(revokeTarget.node_id).text })}</p>
		<div class="actions">
			<Button onclick={() => (revokeTarget = null)}>{m.action_cancel()}</Button>
			<Button variant="danger" disabled={busy} onclick={confirmRevoke}>
				{m.cluster_revoke_confirm()}
			</Button>
		</div>
	</Sheet>
{/if}

<style>
	.lead {
		margin: 0 0 1rem;
		color: var(--label-2);
	}

	.toolbar {
		margin-bottom: 0.75rem;
	}

	.summary {
		margin: 0 0 0.5rem;
		font-size: 0.84375rem;
		color: var(--label-2);
	}

	.symbol {
		display: inline-flex;
		flex: 0 0 auto;
	}

	.symbol.ok {
		color: var(--ok);
	}

	.symbol.warn {
		color: var(--warn);
	}

	.symbol.neutral {
		color: var(--label-3);
	}

	.state,
	.hint {
		margin: 0;
		color: var(--label-2);
		font-size: 0.84375rem;
	}

	.hint.invalid {
		color: var(--danger);
	}

	.notice {
		margin: 0.75rem 0;
	}

	.hint + .field-label {
		margin-top: 0.75rem;
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
	}

	.token {
		display: block;
		margin: 0.75rem 0;
		padding: 0.5rem;
		overflow-x: auto;
		word-break: break-all;
		background: var(--surface-2);
		border-radius: var(--r-control);
	}

	.actions {
		display: flex;
		flex-wrap: wrap;
		justify-content: flex-end;
		gap: 0.5rem;
		margin-top: 1rem;
	}
</style>
