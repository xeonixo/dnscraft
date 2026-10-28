<script lang="ts">
	import { onMount } from 'svelte';
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import Sheet from '$lib/components/Sheet.svelte';
	import {
		listClusterNodes,
		mintJoinToken,
		revokeClusterNode,
		type ClusterNode,
	} from '$lib/api/cluster';
	import { failureOf, settle, type Result } from '$lib/api/result';
	import { auth } from '$lib/auth/state.svelte';
	import { displayText } from '$lib/safe-text';
	import { formatDateTime, formatFingerprint } from '$lib/format';
	import { getLocale } from '$lib/i18n/locale';
	import { m } from '$lib/paraglide/messages';

	const isAdmin = $derived(auth.role === 'admin');
	const locale = getLocale();

	let result = $state<Result<ClusterNode[]>>({ kind: 'loading' });
	let joinOpen = $state(false);
	let joinNodeId = $state('');
	let joinToken = $state<string | null>(null);
	let joinExpires = $state<string | null>(null);
	let detail = $state<ClusterNode | null>(null);
	let revokeTarget = $state<ClusterNode | null>(null);
	let busy = $state(false);
	let failure = $state<{ code: string; params: Record<string, unknown> } | null>(null);

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

	onMount(() => {
		void load();
	});
</script>

<p class="lead">{m.cluster_lead()}</p>

{#if failure}
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

	<GroupedList header={m.cluster_nodes_group()}>
		{#each result.data as node (node.node_id)}
			<GroupedRow
				label={displayText(node.node_id).text}
				detail={node.revoked
					? m.cluster_revoked()
					: m.cluster_node_meta({
							version: node.applied_config_version ?? '—',
							seen: node.last_seen
								? formatDateTime(new Date(node.last_seen), locale)
								: m.cluster_never_seen(),
						})}
			>
				{#snippet trailing()}
					<Button onclick={() => (detail = node)}>{m.cluster_detail()}</Button>
					{#if isAdmin && !node.revoked}
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
	<Sheet open={true} title={m.cluster_detail_title()} onclose={() => (detail = null)}>
		<GroupedList>
			<GroupedRow label={m.cluster_field_role()} detail={detail.role} />
			<GroupedRow
				label={m.cluster_field_fingerprint()}
				detail={formatFingerprint(detail.fingerprint)}
				detailMono
			/>
			<GroupedRow
				label={m.cluster_field_joined()}
				detail={formatDateTime(new Date(detail.joined_at), locale)}
				detailMono
			/>
			<GroupedRow
				label={m.cluster_field_last_seen()}
				detail={detail.last_seen
					? formatDateTime(new Date(detail.last_seen), locale)
					: m.cluster_never_seen()}
				detailMono
			/>
		</GroupedList>
		<div class="actions">
			<Button onclick={() => (detail = null)}>{m.action_close()}</Button>
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

	.state,
	.hint {
		margin: 0;
		color: var(--label-2);
		font-size: 0.84375rem;
	}

	.notice {
		margin: 0.75rem 0;
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
