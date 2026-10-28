<script lang="ts">
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import Segmented from '$lib/components/Segmented.svelte';
	import Sheet from '$lib/components/Sheet.svelte';
	import UnavailableNotice from '$lib/components/UnavailableNotice.svelte';
	import {
		listMcpRules,
		removeMcpRule,
		resumeFilterSet,
		type McpRuleKind,
		type McpRuleRow,
	} from '$lib/api/mcp-rules';
	import { failureOf, settle, type Result } from '$lib/api/result';
	import { auth } from '$lib/auth/state.svelte';
	import { displayText } from '$lib/safe-text';
	import { formatRelativeTime } from '$lib/format';
	import { getLocale } from '$lib/i18n/locale';
	import { m } from '$lib/paraglide/messages';

	const isAdmin = $derived(auth.role === 'admin');
	const locale = getLocale();

	const kindOptions: { value: McpRuleKind; label: string }[] = [
		{ value: 'rules', label: m.mcp_rules_kind_rules() },
		{ value: 'temporary_allows', label: m.mcp_rules_kind_allows() },
		{ value: 'pauses', label: m.mcp_rules_kind_pauses() },
	];

	let kind = $state<McpRuleKind>('rules');
	let result = $state<Result<McpRuleRow[]>>({ kind: 'loading' });
	let removeTarget = $state<McpRuleRow | null>(null);
	let busy = $state(false);
	let failure = $state<{ code: string; params: Record<string, unknown> } | null>(null);

	async function load(): Promise<void> {
		result = await settle(
			listMcpRules(kind).then((page) => {
				if (kind === 'temporary_allows') return page.temporary_allows ?? [];
				if (kind === 'pauses') return page.pauses ?? [];
				return page.rules ?? [];
			}),
		);
	}

	function expiryDetail(row: McpRuleRow): string {
		const instant = row.expires_at ?? row.paused_until;
		if (!instant) return '—';
		const date = new Date(instant);
		return formatRelativeTime(date, new Date(), locale);
	}

	async function confirmRemove(): Promise<void> {
		if (!removeTarget) return;
		busy = true;
		failure = null;
		try {
			if (kind === 'rules') {
				await removeMcpRule(removeTarget.domain);
			} else if (kind === 'pauses') {
				await resumeFilterSet(removeTarget.filter_set_id ?? 'default');
			}
			removeTarget = null;
			await load();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	$effect(() => {
		const current = kind;
		void current;
		void load();
	});
</script>

<p class="lead">{m.mcp_rules_lead()}</p>

<Segmented options={kindOptions} bind:value={kind} label={m.mcp_rules_kind_label()} />

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
	<GroupedList header={m.mcp_rules_list_header()}>
		{#each result.data as row, index (row.id ?? `${row.domain}-${index}`)}
			<GroupedRow
				label={displayText(row.domain ?? row.filter_set_id ?? '—').text}
				detail={m.mcp_rules_row_meta({ expiry: expiryDetail(row) })}
				mono
			>
				{#snippet trailing()}
					{#if isAdmin && kind !== 'temporary_allows'}
						<Button variant="danger" disabled={busy} onclick={() => (removeTarget = row)}>
							{kind === 'pauses' ? m.mcp_rules_resume() : m.action_delete()}
						</Button>
					{/if}
				{/snippet}
			</GroupedRow>
		{:else}
			<GroupedRow label={m.mcp_rules_empty()} />
		{/each}
	</GroupedList>
{/if}

{#if removeTarget}
	<Sheet
		open={true}
		title={kind === 'pauses' ? m.mcp_rules_resume_title() : m.mcp_rules_remove_title()}
		onclose={() => (removeTarget = null)}
	>
		<p class="body">
			{kind === 'pauses'
				? m.mcp_rules_resume_body({ set: removeTarget.filter_set_id ?? 'default' })
				: m.mcp_rules_remove_body({ domain: displayText(removeTarget.domain).text })}
		</p>
		<div class="actions">
			<Button onclick={() => (removeTarget = null)}>{m.action_cancel()}</Button>
			<Button variant="danger" disabled={busy} onclick={confirmRemove}>
				{m.mcp_rules_remove_confirm()}
			</Button>
		</div>
	</Sheet>
{/if}

<style>
	.lead {
		margin: 0 0 1rem;
		color: var(--label-2);
	}

	.state {
		margin: 1rem 0 0;
		color: var(--label-2);
	}

	.notice {
		margin: 0.75rem 0;
	}

	.body {
		margin: 0;
		color: var(--label-2);
		overflow-wrap: anywhere;
	}

	.actions {
		display: flex;
		flex-wrap: wrap;
		justify-content: flex-end;
		gap: 0.5rem;
		margin-top: 1rem;
	}
</style>
