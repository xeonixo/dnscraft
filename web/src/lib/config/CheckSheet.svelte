<script lang="ts">
	import Button from '$lib/components/Button.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import Sheet from '$lib/components/Sheet.svelte';
	import StatusRow from '$lib/components/StatusRow.svelte';
	import type { ConfigFinding, ValidateResult } from '$lib/api/config';
	import { findingLabel, type McpRuleChange } from '$lib/config/view';
	import { m } from '$lib/paraglide/messages';

	interface Props {
		/** The dry-run answer for the content that was checked. */
		result: ValidateResult;
		/** How the checked content treats each filter set's mcp_rules against the stored snapshot. */
		mcpChanges: McpRuleChange[];
		onclose: () => void;
	}

	let { result, mcpChanges, onclose }: Props = $props();

	const diffRows = $derived(
		(
			[
				[m.config_change_sections(), result.diff.changed_sections],
				[m.config_change_added(), result.diff.added],
				[m.config_change_removed(), result.diff.removed],
				[m.config_change_changed(), result.diff.changed],
			] as const
		).filter(([, paths]) => paths.length > 0),
	);
	const hasChanges = $derived(diffRows.length > 0 || mcpChanges.length > 0);

	function detailsOf(finding: ConfigFinding): string[] {
		const label = findingLabel(finding);
		const lines = label === finding.code ? [] : [finding.code];
		if (finding.path) lines.push(m.config_finding_path({ path: finding.path }));
		return lines;
	}

	function mcpLabel(change: McpRuleChange): string {
		if (change.kind === 'carried') {
			return m.config_mcp_carried({ set: change.set, count: change.count });
		}
		if (change.kind === 'deleted') {
			return m.config_mcp_deleted({ set: change.set, count: change.count });
		}
		return m.config_mcp_replaced({ set: change.set, count: change.count });
	}
</script>

<Sheet open={true} title={m.config_check_title()} {onclose}>
	<GroupedList>
		{#if result.valid}
			<StatusRow
				icon="check-circle"
				tone="ok"
				label={m.config_check_ok()}
				verdict={m.config_verdict_valid()}
			/>
		{:else}
			<StatusRow
				icon="x-circle"
				tone="danger"
				label={m.config_check_errors({ count: result.errors.length })}
				verdict={m.config_verdict_invalid()}
			/>
		{/if}
	</GroupedList>

	{#if result.errors.length > 0}
		<GroupedList header={m.config_check_errors_section()}>
			{#each result.errors as finding, index (index)}
				<StatusRow
					icon="x-circle"
					tone="danger"
					label={findingLabel(finding)}
					details={detailsOf(finding)}
					verdict={m.config_finding_blocking()}
				/>
			{/each}
		</GroupedList>
	{/if}

	{#if result.warnings.length > 0}
		<GroupedList header={m.config_check_warnings_section()}>
			{#each result.warnings as finding, index (index)}
				<StatusRow
					icon="alert-triangle"
					tone="warn"
					label={findingLabel(finding)}
					details={detailsOf(finding)}
					verdict={m.config_finding_warning()}
				/>
			{/each}
		</GroupedList>
	{/if}

	<GroupedList header={m.config_check_changes_section()}>
		{#if hasChanges}
			{#each diffRows as [heading, paths] (heading)}
				<GroupedRow label={heading} detail={paths.join(', ')} detailMono={true} />
			{/each}
			{#each mcpChanges as change, index (index)}
				<GroupedRow label={mcpLabel(change)} />
			{/each}
		{:else}
			<GroupedRow label={m.config_change_none()} />
		{/if}
	</GroupedList>

	<p class="footer">{m.config_check_footer()}</p>

	<div class="actions">
		<Button variant="primary" onclick={onclose}>{m.action_close()}</Button>
	</div>
</Sheet>

<style>
	.footer {
		margin: 0.75rem 0 0;
		font-size: 0.8125rem;
		color: var(--label-3);
		overflow-wrap: anywhere;
	}

	.actions {
		display: flex;
		justify-content: flex-end;
		margin-top: 1.125rem;
	}
</style>
