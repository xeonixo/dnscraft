<script lang="ts">
	import { displayText } from '$lib/safe-text';

	interface Props {
		/** Registry ids plus any currently selected ids that are not yet enrolled. */
		nodeIds: string[];
		selected: string[];
		label: string;
		hint: string;
		/** Shown when there is no cluster (standalone). */
		solo: string;
		labelId?: string;
		hintId?: string;
		ontoggle?: (id: string, checked: boolean) => void;
	}

	let {
		nodeIds,
		selected,
		label,
		hint,
		solo,
		labelId = 'node-checklist-label',
		hintId = 'node-checklist-hint',
		ontoggle,
	}: Props = $props();
</script>

<p class="field-label" id={labelId}>{label}</p>
{#if nodeIds.length > 0}
	<div class="node-list" role="group" aria-labelledby={labelId} aria-describedby={hintId}>
		{#each nodeIds as nodeId (nodeId)}
			<label class="node-row">
				<span class="mono">{displayText(nodeId).text}</span>
				<input
					type="checkbox"
					checked={selected.includes(nodeId)}
					onchange={(event) =>
						ontoggle?.(nodeId, (event.currentTarget as HTMLInputElement).checked)}
				/>
			</label>
		{/each}
	</div>
	<p id={hintId} class="hint">{hint}</p>
{:else}
	<p class="hint">{solo}</p>
{/if}

<style>
	.field-label {
		display: block;
		margin: 0 0 0.375rem;
		font-size: 0.84375rem;
		color: var(--label-2);
	}

	.node-list {
		overflow: hidden;
		margin: 0 0 0.5rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		background: var(--surface-2);
	}

	.node-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 0.75rem;
		min-height: 2.5rem;
		padding: 0 0.75rem;
		cursor: pointer;
	}

	.node-row + .node-row {
		border-top: 1px solid var(--separator);
	}

	.node-row input {
		width: 1.05rem;
		height: 1.05rem;
		accent-color: var(--accent-solid);
	}

	.node-row .mono {
		font-family: var(--font-mono, ui-monospace, SFMono-Regular, Menlo, monospace);
		font-size: 0.875rem;
	}

	.hint {
		margin: -0.25rem 0 1rem;
		color: var(--label-2);
		font-size: 0.84375rem;
	}
</style>
