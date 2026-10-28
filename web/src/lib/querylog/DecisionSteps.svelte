<script lang="ts">
	import Icon from '$lib/components/Icon.svelte';
	import Value from './Value.svelte';
	import type { DecisionStep } from '$lib/api/query-log';
	import { stageLabel, stepDetail, verdictLabel, verdictStyle } from './view';

	interface Props {
		steps: DecisionStep[];
	}

	let { steps }: Props = $props();
</script>

<ol class="steps">
	{#each steps as step, index (index)}
		{@const style = verdictStyle(step.verdict)}
		{@const detail = stepDetail(step)}
		<li class="step">
			<span class="index mono">{index + 1}</span>
			<span class="symbol {style.tone}">
				<Icon name={style.icon} size="1.125rem" strokeWidth={1.7} />
			</span>
			<span class="main">
				<span class="stage">{stageLabel(step.stage)}</span>
				<span class="verdict {style.tone}">{verdictLabel(step.verdict)}</span>
				{#if detail}
					<span class="detail"><Value value={detail.text} mono={detail.mono} /></span>
				{/if}
				<span class="id mono"><Value value={step.stage} mono /></span>
			</span>
		</li>
	{/each}
</ol>

<style>
	.steps {
		margin: 0;
		padding: 0;
		list-style: none;
	}

	.step {
		display: grid;
		grid-template-columns: 1.5rem 1.125rem minmax(0, 1fr);
		gap: 0.25rem 0.75rem;
		align-items: start;
		min-height: 2.75rem;
		padding: 0.75rem 1rem;
		color: var(--label);
	}

	.step + .step {
		border-top: 1px solid var(--separator);
	}

	.index {
		font-size: 0.75rem;
		color: var(--label-3);
		padding-top: 0.125rem;
	}

	.symbol {
		display: inline-flex;
		padding-top: 0.0625rem;
	}

	.main {
		display: flex;
		flex-direction: column;
		min-width: 0;
	}

	.stage {
		font-size: 0.9375rem;
	}

	.verdict {
		font-size: 0.8125rem;
		font-weight: 500;
	}

	.detail {
		font-size: 0.8125rem;
		color: var(--label-2);
		overflow-wrap: anywhere;
	}

	.id {
		font-size: 0.75rem;
		color: var(--label-3);
		overflow-wrap: anywhere;
	}

	.mono {
		font-family: var(--font-mono);
	}

	.ok {
		color: var(--ok);
	}

	.warn {
		color: var(--warn);
	}

	.danger {
		color: var(--danger);
	}

	.neutral {
		color: var(--label-2);
	}
</style>
