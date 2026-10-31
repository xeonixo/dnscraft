<script lang="ts">
	import Button from '$lib/components/Button.svelte';
	import Icon from '$lib/components/Icon.svelte';
	import Value from './Value.svelte';
	import { cnameChainOf, type DecisionStep } from '$lib/api/query-log';
	import { decisiveIndex, stageLabel, stepDetail, verdictLabel, verdictStyle } from './view';
	import { m } from '$lib/paraglide/messages';

	interface Props {
		steps: DecisionStep[];
		/** Admin only: opens a rule sheet for one CNAME hop. Without it the hops get no button. */
		onrule?: (name: string, verdict: string) => void;
	}

	let { steps, onrule }: Props = $props();
	const decisive = $derived(decisiveIndex(steps));
</script>

<ol class="steps">
	{#each steps as step, index (index)}
		{@const style = verdictStyle(step.verdict)}
		{@const detail = stepDetail(step)}
		{@const chain = step.stage === 'cname_chain' ? cnameChainOf(step) : null}
		{@const isDecisive = index === decisive}
		<li class="step" class:decisive={isDecisive}>
			<span class="index mono">{index + 1}</span>
			<span class="symbol {style.tone}">
				<Icon name={style.icon} size="1.125rem" strokeWidth={1.7} />
			</span>
			<span class="main">
				<span class="headline">
					<span class="stage">{stageLabel(step.stage)}</span>
					<span class="verdict">{verdictLabel(step.verdict)}</span>
					{#if isDecisive}
						<span class="tag">{m.querylog_step_decisive()}</span>
					{/if}
				</span>
				{#if chain}
					<ol class="hops">
						{#each chain.hops as hop, hopIndex (hopIndex)}
							{@const hopStyle = verdictStyle(hop.verdict)}
							<li class="hop" class:blocking={hop.verdict === 'blocked'}>
								<span class="hop-name"><Value value={hop.name} mono /></span>
								<span class="hop-verdict {hopStyle.tone}">
									<Icon name={hopStyle.icon} size="0.9375rem" strokeWidth={1.7} />
									<span>{verdictLabel(hop.verdict)}</span>
								</span>
								<span class="hop-rule">
									{#if hop.rule_text !== null}
										<Value value={hop.rule_text} mono oneLine />
										{#if hop.list_id !== null}
											<span class="mono">{hop.list_id}</span>
										{/if}
									{:else if hop.verdict === 'pass'}
										{m.querylog_cname_no_rule()}
									{/if}
								</span>
								{#if onrule}
									<span class="hop-action">
										<Button onclick={() => onrule(hop.name, hop.verdict)}>
											{m.querylog_rule_create()}
										</Button>
									</span>
								{/if}
							</li>
						{/each}
					</ol>
					<span class="resolved">
						<span class="resolved-label">{m.querylog_cname_resolved_to()}</span>
						{#if chain.addresses.length > 0}
							<Value value={chain.addresses.join(', ')} mono />
						{:else}
							<span>{m.querylog_cname_none()}</span>
						{/if}
					</span>
				{:else if detail}
					<span class="detail"><Value value={detail.text} mono={detail.mono} /></span>
				{/if}
				<span class="id"><Value value={step.stage} mono /></span>
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

	/* The decisive step: tinted row and a heavier stage name; the tag and the icon carry it too. */
	.step.decisive {
		background: var(--accent-fill);
	}

	.step.decisive .stage {
		font-weight: 600;
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

	.headline {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 0.25rem 0.5rem;
	}

	.stage {
		font-size: 0.9375rem;
	}

	.verdict {
		font-size: 0.8125rem;
		font-weight: 500;
		color: var(--label-2);
	}

	.tag {
		padding: 0 0.375rem;
		border-radius: var(--r-ctl);
		background: var(--surface);
		color: var(--accent);
		font-size: 0.75rem;
		font-weight: 600;
	}

	.detail {
		font-size: 0.8125rem;
		color: var(--label-2);
		overflow-wrap: anywhere;
	}

	/* The CNAME chain: one row per name, in chain order, then the resolved addresses. */
	.hops {
		display: flex;
		flex-direction: column;
		gap: 0.375rem;
		margin: 0.5rem 0 0;
		padding: 0;
		list-style: none;
	}

	.hop {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 0.25rem 0.5rem;
		padding: 0.5rem 0.625rem;
		border-radius: var(--r-ctl);
		background: var(--surface);
	}

	.hop.blocking {
		box-shadow: inset 2px 0 0 var(--danger);
	}

	.hop-name {
		flex: 1 1 10rem;
		min-width: 0;
		font-family: var(--font-mono);
		font-size: 0.8125rem;
	}

	.hop-verdict {
		display: inline-flex;
		align-items: center;
		gap: 0.25rem;
		font-size: 0.8125rem;
		font-weight: 500;
		margin-inline-start: auto;
	}

	.hop-rule {
		flex: 1 1 8rem;
		display: flex;
		flex-wrap: wrap;
		gap: 0.125rem 0.5rem;
		min-width: 0;
		font-size: 0.75rem;
		color: var(--label-2);
	}

	.hop-action {
		margin-inline-start: auto;
	}

	.resolved {
		display: flex;
		flex-wrap: wrap;
		gap: 0.25rem 0.5rem;
		margin-top: 0.5rem;
		font-size: 0.8125rem;
		color: var(--label);
		overflow-wrap: anywhere;
	}

	.resolved-label {
		color: var(--label-2);
	}

	.id {
		font-size: 0.75rem;
		color: var(--label-2);
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
