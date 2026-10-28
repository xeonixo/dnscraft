<script lang="ts">
	import Icon from './Icon.svelte';
	import type { IconName, StatusTone } from './icons';

	interface Props {
		/** Symbol that carries the state together with the verdict text (never color alone). */
		icon: IconName;
		tone: StatusTone;
		/** Primary label; untrusted names are rendered as text. */
		label: string;
		/** Set when the label is a domain, IP or identifier. */
		mono?: boolean;
		/** Secondary lines under the label. */
		details?: string[];
		/** Translated verdict shown at the trailing edge. */
		verdict: string;
	}

	let { icon, tone, label, mono = false, details = [], verdict }: Props = $props();
</script>

<div class="row">
	<span class="symbol {tone}"><Icon name={icon} size="1.125rem" strokeWidth={1.7} /></span>
	<div class="main">
		<span class="label" class:mono>{label}</span>
		{#each details as line, index (index)}
			<span class="detail">{line}</span>
		{/each}
	</div>
	<span class="verdict {tone}">{verdict}</span>
</div>

<style>
	.row {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		min-height: 3.25rem;
		padding: 0.75rem 1rem;
		color: var(--label);
	}

	.symbol {
		display: inline-flex;
		flex: 0 0 auto;
	}

	.main {
		display: flex;
		flex: 1 1 auto;
		flex-direction: column;
		min-width: 0;
	}

	.label {
		font-size: 0.9375rem;
		overflow-wrap: anywhere;
	}

	.label.mono {
		font-family: var(--font-mono);
		font-size: 0.875rem;
	}

	.detail {
		margin-top: 0.0625rem;
		font-size: 0.78125rem;
		color: var(--label-2);
		overflow-wrap: anywhere;
	}

	.verdict {
		flex: 0 0 auto;
		font-size: 0.78125rem;
		font-weight: 500;
		text-align: end;
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
		color: var(--label-3);
	}
</style>
