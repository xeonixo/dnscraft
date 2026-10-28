<script lang="ts">
	import type { Snippet } from 'svelte';

	interface Props {
		/** Section header above the group (translated). */
		header?: string;
		/** Footer text that explains the consequence of the rows (translated). */
		footer?: string;
		children: Snippet;
	}

	let { header, footer, children }: Props = $props();
	const headerId = $props.id();
</script>

<section class="grouped" aria-labelledby={header ? headerId : undefined}>
	{#if header}
		<h2 class="head" id={headerId}>{header}</h2>
	{/if}
	<div class="group">
		{@render children()}
	</div>
	{#if footer}
		<p class="foot">{footer}</p>
	{/if}
</section>

<style>
	.grouped {
		display: flex;
		flex-direction: column;
		gap: 0.375rem;
		min-width: 0;
	}

	.head {
		margin: 0;
		padding: 0.25rem 1rem 0.375rem;
		font-size: 0.8125rem;
		font-weight: 500;
		letter-spacing: 0;
		color: var(--label-2);
	}

	.group {
		overflow: hidden;
		background: var(--surface);
		border: 1px solid var(--separator);
		border-radius: var(--r-card);
		box-shadow: var(--shadow);
	}

	/* Hairline between rows; the rows themselves are child components. */
	.group > :global(* + *) {
		border-top: 1px solid var(--separator);
	}

	.foot {
		margin: 0;
		padding: 0 1rem;
		font-size: 0.8125rem;
		color: var(--label-3);
	}
</style>
