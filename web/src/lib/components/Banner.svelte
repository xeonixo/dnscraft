<script lang="ts">
	import type { Snippet } from 'svelte';
	import Icon from './Icon.svelte';

	interface Props {
		/** Translated headline; the warning symbol carries the meaning, not the color. */
		title: string;
		children?: Snippet;
	}

	let { title, children }: Props = $props();
</script>

<div class="banner warn" role="status">
	<span class="symbol">
		<Icon name="alert-triangle" size="1.1875rem" strokeWidth={1.8} />
	</span>
	<div class="body">
		<p class="title">{title}</p>
		{#if children}
			<div class="detail">{@render children()}</div>
		{/if}
	</div>
</div>

<style>
	.banner {
		display: flex;
		align-items: flex-start;
		gap: 0.75rem;
		padding: 0.875rem 1rem;
		background: var(--surface);
		border: 1px solid var(--separator);
		border-radius: var(--r-card);
	}

	.symbol {
		display: inline-flex;
		margin-top: 0.0625rem;
		color: var(--warn);
	}

	.body {
		display: flex;
		flex: 1 1 auto;
		flex-direction: column;
		gap: 0.125rem;
		min-width: 0;
	}

	.title {
		margin: 0;
		font-weight: 600;
	}

	.detail {
		font-size: 0.84375rem;
		color: var(--label-2);
		overflow-wrap: anywhere;
	}
</style>
