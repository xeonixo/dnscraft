<script lang="ts">
	import type { Snippet } from 'svelte';
	import Value from './Value.svelte';

	interface Props {
		label: string;
		/** Untrusted value, rendered through Value (text only). Ignored when `children` is given. */
		value?: string | null;
		/** Technical value (id, IP, rule, code): SF Mono. */
		mono?: boolean;
		/** Replaces the value, for links or a custom mark. */
		children?: Snippet;
	}

	let { label, value, mono = false, children }: Props = $props();
</script>

<div class="row">
	<span class="label">{label}</span>
	<span class="value">
		{#if children}
			{@render children()}
		{:else}
			<Value {value} {mono} />
		{/if}
	</span>
</div>

<style>
	/* Label column next to the value, both start-aligned. Wide containers (the detail page's
	   container, named "detail") get a fixed label column so values sit close to their labels. */
	.row {
		display: grid;
		grid-template-columns: minmax(0, 8.5rem) minmax(0, 1fr);
		column-gap: 1rem;
		align-items: baseline;
		min-height: 2.75rem;
		padding: 0.625rem 1rem;
		color: var(--label);
	}

	@container detail (min-width: 56.25rem) {
		.row {
			grid-template-columns: minmax(0, 11rem) minmax(0, 1fr);
		}
	}

	.label {
		font-size: 0.9375rem;
		color: var(--label-2);
		overflow-wrap: anywhere;
	}

	.value {
		min-width: 0;
		font-size: 0.9375rem;
		color: var(--label);
		overflow-wrap: anywhere;
	}
</style>
