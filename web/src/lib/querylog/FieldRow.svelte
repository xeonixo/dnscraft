<script lang="ts">
	import type { Snippet } from 'svelte';
	import Value from './Value.svelte';

	interface Props {
		label: string;
		/** Untrusted value, rendered through Value (text only). Ignored when `children` is given. */
		value?: string | null;
		mono?: boolean;
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
	.row {
		display: flex;
		flex-wrap: wrap;
		align-items: baseline;
		justify-content: space-between;
		gap: 0.25rem 1rem;
		min-height: 2.75rem;
		padding: 0.625rem 1rem;
		color: var(--label);
	}

	.label {
		flex: 0 0 auto;
		font-size: 0.9375rem;
	}

	.value {
		min-width: 0;
		max-width: 100%;
		margin-inline-start: auto;
		text-align: end;
		font-size: 0.9375rem;
		color: var(--label-2);
		overflow-wrap: anywhere;
	}
</style>
