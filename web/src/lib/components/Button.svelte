<script lang="ts">
	import type { Snippet } from 'svelte';
	import type { HTMLButtonAttributes } from 'svelte/elements';

	interface Props extends HTMLButtonAttributes {
		variant?: 'primary' | 'secondary' | 'danger';
		children: Snippet;
	}

	let {
		variant = 'secondary',
		type = 'button',
		class: className = '',
		children,
		...rest
	}: Props = $props();
</script>

<button {type} class="btn {variant} {className}" {...rest}>
	{@render children()}
</button>

<style>
	.btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		gap: 0.375rem;
		min-width: 2.75rem;
		min-height: var(--control-h);
		padding: 0.4375rem var(--control-px);
		border: 1px solid transparent;
		border-radius: var(--r-ctl);
		font: inherit;
		font-size: 0.875rem;
		font-weight: 600;
		text-decoration: none;
		cursor: pointer;
	}

	.btn:disabled {
		opacity: 0.4;
		cursor: not-allowed;
	}

	.primary {
		background: var(--accent-solid);
		color: var(--on-accent);
	}

	.secondary {
		background: var(--surface-2);
		border-color: var(--separator);
		color: var(--label);
		font-weight: 500;
	}

	.danger {
		background: var(--danger-fill);
		color: var(--on-accent);
	}
</style>
