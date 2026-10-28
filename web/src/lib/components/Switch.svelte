<script lang="ts">
	import type { HTMLInputAttributes } from 'svelte/elements';

	interface Props extends Omit<HTMLInputAttributes, 'type' | 'checked' | 'value'> {
		checked?: boolean;
	}

	// The native checkbox keeps keyboard (Space) and form semantics; role="switch" names it.
	// Callers pass an accessible name (aria-label or aria-labelledby) through the rest props.
	let { checked = $bindable(false), class: className = '', ...rest }: Props = $props();
</script>

<label class="switch {className}">
	<input type="checkbox" role="switch" bind:checked {...rest} />
	<span class="track" aria-hidden="true"><span class="thumb"></span></span>
</label>

<style>
	.switch {
		position: relative;
		display: inline-flex;
		align-items: center;
		justify-content: center;
		flex: 0 0 auto;
		min-width: 2.75rem;
		min-height: 2.75rem;
		cursor: pointer;
	}

	.switch input {
		position: absolute;
		width: 1px;
		height: 1px;
		margin: 0;
		opacity: 0;
		pointer-events: none;
	}

	.track {
		position: relative;
		width: 3.1875rem;
		height: 1.9375rem;
		border-radius: 1rem;
		background: var(--track-off);
		transition: background var(--duration-fast);
	}

	.thumb {
		position: absolute;
		top: 0.125rem;
		left: 0.125rem;
		width: 1.6875rem;
		height: 1.6875rem;
		border-radius: 50%;
		background: var(--switch-thumb);
		box-shadow: var(--shadow-thumb);
		transition: transform var(--duration-fast) var(--ease);
	}

	.switch input:checked + .track {
		background: var(--ok);
	}

	.switch input:checked + .track .thumb {
		transform: translateX(1.25rem);
	}

	.switch input:focus-visible + .track {
		outline: 2px solid var(--accent);
		outline-offset: 2px;
	}

	.switch:has(input:disabled) {
		cursor: not-allowed;
	}

	.switch input:disabled + .track {
		opacity: 0.4;
	}
</style>
