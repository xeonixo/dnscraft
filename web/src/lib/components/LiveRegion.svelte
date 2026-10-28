<script lang="ts">
	import { live } from '$lib/live.svelte';
</script>

<!-- The region itself stays in the DOM so that screen readers pick up each new message. -->
<div class="live" role="status" aria-live="polite">
	<p class="toast" hidden={live.message === ''}>{live.message}</p>
</div>

<style>
	.live {
		position: fixed;
		inset-inline: 1rem;
		bottom: 1rem;
		z-index: 70;
		display: flex;
		justify-content: center;
		pointer-events: none;
	}

	.toast {
		max-width: 32.5rem;
		margin: 0;
		padding: 0.75rem 1rem;
		background: var(--surface);
		border: 1px solid var(--separator);
		border-radius: var(--r-card);
		box-shadow: var(--shadow-sheet);
		color: var(--label);
		font-size: 0.9375rem;
		overflow-wrap: anywhere;
	}

	.toast[hidden] {
		display: none;
	}
</style>
