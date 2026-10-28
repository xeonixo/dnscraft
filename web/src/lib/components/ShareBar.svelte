<script lang="ts">
	interface Props {
		/** Share of the whole in 0..1; out-of-range values are clamped. */
		share: number;
	}

	let { share }: Props = $props();
	const width = $derived(Math.min(1, Math.max(0, share)) * 100);
</script>

<!-- Decorative: the share is always printed as text next to the bar. -->
<svg
	class="bar"
	viewBox="0 0 100 8"
	preserveAspectRatio="none"
	aria-hidden="true"
	focusable="false"
>
	<rect class="track" x="0" y="0" width="100" height="8" rx="4" />
	<rect class="fill" x="0" y="0" {width} height="8" rx="4" />
</svg>

<style>
	.bar {
		display: block;
		flex: 0 0 auto;
		width: 6rem;
		height: 0.5rem;
	}

	.track {
		fill: var(--surface-2);
	}

	.fill {
		fill: var(--accent);
	}
</style>
