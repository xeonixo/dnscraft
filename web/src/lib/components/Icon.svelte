<script lang="ts">
	import { ICON_SHAPES, type IconName } from './icons';

	interface Props {
		name: IconName;
		/** Rendered width and height; rem keeps icons aligned with text scaling. */
		size?: string;
		/** Prototype stroke weight; 1.6 for regular icons, heavier for toolbar glyphs. */
		strokeWidth?: number;
	}

	let { name, size = '1.0625rem', strokeWidth = 1.6 }: Props = $props();
	const shapes = $derived(ICON_SHAPES[name]);
</script>

<!-- Decorative: every icon is paired with a visible label or an accessible name by its caller. -->
<svg
	class="icon"
	style:width={size}
	style:height={size}
	viewBox="0 0 24 24"
	fill="none"
	stroke="currentColor"
	stroke-width={strokeWidth}
	stroke-linecap="round"
	stroke-linejoin="round"
	aria-hidden="true"
	focusable="false"
>
	{#each shapes as shape, index (index)}
		<svelte:element this={shape.tag} {...shape.attrs} />
	{/each}
</svg>

<style>
	.icon {
		display: inline-block;
		flex: 0 0 auto;
		vertical-align: middle;
	}
</style>
