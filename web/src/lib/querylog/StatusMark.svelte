<script lang="ts">
	import Icon from '$lib/components/Icon.svelte';
	import type { IconName, StatusTone } from '$lib/components/icons';

	interface Props {
		icon: IconName;
		tone: StatusTone;
		/** Translated verdict word; the icon and the word carry the state, not the colour alone. */
		label: string;
	}

	let { icon, tone, label }: Props = $props();
</script>

<span class="mark {tone}">
	<Icon name={icon} size="1rem" strokeWidth={1.7} />
	<span>{label}</span>
</span>

<style>
	.mark {
		display: inline-flex;
		align-items: center;
		gap: 0.375rem;
		font-size: 0.8125rem;
		font-weight: 500;
		white-space: nowrap;
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
		color: var(--label-2);
	}
</style>
