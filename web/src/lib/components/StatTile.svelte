<script lang="ts">
	import Icon from './Icon.svelte';
	import type { IconName } from './icons';

	interface Props {
		label: string;
		value: string | number;
		unit?: string;
		/** Semantic accent; always shown with an icon and the translated toneLabel. */
		tone?: 'ok' | 'danger';
		toneLabel?: string;
	}

	let { label, value, unit, tone, toneLabel }: Props = $props();

	const toneIcon: Record<'ok' | 'danger', IconName> = {
		ok: 'check-circle',
		danger: 'x-circle',
	};
</script>

<div class="tile" class:ok={tone === 'ok'} class:danger={tone === 'danger'}>
	<span class="name">{label}</span>
	<span class="value num">
		{value}{#if unit}<span class="unit">{unit}</span>{/if}
	</span>
	{#if tone}
		<span class="tone">
			<Icon name={toneIcon[tone]} size="0.875rem" strokeWidth={2} />
			{#if toneLabel}<span>{toneLabel}</span>{/if}
		</span>
	{/if}
</div>

<style>
	.tile {
		display: flex;
		flex-direction: column;
		gap: 0.625rem;
		min-width: 0;
		padding: 1rem;
		background: var(--surface);
		border: 1px solid var(--separator);
		border-radius: var(--r-card);
		box-shadow: var(--shadow);
	}

	.name {
		font-size: 0.84375rem;
		color: var(--label-2);
		overflow-wrap: anywhere;
	}

	.value {
		font-size: 1.875rem;
		font-weight: 700;
		line-height: 1.05;
		letter-spacing: -0.03em;
		overflow-wrap: anywhere;
	}

	.unit {
		margin-inline-start: 0.125rem;
		font-size: 0.9375rem;
		font-weight: 600;
		letter-spacing: 0;
		color: var(--label-2);
	}

	.tone {
		display: inline-flex;
		align-items: center;
		gap: 0.3125rem;
		font-size: 0.78125rem;
		font-weight: 500;
		color: var(--label-3);
	}

	.tile.ok .tone {
		color: var(--ok);
	}

	.tile.danger .tone,
	.tile.danger .value {
		/* danger-fill is darker than --danger and clears 4.5:1 on surface. */
		color: var(--danger-fill);
	}

	.num {
		font-variant-numeric: tabular-nums;
	}
</style>
