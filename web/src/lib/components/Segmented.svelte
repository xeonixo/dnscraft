<script lang="ts" generics="T extends string">
	interface Option {
		value: T;
		label: string;
	}

	interface Props {
		options: Option[];
		value: T;
		/** Accessible name of the group (a translated message). */
		label: string;
		onchange?: (value: T) => void;
	}

	let { options, value = $bindable(), label, onchange }: Props = $props();
	let buttons: HTMLButtonElement[] = [];

	function select(next: T): void {
		value = next;
		onchange?.(next);
	}

	// Radio-group keyboard model: arrows move and select (wrapping), Home and End jump.
	function onkeydown(event: KeyboardEvent, index: number): void {
		const last = options.length - 1;
		let target: number;
		switch (event.key) {
			case 'ArrowRight':
			case 'ArrowDown':
				target = index === last ? 0 : index + 1;
				break;
			case 'ArrowLeft':
			case 'ArrowUp':
				target = index === 0 ? last : index - 1;
				break;
			case 'Home':
				target = 0;
				break;
			case 'End':
				target = last;
				break;
			default:
				return;
		}
		event.preventDefault();
		select(options[target].value);
		buttons[target]?.focus();
	}
</script>

<div class="segmented" role="radiogroup" aria-label={label}>
	{#each options as option, index (option.value)}
		{@const checked = option.value === value}
		<button
			type="button"
			role="radio"
			class="segment"
			aria-checked={checked}
			tabindex={checked ? 0 : -1}
			bind:this={buttons[index]}
			onclick={() => select(option.value)}
			onkeydown={(event) => onkeydown(event, index)}
		>
			{option.label}
		</button>
	{/each}
</div>

<style>
	.segmented {
		display: inline-flex;
		max-width: 100%;
		gap: 0.125rem;
		padding: 0.125rem;
		background: var(--surface);
		border: 1px solid var(--separator);
		border-radius: 0.5625rem;
	}

	.segment {
		min-width: 2.75rem;
		min-height: var(--control-h);
		padding: 0.3125rem 0.8125rem;
		appearance: none;
		border: 0;
		border-radius: 0.4375rem;
		background: transparent;
		color: var(--label);
		font: inherit;
		font-size: 0.84375rem;
		white-space: nowrap;
		cursor: pointer;
	}

	.segment[aria-checked='true'] {
		background: var(--label);
		color: var(--canvas);
		font-weight: 600;
	}
</style>
