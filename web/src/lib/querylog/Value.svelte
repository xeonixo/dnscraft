<script lang="ts">
	import { DISPLAY_LIMIT, displayText } from '$lib/safe-text';
	import { m } from '$lib/paraglide/messages';

	interface Props {
		/** Untrusted value (domain, name, rule text). Rendered as text only, never as markup. */
		value: string | null | undefined;
		mono?: boolean;
		/** Code points shown before the value is cut behind an expansion. */
		limit?: number;
	}

	let { value, mono = false, limit = DISPLAY_LIMIT }: Props = $props();
	const shown = $derived(displayText(value, limit));
</script>

<span class="value" class:mono>{shown.text}</span>
{#if shown.truncated}
	<details class="more">
		<summary>{m.querylog_show_full()}</summary>
		<span class="full" class:mono>{shown.full}</span>
	</details>
{/if}

<style>
	.value {
		overflow-wrap: anywhere;
	}

	.mono {
		font-family: var(--font-mono);
		font-size: 0.875em;
	}

	.more {
		display: block;
		margin-top: 0.25rem;
	}

	.more summary {
		display: inline-flex;
		align-items: center;
		min-height: 2.75rem;
		color: var(--accent);
		cursor: pointer;
	}

	.full {
		display: block;
		padding: 0.5rem 0.625rem;
		background: var(--surface-2);
		border-radius: var(--r-ctl);
		overflow-wrap: anywhere;
		white-space: pre-wrap;
	}
</style>
