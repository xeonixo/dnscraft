<script lang="ts">
	import type { Snippet } from 'svelte';
	import { resolve } from '$app/paths';
	import type { StaticRouteId } from '$lib/nav';

	interface Props {
		/** Primary label (translated, or untrusted data rendered as text). */
		label: string;
		/** Secondary label under the primary one. */
		detail?: string;
		leading?: Snippet;
		trailing?: Snippet;
		/** Makes the whole row a link (SvelteKit route path). */
		href?: StaticRouteId;
		/** Makes the whole row a button (used when the row opens an editor instead of a route). */
		onclick?: () => void;
		/** Primary label is a domain, IP or identifier: SF Mono. */
		mono?: boolean;
		/** Secondary label is an identifier: SF Mono. */
		detailMono?: boolean;
		/** Proportional background bar behind the row, 0..1 (decorative; the value stays in the trailing text). */
		share?: number;
		shareTone?: 'accent' | 'danger';
		/** Primary label is cut to one line with an ellipsis instead of wrapping. */
		truncate?: boolean;
	}

	let {
		label,
		detail,
		leading,
		trailing,
		href,
		onclick,
		mono = false,
		detailMono = false,
		share,
		shareTone = 'accent',
		truncate = false,
	}: Props = $props();

	const shareWidth = $derived(share === undefined ? 0 : Math.min(1, Math.max(0, share)) * 100);
</script>

{#snippet content()}
	{#if share !== undefined}
		<span class="meter {shareTone}" aria-hidden="true" style:width="{shareWidth}%"></span>
	{/if}
	{#if leading}
		<span class="leading">{@render leading()}</span>
	{/if}
	<span class="main">
		<span class="label" class:mono class:truncate>{label}</span>
		{#if detail}
			<span class="detail" class:mono={detailMono}>{detail}</span>
		{/if}
	</span>
	{#if trailing}
		<span class="trailing">{@render trailing()}</span>
	{/if}
{/snippet}

{#if href}
	<a class="row" href={resolve(href)}>{@render content()}</a>
{:else if onclick}
	<button type="button" class="row interactive" {onclick}>{@render content()}</button>
{:else}
	<div class="row">{@render content()}</div>
{/if}

<style>
	.row {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		min-height: 3.25rem;
		padding: 0.75rem 1rem;
		color: var(--label);
		text-decoration: none;
		position: relative;
	}

	a.row:hover,
	.row.interactive:hover {
		background: var(--surface-2);
	}

	.row.interactive {
		width: 100%;
		border: none;
		background: transparent;
		font: inherit;
		text-align: start;
		cursor: pointer;
	}

	@media (max-width: 54.99rem) {
		.row {
			min-height: 2.75rem;
			padding: 0.5rem 1rem;
		}
	}

	.leading,
	.trailing {
		display: inline-flex;
		align-items: center;
		flex: 0 0 auto;
		position: relative;
	}

	.meter {
		position: absolute;
		/* A thin share indicator along the bottom edge: the text keeps the row's full contrast. */
		inset-block-end: 0;
		inset-inline-start: 0;
		height: 3px;
		max-width: 100%;
		pointer-events: none;
		background: var(--accent);
		opacity: 0.6;
	}

	.meter.danger {
		background: var(--danger);
	}

	.trailing {
		margin-inline-start: auto;
		text-align: end;
	}

	.main {
		display: flex;
		flex: 1 1 auto;
		flex-direction: column;
		min-width: 0;
		position: relative;
	}

	.label {
		font-size: 0.9375rem;
		overflow-wrap: anywhere;
	}

	.detail {
		margin-top: 0.0625rem;
		font-size: 0.78125rem;
		color: var(--label-2);
		overflow-wrap: anywhere;
	}

	.label.truncate {
		display: block;
		overflow: hidden;
		white-space: nowrap;
		text-overflow: ellipsis;
	}

	.mono {
		font-family: var(--font-mono);
	}

	.label.mono {
		font-size: 0.875rem;
	}
</style>
