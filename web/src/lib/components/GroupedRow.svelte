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
		/** Primary label is a domain, IP or identifier: SF Mono. */
		mono?: boolean;
		/** Secondary label is an identifier: SF Mono. */
		detailMono?: boolean;
	}

	let {
		label,
		detail,
		leading,
		trailing,
		href,
		mono = false,
		detailMono = false,
	}: Props = $props();
</script>

{#snippet content()}
	{#if leading}
		<span class="leading">{@render leading()}</span>
	{/if}
	<span class="main">
		<span class="label" class:mono>{label}</span>
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
	}

	a.row:hover {
		background: var(--surface-2);
	}

	.leading,
	.trailing {
		display: inline-flex;
		align-items: center;
		flex: 0 0 auto;
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

	.mono {
		font-family: var(--font-mono);
	}

	.label.mono {
		font-size: 0.875rem;
	}
</style>
