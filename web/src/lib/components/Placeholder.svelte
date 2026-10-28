<script lang="ts">
	import { page } from '$app/state';
	import Icon from './Icon.svelte';
	import { m } from '$lib/paraglide/messages';
	import { navItemForPath } from '$lib/nav';

	// Every routed screen that is not built yet renders this, with the icon of its nav entry.
	const icon = $derived(navItemForPath(page.url.pathname)?.icon ?? 'info');
</script>

<section class="empty">
	<span class="symbol"><Icon name={icon} size="2rem" strokeWidth={1.4} /></span>
	<p>{m.state_coming_soon()}</p>
</section>

<style>
	.empty {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 0.75rem;
		padding: 2.5rem 1rem;
		background: var(--surface);
		border: 1px solid var(--separator);
		border-radius: var(--r-card);
		box-shadow: var(--shadow);
		color: var(--label-2);
		text-align: center;
	}

	.symbol {
		display: inline-flex;
		color: var(--label-3);
	}

	p {
		margin: 0;
	}
</style>
