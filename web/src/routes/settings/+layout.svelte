<script lang="ts">
	import type { Snippet } from 'svelte';
	import { resolve } from '$app/paths';
	import { page } from '$app/state';
	import { settingsTabs } from '$lib/nav';
	import { m } from '$lib/paraglide/messages';

	let { children }: { children: Snippet } = $props();

	// One tab bar for every Einstellungen screen; the nav item and the page title stay "Einstellungen".
	const path = $derived(page.url.pathname);
</script>

<nav class="tabs" aria-label={m.settings_tabs_label()}>
	{#each settingsTabs as tab (tab.path)}
		<a class="tab" href={resolve(tab.path)} aria-current={tab.path === path ? 'page' : undefined}
			>{tab.label()}</a
		>
	{/each}
</nav>

{@render children()}

<style>
	.tabs {
		display: flex;
		flex-wrap: wrap;
		gap: 0.125rem;
		box-sizing: border-box;
		width: 100%;
		padding: 0.125rem;
		background: var(--surface);
		border: 1px solid var(--separator);
		border-radius: 0.5625rem;
	}

	.tab {
		display: inline-flex;
		flex: 1 1 auto;
		align-items: center;
		justify-content: center;
		min-width: 2.75rem;
		min-height: 2.75rem;
		padding: 0.3125rem 0.8125rem;
		border-radius: 0.4375rem;
		color: var(--label);
		font-size: 0.84375rem;
		text-align: center;
		text-decoration: none;
	}

	.tab:hover {
		background: var(--surface-2);
	}

	.tab[aria-current='page'] {
		background: var(--label);
		color: var(--canvas);
		font-weight: 600;
	}
</style>
