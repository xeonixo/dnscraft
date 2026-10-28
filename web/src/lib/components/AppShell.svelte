<script lang="ts">
	import type { Snippet } from 'svelte';
	import Sidebar from './Sidebar.svelte';
	import Toolbar from './Toolbar.svelte';
	import { m } from '$lib/paraglide/messages';
	import type { Role } from '$lib/nav';

	interface Props {
		title: string;
		currentPath: string;
		role?: Role;
		actions?: Snippet;
		children: Snippet;
	}

	let { title, currentPath, role = 'viewer', actions, children }: Props = $props();

	const SIDEBAR_ID = 'sidebar-nav';
	let navOpen = $state(false);
	let menuButton: HTMLButtonElement | undefined = $state();

	function closeNav(restoreFocus: boolean): void {
		navOpen = false;
		if (restoreFocus) menuButton?.focus();
	}

	function onkeydown(event: KeyboardEvent): void {
		if (event.key === 'Escape' && navOpen) closeNav(true);
	}
</script>

<svelte:window {onkeydown} />

<div class="app">
	<Sidebar id={SIDEBAR_ID} {currentPath} {role} open={navOpen} onnavigate={() => closeNav(false)} />

	{#if navOpen}
		<button
			type="button"
			class="scrim"
			aria-label={m.nav_menu_close()}
			onclick={() => closeNav(true)}
		></button>
	{/if}

	<main class="main">
		<Toolbar
			{title}
			menuExpanded={navOpen}
			menuControls={SIDEBAR_ID}
			onmenu={() => (navOpen = !navOpen)}
			bind:menuButton
			{actions}
		/>
		<div class="content">
			{@render children()}
		</div>
	</main>
</div>

<style>
	.app {
		display: flex;
		min-height: 100dvh;
	}

	.main {
		display: flex;
		flex: 1 1 auto;
		flex-direction: column;
		min-width: 0;
	}

	.content {
		display: flex;
		flex-direction: column;
		gap: 1.125rem;
		box-sizing: border-box;
		width: 100%;
		max-width: 65rem;
		padding: 1.25rem;
	}

	.scrim {
		position: fixed;
		inset: 0;
		z-index: 39;
		padding: 0;
		border: 0;
		background: var(--scrim);
		cursor: pointer;
	}

	/* Compact width: content gutter 16px; wide: 20px. */
	@media (max-width: 54.99rem) {
		.content {
			gap: 1rem;
			padding: 1rem;
		}
	}
</style>
