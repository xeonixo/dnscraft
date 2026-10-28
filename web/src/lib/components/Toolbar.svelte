<script lang="ts">
	import type { Snippet } from 'svelte';
	import Icon from './Icon.svelte';
	import { m } from '$lib/paraglide/messages';
	import { resolveTheme, setTheme, theme } from '$lib/theme';

	interface Props {
		title: string;
		menuExpanded: boolean;
		menuControls: string;
		onmenu: () => void;
		/** Bound to the menu button so the shell can return focus to it. */
		menuButton?: HTMLButtonElement;
		/** Trailing page actions, such as the primary action of the screen. */
		actions?: Snippet;
	}

	let {
		title,
		menuExpanded,
		menuControls,
		onmenu,
		menuButton = $bindable(),
		actions,
	}: Props = $props();

	const shown = $derived(resolveTheme($theme));

	function toggleTheme(): void {
		setTheme(shown === 'dark' ? 'light' : 'dark');
	}
</script>

<header class="toolbar">
	<button
		type="button"
		class="icon-btn menu-btn"
		aria-label={m.nav_menu_open()}
		aria-controls={menuControls}
		aria-expanded={menuExpanded}
		bind:this={menuButton}
		onclick={onmenu}
	>
		<Icon name="menu" size="1.125rem" strokeWidth={1.8} />
	</button>
	<h1 id="page-title" tabindex="-1">{title}</h1>
	<div class="spacer"></div>
	<div class="actions">
		{#if actions}
			{@render actions()}
		{/if}
		<button
			type="button"
			class="icon-btn"
			aria-label={m.theme_toggle_label()}
			onclick={toggleTheme}
		>
			<Icon name={shown === 'dark' ? 'moon' : 'sun'} />
		</button>
	</div>
</header>

<style>
	.toolbar {
		position: sticky;
		top: 0;
		z-index: 5;
		display: flex;
		align-items: center;
		gap: 0.75rem;
		padding: calc(0.875rem + env(safe-area-inset-top)) 1.25rem 0.75rem;
		background: var(--material-bg);
		backdrop-filter: var(--material-blur);
		-webkit-backdrop-filter: var(--material-blur);
		border-bottom: 1px solid var(--separator);
	}

	h1 {
		margin: 0;
		font-size: 1.3125rem;
		font-weight: 700;
		letter-spacing: -0.02em;
	}

	h1:focus {
		outline: none;
	}

	.spacer {
		flex: 1 1 auto;
	}

	.actions {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}

	.icon-btn {
		display: grid;
		place-items: center;
		min-width: 2.75rem;
		min-height: 2.75rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		background: var(--surface);
		color: var(--label);
		cursor: pointer;
	}

	.icon-btn:hover {
		background: var(--surface-2);
	}

	/* Compact-first: the sidebar becomes a drawer opened from this button below 55rem. */
	@media (min-width: 55rem) {
		.menu-btn {
			display: none;
		}
	}

	@media (max-width: 54.99rem) {
		.toolbar {
			padding-inline: 1rem;
		}

		h1 {
			font-size: 1.1875rem;
		}
	}
</style>
