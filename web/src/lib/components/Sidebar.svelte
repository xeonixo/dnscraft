<script lang="ts">
	import { resolve } from '$app/paths';
	import Icon from './Icon.svelte';
	import { m } from '$lib/paraglide/messages';
	import {
		isActivePath,
		isVisible,
		navFeedback,
		navSections,
		navSettings,
		type NavItem,
		type NavSection,
		type Role,
	} from '$lib/nav';

	interface Props {
		/** Route path of the current screen; only the item for that screen (or its sub-path) gets aria-current. */
		currentPath: string;
		role?: Role;
		sections?: NavSection[];
		/** Drawer state on compact widths; always visible from the wide breakpoint. */
		open?: boolean;
		id?: string;
		onnavigate?: () => void;
	}

	let {
		currentPath,
		role = 'viewer',
		sections = navSections,
		open = false,
		id,
		onnavigate,
	}: Props = $props();
</script>

{#snippet link(entry: NavItem)}
	<a
		class="nav-item"
		href={resolve(entry.path)}
		aria-current={isActivePath(entry.path, currentPath) ? 'page' : undefined}
		onclick={() => onnavigate?.()}
	>
		<span class="nav-icon"><Icon name={entry.icon} /></span>
		<span class="nav-label">{entry.label()}</span>
	</a>
{/snippet}

<aside {id} class="sidebar" class:open>
	<div class="brand">
		<span class="mark"><Icon name="globe" size="0.9375rem" strokeWidth={2} /></span>
		<span>{m.app_name()}</span>
	</div>

	<nav class="sections" aria-label={m.navigation_label()}>
		{#each sections as section, index (index)}
			{@const visible = section.items.filter((entry) => isVisible(entry, role))}
			{#if visible.length > 0}
				<p class="nav-section">{section.heading()}</p>
				{#each visible as entry (entry.path)}
					{@render link(entry)}
				{/each}
			{/if}
		{/each}
		<div class="nav-settings">
			{@render link(navSettings)}
		</div>
	</nav>

	<div class="sidebar-foot">
		<p class="node">
			<span class="node-dot" aria-hidden="true"></span>
			{m.sidebar_node_unknown()}
		</p>
		<a class="foot-link" href={resolve(navFeedback.path)} onclick={() => onnavigate?.()}>
			{navFeedback.label()}
		</a>
	</div>
</aside>

<style>
	.sidebar {
		position: fixed;
		inset: 0 auto 0 0;
		z-index: 40;
		display: flex;
		flex-direction: column;
		gap: 0.125rem;
		width: 15.5rem;
		max-width: 85vw;
		height: 100dvh;
		overflow-y: auto;
		padding: calc(0.75rem + env(safe-area-inset-top)) 0.625rem
			calc(1rem + env(safe-area-inset-bottom)) calc(0.625rem + env(safe-area-inset-left));
		background: var(--material-bg);
		backdrop-filter: var(--material-blur);
		-webkit-backdrop-filter: var(--material-blur);
		border-right: 1px solid var(--separator);
		transform: translateX(-100%);
		visibility: hidden;
		transition:
			transform var(--duration-normal) var(--ease),
			visibility 0s linear var(--duration-normal);
	}

	.sidebar.open {
		transform: none;
		visibility: visible;
		transition-delay: 0s;
	}

	/* Persistent sidebar from 55rem (880px at the default root size). */
	@media (min-width: 55rem) {
		.sidebar {
			position: sticky;
			top: 0;
			flex: 0 0 auto;
			transform: none;
			visibility: visible;
			max-width: none;
		}
	}

	.brand {
		display: flex;
		align-items: center;
		gap: 0.5625rem;
		padding: 0.25rem 0.5rem 0.75rem;
		font-size: 0.9375rem;
		font-weight: 600;
		letter-spacing: -0.01em;
	}

	.mark {
		display: grid;
		flex: 0 0 auto;
		place-items: center;
		width: 1.625rem;
		height: 1.625rem;
		border-radius: 0.4375rem;
		background: var(--accent-solid);
		color: var(--on-accent);
	}

	.sections {
		display: flex;
		flex-direction: column;
		gap: 0.125rem;
	}

	.nav-section {
		margin: 0;
		padding: 0.875rem 0.625rem 0.25rem;
		font-size: 0.71875rem;
		font-weight: 600;
		letter-spacing: 0.02em;
		text-transform: uppercase;
		color: var(--label-3);
	}

	.nav-item {
		display: flex;
		align-items: center;
		gap: 0.5625rem;
		min-height: 2.75rem;
		padding: 0.375rem 0.625rem;
		border-radius: 0.4375rem;
		color: var(--label);
		font-size: 0.9375rem;
		text-decoration: none;
	}

	.nav-item:not([aria-current='page']):hover {
		background: var(--surface);
	}

	.nav-item[aria-current='page'] {
		background: var(--accent-fill);
		color: var(--accent);
		font-weight: 500;
	}

	.nav-icon {
		display: inline-flex;
		color: var(--label-2);
	}

	.nav-item[aria-current='page'] .nav-icon {
		color: var(--accent);
	}

	.nav-label {
		min-width: 0;
		overflow-wrap: anywhere;
	}

	.nav-settings {
		margin-top: 0.75rem;
	}

	.sidebar-foot {
		display: flex;
		flex-direction: column;
		gap: 0.125rem;
		margin-top: auto;
		padding: 0.625rem;
		font-size: 0.8125rem;
	}

	.node {
		display: flex;
		align-items: center;
		gap: 0.4375rem;
		margin: 0;
		color: var(--label-2);
	}

	.node-dot {
		flex: 0 0 auto;
		width: 0.5rem;
		height: 0.5rem;
		border-radius: 50%;
		background: var(--track-off);
	}

	.foot-link {
		display: flex;
		align-items: center;
		min-height: 2.75rem;
		color: var(--accent);
		text-decoration: none;
	}

	.foot-link:hover {
		text-decoration: underline;
	}
</style>
