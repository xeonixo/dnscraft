<script lang="ts">
	import type { Snippet } from 'svelte';
	import { onMount } from 'svelte';
	import '$lib/styles/tokens.css';
	import '$lib/styles/base.css';
	import { afterNavigate, goto } from '$app/navigation';
	import { page } from '$app/state';
	import { resolve } from '$app/paths';
	import AppShell from '$lib/components/AppShell.svelte';
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import LiveRegion from '$lib/components/LiveRegion.svelte';
	import { roleLabel, routeDecision } from '$lib/auth/guards';
	import { isPublicPath } from '$lib/auth/public-routes';
	import { auth } from '$lib/auth/state.svelte';
	import { loadMe } from '$lib/auth/store.svelte';
	import { getLocale } from '$lib/i18n/locale';
	import { navItemForPath } from '$lib/nav';
	import { m } from '$lib/paraglide/messages';
	import { CLIENT_NETWORK } from '$lib/api/error-codes';
	import { enablePullToRefresh } from '$lib/pwa/pull-to-refresh';
	import { registerServiceWorker } from '$lib/pwa/register-sw';
	import { themeColorFor } from '$lib/pwa/theme-colors';
	import { initTheme, resolveTheme, theme } from '$lib/theme';

	let { children }: { children: Snippet } = $props();

	// The SPA ships one static index.html, so <html lang> follows the active locale at runtime.
	document.documentElement.lang = getLocale();
	initTheme();

	const path = $derived(page.url.pathname);
	const publicRoute = $derived(isPublicPath(path));
	const decision = $derived(routeDecision({ status: auth.status, path, role: auth.role }));
	const requiredRole = $derived(navItemForPath(path)?.minRole ?? 'viewer');
	const title = $derived(navItemForPath(path)?.label() ?? m.app_name());
	const resolvedTheme = $derived(resolveTheme($theme));
	const themeColor = $derived(themeColorFor(resolvedTheme));

	onMount(() => {
		registerServiceWorker();
		void loadMe();
		return enablePullToRefresh();
	});

	// A lost session (401) or a sign-out leaves the anonymous state; a protected route then moves to /login.
	$effect(() => {
		if (auth.status === 'anonymous' && !publicRoute) {
			void goto(resolve('/login'), { replaceState: true });
		}
	});

	// Moves focus to the new screen title so assistive technology announces the navigation.
	// Filter and search changes only touch the query string and keep focus where it is.
	afterNavigate((nav) => {
		const from = nav.from?.url?.pathname;
		if (from !== undefined && from === nav.to?.url?.pathname) return;
		document.getElementById('page-title')?.focus({ preventScroll: true });
	});
</script>

<svelte:head>
	<title>{m.document_title({ page: title, app: m.app_name() })}</title>
	<meta name="theme-color" content={themeColor} />
	<link rel="manifest" href="/manifest.webmanifest" />
</svelte:head>

{#if publicRoute}
	{@render children()}
{:else if auth.status === 'authenticated'}
	<AppShell {title} currentPath={path} role={auth.role}>
		{#if decision === 'forbidden'}
			<section class="permission">
				<p>{m.error_control_api_auth_insufficient_scope({ required: roleLabel(requiredRole) })}</p>
				<a href={resolve('/dashboard')}>{m.back_to_dashboard()}</a>
			</section>
		{:else}
			{@render children()}
		{/if}
	</AppShell>
{:else if auth.status === 'unknown' && auth.loadErrorCode}
	<main class="standalone">
		{#if auth.loadErrorCode === CLIENT_NETWORK}
			<div class="offline" role="alert">
				<p class="offline-message">{m.state_backend_unreachable()}</p>
				<Button variant="primary" onclick={() => void loadMe()}>{m.action_retry()}</Button>
			</div>
		{:else}
			<ErrorNotice code={auth.loadErrorCode} onretry={() => void loadMe()} />
		{/if}
	</main>
{:else}
	<main class="standalone">
		<p class="pending">{m.state_loading()}</p>
	</main>
{/if}

<!-- One polite region for every screen: announcements from any route reach it. -->
<LiveRegion />

<style>
	.standalone {
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
		box-sizing: border-box;
		max-width: 27.5rem;
		min-height: 100dvh;
		margin: 0 auto;
		padding: var(--space-6) var(--space-4);
		justify-content: center;
	}

	.pending {
		margin: 0;
		color: var(--label-2);
		text-align: center;
	}

	.offline {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
		padding: var(--space-4);
		background: var(--surface);
		border: 1px solid var(--separator);
		border-radius: var(--r-card);
		color: var(--label);
	}

	.offline-message {
		margin: 0;
		font-weight: 600;
		overflow-wrap: anywhere;
	}

	.permission {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
		padding: var(--space-5);
		background: var(--surface);
		border: 1px solid var(--separator);
		border-radius: var(--r-card);
		color: var(--label);
	}

	.permission p {
		margin: 0;
		overflow-wrap: anywhere;
	}

	.permission a {
		align-self: flex-start;
		display: inline-flex;
		align-items: center;
		min-height: 2.75rem;
		color: var(--accent);
		text-decoration: none;
	}

	.permission a:hover {
		text-decoration: underline;
	}
</style>
