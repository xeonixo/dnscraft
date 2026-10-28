<script lang="ts">
	import type { Snippet } from 'svelte';
	import '$lib/styles/tokens.css';
	import '$lib/styles/base.css';
	import { afterNavigate } from '$app/navigation';
	import { page } from '$app/state';
	import AppShell from '$lib/components/AppShell.svelte';
	import { getLocale } from '$lib/i18n/locale';
	import { navItemForPath } from '$lib/nav';
	import { m } from '$lib/paraglide/messages';
	import { initTheme } from '$lib/theme';

	let { children }: { children: Snippet } = $props();

	// The SPA ships one static index.html, so <html lang> follows the active locale at runtime.
	document.documentElement.lang = getLocale();
	initTheme();

	const title = $derived(navItemForPath(page.url.pathname)?.label() ?? m.app_name());

	// Moves focus to the new screen title so assistive technology announces the navigation.
	afterNavigate(() => {
		document.getElementById('page-title')?.focus({ preventScroll: true });
	});
</script>

<svelte:head>
	<title>{m.document_title({ page: title, app: m.app_name() })}</title>
</svelte:head>

<AppShell {title} currentPath={page.url.pathname}>
	{@render children()}
</AppShell>
