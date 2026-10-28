<script lang="ts">
	import type { Snippet } from 'svelte';
	import '$lib/styles/tokens.css';
	import '$lib/styles/base.css';
	import { m } from '$lib/paraglide/messages';
	import { getLocale } from '$lib/i18n/locale';

	let { children }: { children: Snippet } = $props();

	// The SPA ships one static index.html, so <html lang> follows the active locale at runtime.
	document.documentElement.lang = getLocale();
</script>

<svelte:head>
	<title>{m.app_name()}</title>
</svelte:head>

{@render children()}
