<script lang="ts">
	import { m } from '$lib/paraglide/messages';
	import LocaleSwitcher from '$lib/i18n/LocaleSwitcher.svelte';
</script>

<main>
	<h1>{m.app_name()}</h1>
	<LocaleSwitcher />
</main>

<style>
	main {
		display: grid;
		gap: var(--space-4);
		justify-items: start;
		padding: var(--space-5);
	}
</style>
