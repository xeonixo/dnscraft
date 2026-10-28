<script lang="ts">
	import { page } from '$app/state';
	import { resolve } from '$app/paths';
	import { m } from '$lib/paraglide/messages';

	// Rendered inside the root layout, so it keeps the shell and the session checks. Unmatched
	// addresses arrive with status 404. The raw error message is never shown.
	const notFound = $derived(page.status === 404);
</script>

<section class="error-page">
	{#if notFound}
		<h2>{m.not_found_title()}</h2>
		<p>{m.not_found_text()}</p>
	{:else}
		<h2>{m.state_error()}</h2>
	{/if}
	<a href={resolve('/dashboard')}>{m.back_to_dashboard()}</a>
</section>

<style>
	.error-page {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
		padding: var(--space-6) var(--space-5);
		background: var(--surface);
		border: 1px solid var(--separator);
		border-radius: var(--r-card);
		color: var(--label-2);
	}

	h2 {
		margin: 0;
		font-size: 1.125rem;
		color: var(--label);
	}

	p {
		margin: 0;
	}

	a {
		align-self: flex-start;
		display: inline-flex;
		align-items: center;
		min-height: 2.75rem;
		color: var(--accent);
		text-decoration: none;
	}

	a:hover {
		text-decoration: underline;
	}
</style>
