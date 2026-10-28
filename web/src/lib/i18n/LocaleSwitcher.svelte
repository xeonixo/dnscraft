<script lang="ts">
	import { locales, type Locale } from '$lib/paraglide/runtime';
	import { m } from '$lib/paraglide/messages';
	import { getLocale, localeName, setLocale } from './locale';

	let current = $state<Locale>(getLocale());

	function onchange(event: Event): void {
		const next = (event.currentTarget as HTMLSelectElement).value as Locale;
		current = next;
		setLocale(next);
	}
</script>

<label class="locale-switcher">
	<span>{m.locale_switcher_label()}</span>
	<select value={current} {onchange}>
		{#each locales as locale (locale)}
			<option value={locale}>{localeName(locale)}</option>
		{/each}
	</select>
</label>

<style>
	.locale-switcher {
		display: inline-flex;
		align-items: center;
		gap: var(--space-2);
		min-height: 2.75rem;
		color: var(--label);
	}

	select {
		min-height: 2.75rem;
		min-width: 2.75rem;
		padding-inline: var(--space-3);
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		background: var(--surface);
		color: var(--label);
		font: inherit;
	}
</style>
