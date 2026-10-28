<script lang="ts">
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import Placeholder from '$lib/components/Placeholder.svelte';
	import Segmented from '$lib/components/Segmented.svelte';
	import LocaleSwitcher from '$lib/i18n/LocaleSwitcher.svelte';
	import { m } from '$lib/paraglide/messages';
	import { setTheme, theme, type ThemeChoice } from '$lib/theme';

	const themeOptions: { value: ThemeChoice; label: string }[] = [
		{ value: 'light', label: m.theme_light() },
		{ value: 'dark', label: m.theme_dark() },
		{ value: 'system', label: m.theme_system() },
	];
</script>

<GroupedList>
	<GroupedRow label={m.theme_group_label()}>
		{#snippet trailing()}
			<Segmented
				options={themeOptions}
				value={$theme}
				label={m.theme_group_label()}
				onchange={(choice) => setTheme(choice)}
			/>
		{/snippet}
	</GroupedRow>
</GroupedList>

<GroupedList>
	<div class="locale">
		<LocaleSwitcher />
	</div>
</GroupedList>

<Placeholder />

<style>
	.locale {
		padding: 0.5rem 1rem;
	}
</style>
