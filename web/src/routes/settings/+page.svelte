<script lang="ts">
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import Segmented from '$lib/components/Segmented.svelte';
	import LocaleSwitcher from '$lib/i18n/LocaleSwitcher.svelte';
	import { m } from '$lib/paraglide/messages';
	import { setTheme, theme, type ThemeChoice } from '$lib/theme';

	const themeOptions: { value: ThemeChoice; label: string }[] = [
		{ value: 'light', label: m.theme_light() },
		{ value: 'dark', label: m.theme_dark() },
		{ value: 'system', label: m.theme_system() },
	];

	// Groups that W9 fills in; until then each one says it follows later.
	const pendingHeaders: (() => string)[] = [
		m.settings_group_account,
		m.settings_group_logging,
		m.settings_group_update,
		m.settings_group_tokens,
		m.settings_group_audit,
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

<GroupedList header={m.settings_group_language()}>
	<div class="locale">
		<LocaleSwitcher />
	</div>
</GroupedList>

{#each pendingHeaders as header, index (index)}
	<GroupedList header={header()}>
		<GroupedRow label={m.settings_pending()} />
	</GroupedList>
{/each}

<style>
	.locale {
		padding: 0.5rem 1rem;
	}
</style>
