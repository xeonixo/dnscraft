<script lang="ts">
	import { onMount } from 'svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import Segmented from '$lib/components/Segmented.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import LocaleSwitcher from '$lib/i18n/LocaleSwitcher.svelte';
	import AuditPanel from '$lib/settings/AuditPanel.svelte';
	import TokensPanel from '$lib/settings/TokensPanel.svelte';
	import UnifiPanel from '$lib/settings/UnifiPanel.svelte';
	import { getConfig } from '$lib/api/config';
	import { getUpdateCheck, type UpdateCheck } from '$lib/api/system';
	import { getStatus } from '$lib/api/stats';
	import { failureOf, settle, type Result } from '$lib/api/result';
	import { auth } from '$lib/auth/state.svelte';
	import { patchConfigSection } from '$lib/settings/config-patch';
	import { m } from '$lib/paraglide/messages';
	import { setTheme, theme, type ThemeChoice } from '$lib/theme';

	const themeOptions: { value: ThemeChoice; label: string }[] = [
		{ value: 'light', label: m.theme_light() },
		{ value: 'dark', label: m.theme_dark() },
		{ value: 'system', label: m.theme_system() },
	];

	const isAdmin = $derived(auth.role === 'admin');

	let retentionDays = $state<number | null>(null);
	let retentionBusy = $state(false);
	let retentionFailure = $state<{ code: string; params: Record<string, unknown> } | null>(null);

	let update = $state<Result<UpdateCheck>>({ kind: 'loading' });
	let runningVersion = $state<string>('—');

	onMount(() => {
		void loadLogging();
		void loadUpdate();
		void getStatus()
			.then((status) => {
				runningVersion = status.version;
			})
			.catch(() => {
				runningVersion = '—';
			});
	});

	async function loadLogging(): Promise<void> {
		try {
			const snapshot = await getConfig();
			const settings = snapshot.config?.control_api_settings as Record<string, unknown> | undefined;
			const queryLog = settings?.query_log as Record<string, unknown> | undefined;
			const days = queryLog?.retention_days;
			retentionDays = typeof days === 'number' ? days : null;
		} catch {
			retentionDays = null;
		}
	}

	async function loadUpdate(): Promise<void> {
		update = await settle(getUpdateCheck());
	}

	async function saveRetention(): Promise<void> {
		if (!isAdmin || retentionDays === null) return;
		retentionBusy = true;
		retentionFailure = null;
		try {
			await patchConfigSection('control_api_settings', {
				query_log: { retention_days: retentionDays },
			});
		} catch (cause) {
			retentionFailure = failureOf(cause);
		} finally {
			retentionBusy = false;
		}
	}
</script>

<GroupedList header={m.settings_group_account()}>
	<GroupedRow label={m.settings_account_actor()} detail={auth.actorId} detailMono />
	<GroupedRow label={m.settings_account_role()} detail={auth.role} />
</GroupedList>

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

<GroupedList header={m.settings_group_logging()}>
	{#if isAdmin}
		<GroupedRow label={m.settings_retention_label()}>
			{#snippet trailing()}
				<input
					class="retention field"
					type="number"
					min="1"
					max="3650"
					bind:value={retentionDays}
					aria-label={m.settings_retention_label()}
				/>
				<button
					class="save-link"
					type="button"
					disabled={retentionBusy}
					onclick={() => void saveRetention()}
				>
					{m.action_save()}
				</button>
			{/snippet}
		</GroupedRow>
		{#if retentionFailure}
			<div class="notice">
				<ErrorNotice code={retentionFailure.code} params={retentionFailure.params} />
			</div>
		{/if}
	{:else}
		<GroupedRow label={m.settings_retention_viewer()} />
	{/if}
	<GroupedRow label={m.settings_ip_truncation_note()} />
</GroupedList>

<GroupedList header={m.settings_group_update()}>
	<GroupedRow label={m.settings_running_version()} detail={runningVersion} detailMono />
	{#if update.kind === 'loading'}
		<GroupedRow label={m.state_loading()} />
	{:else if update.kind === 'unavailable'}
		<GroupedRow label={m.settings_update_unavailable()} />
	{:else if update.kind === 'error'}
		<GroupedRow label={m.settings_update_unavailable()} detail={update.code} detailMono />
	{:else if update.kind === 'ok' && !update.data.enabled}
		<GroupedRow label={m.settings_update_disabled()} />
	{:else if update.kind === 'ok' && update.data.update_available && update.data.release_url}
		<GroupedRow
			label={m.settings_update_available()}
			detail={`${m.settings_update_version({ latest: update.data.latest ?? '—' })} · ${update.data.release_url}`}
			detailMono
		/>
	{:else if update.kind === 'ok'}
		<GroupedRow label={m.settings_update_current()} detail={update.data.latest ?? '—'} detailMono />
	{/if}
</GroupedList>

<UnifiPanel {isAdmin} />
<TokensPanel {isAdmin} />
<AuditPanel {isAdmin} />

<style>
	.locale {
		padding: 0.5rem 1rem;
	}

	.retention.field {
		width: 5rem;
		min-height: 2.75rem;
		padding: 0.375rem 0.5rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-control);
		background: var(--surface);
	}

	.save-link {
		min-height: 2.75rem;
		padding: 0 0.75rem;
		border: none;
		background: transparent;
		color: var(--accent);
		font: inherit;
		cursor: pointer;
	}

	.notice {
		padding: 0 1rem 0.75rem;
	}
</style>
