<script lang="ts">
	import { onMount } from 'svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import Segmented from '$lib/components/Segmented.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import LocaleSwitcher from '$lib/i18n/LocaleSwitcher.svelte';
	import AuditPanel from '$lib/settings/AuditPanel.svelte';
	import TokensPanel from '$lib/settings/TokensPanel.svelte';
	import OidcPanel from '$lib/settings/OidcPanel.svelte';
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

	type IpTruncate = 'none' | 'last_octet' | 'last_group';
	const ipTruncateOptions: { value: IpTruncate; label: string }[] = [
		{ value: 'none', label: m.settings_ip_truncation_full() },
		{ value: 'last_octet', label: m.settings_ip_truncation_last_octet() },
		{ value: 'last_group', label: m.settings_ip_truncation_last_group() },
	];
	let ipTruncate = $state<IpTruncate>('none');
	let ipTruncateBusy = $state(false);
	let ipTruncateFailure = $state<{ code: string; params: Record<string, unknown> } | null>(null);
	// The stored query_log object as loaded. Saves send it back with the changed key, because the
	// section patch replaces `query_log` as a whole and would otherwise drop the other key.
	let queryLog = $state<Record<string, unknown> | null>(null);

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
			const stored = settings?.query_log as Record<string, unknown> | undefined;
			const days = stored?.retention_days;
			retentionDays = typeof days === 'number' ? days : null;
			const truncate = stored?.ip_truncate;
			ipTruncate = truncate === 'last_octet' || truncate === 'last_group' ? truncate : 'none';
			queryLog = stored ? { ...stored } : {};
		} catch {
			retentionDays = null;
			queryLog = null;
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
				query_log: { ...queryLog, retention_days: retentionDays },
			});
		} catch (cause) {
			retentionFailure = failureOf(cause);
		} finally {
			retentionBusy = false;
		}
	}

	async function saveIpTruncate(): Promise<void> {
		if (!isAdmin || queryLog === null) return;
		ipTruncateBusy = true;
		ipTruncateFailure = null;
		try {
			await patchConfigSection('control_api_settings', {
				query_log: { ...queryLog, ip_truncate: ipTruncate },
			});
		} catch (cause) {
			ipTruncateFailure = failureOf(cause);
		} finally {
			ipTruncateBusy = false;
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
	<GroupedRow label={m.settings_ip_truncation_label()} />
	<div class="ip-control">
		<select
			class="ip field"
			bind:value={ipTruncate}
			disabled={!isAdmin || ipTruncateBusy || queryLog === null}
			aria-label={m.settings_ip_truncation_label()}
		>
			{#each ipTruncateOptions as option (option.value)}
				<option value={option.value}>{option.label}</option>
			{/each}
		</select>
		{#if isAdmin}
			<button
				class="save-link"
				type="button"
				disabled={ipTruncateBusy || queryLog === null}
				onclick={() => void saveIpTruncate()}
			>
				{m.action_save()}
			</button>
		{/if}
	</div>
	{#if ipTruncateFailure}
		<div class="notice">
			<ErrorNotice code={ipTruncateFailure.code} params={ipTruncateFailure.params} />
		</div>
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

<OidcPanel {isAdmin} />
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

	.ip-control {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0 1rem 0.5rem;
	}

	.ip.field {
		flex: 1 1 auto;
		min-width: 0;
		min-height: 2.75rem;
		padding: 0.375rem 0.5rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-control);
		background: var(--surface);
		font: inherit;
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
