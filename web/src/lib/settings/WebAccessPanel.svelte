<script lang="ts">
	import { onMount } from 'svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import Switch from '$lib/components/Switch.svelte';
	import {
		deleteWebBan,
		getWebAccess,
		getWebBans,
		putWebAccess,
		type WebBan,
	} from '$lib/api/system';
	import { formatDateTime } from '$lib/format';
	import { getLocale } from '$lib/i18n/locale';
	import { failureOf } from '$lib/api/result';
	import { announce } from '$lib/live.svelte';
	import { m } from '$lib/paraglide/messages';

	interface Props {
		isAdmin: boolean;
	}

	let { isAdmin }: Props = $props();

	const locale = getLocale();

	let bans = $state<WebBan[]>([]);
	let enabled = $state(false);
	let loaded = $state(false);
	let busy = $state(false);
	let failure = $state<{ code: string; params: Record<string, unknown> } | null>(null);

	onMount(() => {
		if (!isAdmin) return;
		void getWebAccess()
			.then((access) => {
				enabled = access.public_enabled;
				loaded = true;
				void loadBans();
			})
			.catch((cause) => {
				failure = failureOf(cause);
			});
	});

	async function loadBans(): Promise<void> {
		try {
			bans = (await getWebBans()).items ?? [];
		} catch {
			// No ban table on this node: the list simply stays empty.
			bans = [];
		}
	}

	async function unban(ip: string): Promise<void> {
		failure = null;
		try {
			await deleteWebBan(ip);
			announce(m.settings_web_bans_lifted({ ip }));
		} catch (cause) {
			failure = failureOf(cause);
		}
		await loadBans();
	}

	async function toggle(next: boolean): Promise<void> {
		busy = true;
		failure = null;
		try {
			enabled = (await putWebAccess(next)).public_enabled;
			announce(enabled ? m.settings_web_access_on() : m.settings_web_access_off());
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}
</script>

{#if isAdmin && (loaded || failure)}
	<GroupedList header={m.settings_group_web_access()} footer={m.settings_web_access_footer()}>
		{#if loaded}
			<GroupedRow
				label={m.settings_web_access_label()}
				detail={enabled ? m.settings_web_access_on() : m.settings_web_access_off()}
			>
				{#snippet trailing()}
					<Switch
						checked={enabled}
						disabled={busy}
						aria-label={m.settings_web_access_label()}
						onchange={(event) => void toggle(event.currentTarget.checked)}
					/>
				{/snippet}
			</GroupedRow>
		{/if}
		{#if failure}
			<div class="notice">
				<ErrorNotice code={failure.code} params={failure.params} />
			</div>
		{/if}
	</GroupedList>
	{#if bans.length > 0}
		<GroupedList header={m.settings_web_bans_header()}>
			{#each bans as ban (ban.ip)}
				<GroupedRow
					label={ban.ip}
					mono
					detail={m.settings_web_bans_until({
						time: formatDateTime(new Date(ban.until), locale),
					})}
				>
					{#snippet trailing()}
						<button class="unban" type="button" onclick={() => void unban(ban.ip)}>
							{m.settings_web_bans_unban()}
						</button>
					{/snippet}
				</GroupedRow>
			{/each}
		</GroupedList>
	{/if}
{/if}

<style>
	.unban {
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
