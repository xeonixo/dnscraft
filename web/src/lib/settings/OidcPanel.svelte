<script lang="ts">
	import { onMount } from 'svelte';
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import Switch from '$lib/components/Switch.svelte';
	import { getOidcStatus, putOidcClientSecret } from '$lib/api/auth';
	import { getConfig } from '$lib/api/config';
	import { failureOf } from '$lib/api/result';
	import { announce } from '$lib/live.svelte';
	import { patchConfigSection } from '$lib/settings/config-patch';
	import { m } from '$lib/paraglide/messages';

	interface Props {
		isAdmin: boolean;
	}

	let { isAdmin }: Props = $props();

	interface OidcForm {
		enabled: boolean;
		issuer: string;
		client_id: string;
		admin_group: string;
		groups_claim: string;
		token_skew_seconds: number;
		client_secret: string;
		clear_secret: boolean;
		has_client_secret: boolean;
		callback_path: string;
	}

	const DEFAULT_FORM: OidcForm = {
		enabled: false,
		issuer: '',
		client_id: '',
		admin_group: 'dnscraft-admin',
		groups_claim: 'groups',
		token_skew_seconds: 30,
		client_secret: '',
		clear_secret: false,
		has_client_secret: false,
		callback_path: '/api/v1/auth/oidc/callback',
	};

	let form = $state<OidcForm>({ ...DEFAULT_FORM });
	let loaded = $state(false);
	let loadFailure = $state<{ code: string; params: Record<string, unknown> } | null>(null);
	let saveBusy = $state(false);
	let saveFailure = $state<{ code: string; params: Record<string, unknown> } | null>(null);
	onMount(() => {
		if (isAdmin) void load();
	});

	async function load(): Promise<void> {
		loadFailure = null;
		try {
			const [snapshot, status] = await Promise.all([getConfig(), getOidcStatus()]);
			const settings = (snapshot.config?.control_api_settings ?? {}) as Record<string, unknown>;
			const stored = (settings.oidc ?? {}) as Record<string, unknown>;
			form = {
				enabled: stored.enabled === true || status.enabled,
				issuer: typeof stored.issuer === 'string' ? stored.issuer : status.issuer,
				client_id: typeof stored.client_id === 'string' ? stored.client_id : status.client_id,
				admin_group:
					typeof stored.admin_group === 'string' ? stored.admin_group : status.admin_group,
				groups_claim:
					typeof stored.groups_claim === 'string' ? stored.groups_claim : status.groups_claim,
				token_skew_seconds:
					typeof stored.token_skew_seconds === 'number'
						? stored.token_skew_seconds
						: status.token_skew_seconds,
				client_secret: '',
				clear_secret: false,
				has_client_secret: status.has_client_secret,
				callback_path: status.callback_path,
			};
			loaded = true;
		} catch (cause) {
			loadFailure = failureOf(cause);
			loaded = false;
		}
	}

	async function save(): Promise<void> {
		if (!isAdmin) return;
		saveBusy = true;
		saveFailure = null;
		try {
			await patchConfigSection('control_api_settings', {
				oidc: {
					enabled: form.enabled,
					issuer: form.issuer.trim(),
					client_id: form.client_id.trim(),
					admin_group: form.admin_group.trim() || 'dnscraft-admin',
					groups_claim: form.groups_claim.trim() || 'groups',
					token_skew_seconds: form.token_skew_seconds,
				},
			});
			if (form.clear_secret) {
				await putOidcClientSecret(null);
			} else if (form.client_secret.trim() !== '') {
				await putOidcClientSecret(form.client_secret.trim());
			}
			announce(m.settings_oidc_saved());
			await load();
		} catch (cause) {
			saveFailure = failureOf(cause);
		} finally {
			saveBusy = false;
		}
	}
</script>

{#if !isAdmin}
	<GroupedList header={m.settings_group_oidc()}>
		<GroupedRow label={m.settings_oidc_viewer()} />
	</GroupedList>
{:else if loadFailure}
	<GroupedList header={m.settings_group_oidc()}>
		<div class="notice">
			<ErrorNotice code={loadFailure.code} params={loadFailure.params} onretry={load} />
		</div>
	</GroupedList>
{:else if loaded}
	<GroupedList header={m.settings_group_oidc()}>
		<GroupedRow label={m.settings_oidc_enabled()} detail={m.settings_oidc_enabled_detail()}>
			{#snippet trailing()}
				<Switch bind:checked={form.enabled} aria-label={m.settings_oidc_enabled()} />
			{/snippet}
		</GroupedRow>
		<GroupedRow label={m.settings_oidc_issuer()}>
			{#snippet trailing()}
				<input
					class="field wide"
					type="url"
					bind:value={form.issuer}
					placeholder={m.settings_oidc_issuer_placeholder()}
					autocomplete="off"
					spellcheck="false"
					aria-label={m.settings_oidc_issuer()}
				/>
			{/snippet}
		</GroupedRow>
		<GroupedRow label={m.settings_oidc_client_id()}>
			{#snippet trailing()}
				<input
					class="field"
					bind:value={form.client_id}
					placeholder="dnscraft"
					autocomplete="off"
					spellcheck="false"
					aria-label={m.settings_oidc_client_id()}
				/>
			{/snippet}
		</GroupedRow>
		<GroupedRow
			label={m.settings_oidc_client_secret()}
			detail={form.has_client_secret
				? m.settings_oidc_client_secret_set()
				: m.settings_oidc_client_secret_detail()}
		>
			{#snippet trailing()}
				<input
					class="field"
					type="password"
					bind:value={form.client_secret}
					placeholder={form.has_client_secret
						? m.settings_oidc_client_secret_set()
						: m.settings_oidc_client_secret_detail()}
					autocomplete="new-password"
					aria-label={m.settings_oidc_client_secret()}
				/>
			{/snippet}
		</GroupedRow>
		{#if form.has_client_secret}
			<label class="clear">
				<input type="checkbox" bind:checked={form.clear_secret} />
				{m.settings_oidc_client_secret_clear()}
			</label>
		{/if}
		<GroupedRow label={m.settings_oidc_admin_group()}>
			{#snippet trailing()}
				<input
					class="field"
					bind:value={form.admin_group}
					placeholder="dnscraft-admin"
					autocomplete="off"
					spellcheck="false"
					aria-label={m.settings_oidc_admin_group()}
				/>
			{/snippet}
		</GroupedRow>
		<GroupedRow label={m.settings_oidc_groups_claim()}>
			{#snippet trailing()}
				<input
					class="field"
					bind:value={form.groups_claim}
					placeholder="groups"
					autocomplete="off"
					spellcheck="false"
					aria-label={m.settings_oidc_groups_claim()}
				/>
			{/snippet}
		</GroupedRow>
		<GroupedRow label={m.settings_oidc_token_skew()}>
			{#snippet trailing()}
				<input
					class="field narrow"
					type="number"
					min="5"
					max="300"
					bind:value={form.token_skew_seconds}
					aria-label={m.settings_oidc_token_skew()}
				/>
			{/snippet}
		</GroupedRow>
		<GroupedRow
			label={m.settings_oidc_callback()}
			detail={form.callback_path}
			detailMono
		/>
		<GroupedRow label={m.settings_oidc_authentik_hint()} />
		<div class="actions">
			<Button variant="primary" disabled={saveBusy} onclick={() => void save()}>
				{m.action_save()}
			</Button>
		</div>
		{#if saveFailure}
			<div class="notice">
				<ErrorNotice code={saveFailure.code} params={saveFailure.params} />
			</div>
		{/if}
	</GroupedList>
{/if}

<style>
	.field {
		min-height: 2.75rem;
		padding: 0.375rem 0.5rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-control);
		background: var(--surface);
		font: inherit;
	}

	.field.wide {
		min-width: min(22rem, 70vw);
	}

	.field.narrow {
		width: 5rem;
	}

	.clear {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0 1rem 0.75rem;
		font-size: 0.875rem;
		color: var(--label-2);
	}

	.actions {
		padding: 0.5rem 1rem 1rem;
	}

	.notice {
		padding: 0 1rem 0.75rem;
	}
</style>
