<script lang="ts">
	import { onMount } from 'svelte';
	import Banner from '$lib/components/Banner.svelte';
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import Segmented from '$lib/components/Segmented.svelte';
	import Sheet from '$lib/components/Sheet.svelte';
	import Switch from '$lib/components/Switch.svelte';
	import { listClusterNodes } from '$lib/api/cluster';
	import { getUnifiStatus, putUnifiApiKey, syncClients } from '$lib/api/clients';
	import { getConfig } from '$lib/api/config';
	import { getStatus } from '$lib/api/stats';
	import { failureOf } from '$lib/api/result';
	import { announce } from '$lib/live.svelte';
	import { patchConfigSection } from '$lib/settings/config-patch';
	import {
		DEFAULT_PROFILE,
		DEFAULT_UNIFI_FORM,
		clientsPatchFromForm,
		formFromClients,
		isSelfSyncOwner,
		selectedProfile,
		syncOwnerLabel,
		type ClientsUnifiForm,
		type LocalDomainMode,
		type UnifiProfileForm,
		type UnifiTlsChoice,
	} from '$lib/settings/unifi';
	import { m } from '$lib/paraglide/messages';

	interface Props {
		isAdmin: boolean;
	}

	let { isAdmin }: Props = $props();

	const tlsOptions: { value: UnifiTlsChoice; label: string }[] = [
		{ value: 'secure', label: m.settings_unifi_tls_secure() },
		{ value: 'pin', label: m.settings_unifi_tls_pin() },
		{ value: 'ca_file', label: m.settings_unifi_tls_ca() },
		{ value: 'insecure', label: m.settings_unifi_tls_insecure() },
	];

	const domainModeOptions: { value: LocalDomainMode; label: string }[] = [
		{ value: 'unifi_then_config', label: m.settings_unifi_domain_mode_unifi() },
		{ value: 'config', label: m.settings_unifi_domain_mode_config() },
	];

	let form = $state<ClientsUnifiForm>({
		...DEFAULT_UNIFI_FORM,
		profiles: [{ ...DEFAULT_PROFILE }],
	});
	let selfNodeId = $state('local');
	let nodeIds = $state<string[]>(['local']);
	let loaded = $state(false);
	let loadFailure = $state<{ code: string; params: Record<string, unknown> } | null>(null);
	let saveBusy = $state(false);
	let saveFailure = $state<{ code: string; params: Record<string, unknown> } | null>(null);
	let syncBusy = $state(false);
	let syncNote = $state<string | null>(null);
	let insecureConfirmOpen = $state(false);
	let pendingTls = $state<UnifiTlsChoice | null>(null);
	let tlsUiKey = $state(0);

	const profile = $derived(selectedProfile(form));
	const canSync = $derived(isSelfSyncOwner(form, selfNodeId) && profile.enabled);
	const remoteOwner = $derived(syncOwnerLabel(form, selfNodeId));

	onMount(() => {
		if (isAdmin) void load();
	});

	async function resolveSelfNode(): Promise<{ self: string; nodes: string[] }> {
		try {
			const status = await getStatus();
			const cluster = (status as { cluster?: { role?: string } }).cluster;
			if (!cluster?.role) {
				return { self: 'local', nodes: ['local'] };
			}
			const nodes = await listClusterNodes().catch(() => []);
			const ids = nodes.map((n) => n.node_id);
			if (cluster.role === 'master') {
				const master = nodes.find((n) => n.role === 'master')?.node_id ?? ids[0] ?? 'local';
				return { self: master, nodes: ids.length > 0 ? ids : [master] };
			}
			// Sub-node: node list may be empty; keep sync_owner labels from profiles.
			return { self: '', nodes: ids.length > 0 ? ids : ['local'] };
		} catch {
			return { self: 'local', nodes: ['local'] };
		}
	}

	async function load(): Promise<void> {
		loadFailure = null;
		try {
			const [{ self, nodes }, snapshot, unifi] = await Promise.all([
				resolveSelfNode(),
				getConfig(),
				getUnifiStatus().catch(() => ({ profiles: [], bindings: {} })),
			]);
			selfNodeId = self || 'local';
			nodeIds = nodes.includes('local') ? nodes : ['local', ...nodes];
			form = formFromClients(snapshot.config?.clients, unifi);
			loaded = true;
		} catch (cause) {
			loadFailure = failureOf(cause);
			loaded = false;
		}
	}

	function updateProfile(patch: Partial<UnifiProfileForm>): void {
		const id = form.selected_profile_id;
		form = {
			...form,
			profiles: form.profiles.map((row) => (row.id === id ? { ...row, ...patch } : row)),
		};
	}

	function onTlsChange(next: UnifiTlsChoice): void {
		if (next === 'insecure' && profile.tls !== 'insecure') {
			pendingTls = next;
			insecureConfirmOpen = true;
			return;
		}
		updateProfile({ tls: next });
	}

	function acceptInsecure(): void {
		if (pendingTls) updateProfile({ tls: pendingTls });
		pendingTls = null;
		insecureConfirmOpen = false;
	}

	function cancelInsecure(): void {
		pendingTls = null;
		insecureConfirmOpen = false;
		tlsUiKey += 1;
	}

	function addProfile(): void {
		const id = `profile-${form.profiles.length + 1}`;
		const next: UnifiProfileForm = {
			...DEFAULT_PROFILE,
			id,
			sync_owner: selfNodeId || 'local',
		};
		form = {
			...form,
			profiles: [...form.profiles, next],
			selected_profile_id: id,
		};
	}

	function removeProfile(): void {
		if (form.profiles.length <= 1) return;
		const remaining = form.profiles.filter((p) => p.id !== form.selected_profile_id);
		const bindings = { ...form.bindings };
		for (const [node, profileId] of Object.entries(bindings)) {
			if (profileId === form.selected_profile_id) delete bindings[node];
		}
		form = {
			...form,
			profiles: remaining,
			bindings,
			selected_profile_id: remaining[0]?.id ?? 'default',
		};
	}

	function setBinding(nodeId: string, profileId: string): void {
		const bindings = { ...form.bindings };
		if (!profileId) delete bindings[nodeId];
		else bindings[nodeId] = profileId;
		form = { ...form, bindings };
	}

	async function save(): Promise<void> {
		if (!isAdmin) return;
		saveBusy = true;
		saveFailure = null;
		try {
			await patchConfigSection('clients', clientsPatchFromForm(form));
			for (const row of form.profiles) {
				if (row.clear_api_key) {
					await putUnifiApiKey(row.id, null);
				} else if (row.api_key.trim() !== '') {
					await putUnifiApiKey(row.id, row.api_key.trim());
				}
			}
			announce(m.settings_unifi_saved());
			await load();
		} catch (cause) {
			saveFailure = failureOf(cause);
		} finally {
			saveBusy = false;
		}
	}

	async function syncNow(): Promise<void> {
		if (!isAdmin || !canSync) return;
		syncBusy = true;
		syncNote = null;
		saveFailure = null;
		try {
			const summary = await syncClients();
			syncNote = m.clients_sync_ok({
				count: summary.client_count,
				conflicts: summary.ip_conflicts,
			});
			announce(syncNote);
		} catch (cause) {
			saveFailure = failureOf(cause);
		} finally {
			syncBusy = false;
		}
	}
</script>

{#if !isAdmin}
	<GroupedList header={m.settings_group_unifi()}>
		<GroupedRow label={m.settings_unifi_viewer()} />
	</GroupedList>
{:else}
	{#if profile.tls === 'insecure'}
		<Banner title={m.settings_unifi_insecure_banner()}>
			<p>{m.settings_unifi_insecure_body()}</p>
		</Banner>
	{/if}

	<GroupedList header={m.settings_group_unifi()} footer={loaded ? m.settings_unifi_footnote() : undefined}>
		{#if loadFailure}
			<div class="notice">
				<ErrorNotice code={loadFailure.code} params={loadFailure.params} onretry={() => void load()} />
			</div>
		{:else if !loaded}
			<GroupedRow label={m.state_loading()} />
		{:else}
			<div class="fields">
				<label class="field-label" for="unifi-profile">{m.settings_unifi_profile()}</label>
				<div class="profile-row">
					<select
						id="unifi-profile"
						class="field"
						bind:value={form.selected_profile_id}
						aria-label={m.settings_unifi_profile()}
					>
						{#each form.profiles as row (row.id)}
							<option value={row.id}>{row.id}</option>
						{/each}
					</select>
					<Button onclick={addProfile}>{m.settings_unifi_profile_add()}</Button>
					{#if form.profiles.length > 1}
						<Button onclick={removeProfile}>{m.settings_unifi_profile_remove()}</Button>
					{/if}
				</div>

				<label class="field-label" for="unifi-profile-id">{m.settings_unifi_profile_id()}</label>
				<input
					id="unifi-profile-id"
					class="field mono"
					type="text"
					autocomplete="off"
					spellcheck="false"
					value={profile.id}
					oninput={(event) => {
						const next = (event.currentTarget as HTMLInputElement).value.trim() || profile.id;
						const prev = profile.id;
						const profiles = form.profiles.map((row) =>
							row.id === prev ? { ...row, id: next } : row,
						);
						const bindings = { ...form.bindings };
						for (const [node, bound] of Object.entries(bindings)) {
							if (bound === prev) bindings[node] = next;
						}
						form = { ...form, profiles, bindings, selected_profile_id: next };
					}}
				/>

				<GroupedRow label={m.settings_unifi_enabled()} detail={m.settings_unifi_enabled_detail()}>
					{#snippet trailing()}
						{#each form.profiles as row (row.id)}
							{#if row.id === form.selected_profile_id}
								<Switch bind:checked={row.enabled} aria-label={m.settings_unifi_enabled()} />
							{/if}
						{/each}
					{/snippet}
				</GroupedRow>

				<label class="field-label" for="unifi-url">{m.settings_unifi_gateway()}</label>
				<input
					id="unifi-url"
					class="field mono"
					type="url"
					autocomplete="off"
					spellcheck="false"
					placeholder="https://192.0.2.1"
					value={profile.base_url}
					oninput={(event) =>
						updateProfile({ base_url: (event.currentTarget as HTMLInputElement).value })}
				/>

				<label class="field-label" for="unifi-site">{m.settings_unifi_site()}</label>
				<input
					id="unifi-site"
					class="field mono"
					type="text"
					autocomplete="off"
					spellcheck="false"
					placeholder={m.settings_unifi_site_placeholder()}
					value={profile.site_id}
					oninput={(event) =>
						updateProfile({ site_id: (event.currentTarget as HTMLInputElement).value })}
				/>

				<label class="field-label" for="unifi-owner">{m.settings_unifi_sync_owner()}</label>
				<select
					id="unifi-owner"
					class="field"
					value={profile.sync_owner}
					onchange={(event) =>
						updateProfile({ sync_owner: (event.currentTarget as HTMLSelectElement).value })}
				>
					{#each nodeIds as nodeId (nodeId)}
						<option value={nodeId}>{nodeId}</option>
					{/each}
					{#if !nodeIds.includes(profile.sync_owner)}
						<option value={profile.sync_owner}>{profile.sync_owner}</option>
					{/if}
				</select>

				<label class="field-label" for="unifi-key">{m.settings_unifi_api_key()}</label>
				<input
					id="unifi-key"
					class="field mono"
					type="password"
					autocomplete="new-password"
					spellcheck="false"
					placeholder={profile.has_api_key
						? m.settings_unifi_api_key_set()
						: m.settings_unifi_api_key_detail()}
					value={profile.api_key}
					oninput={(event) =>
						updateProfile({
							api_key: (event.currentTarget as HTMLInputElement).value,
							clear_api_key: false,
						})}
				/>
				{#if profile.has_api_key}
					<label class="clear-key">
						<input
							type="checkbox"
							checked={profile.clear_api_key}
							onchange={(event) =>
								updateProfile({
									clear_api_key: (event.currentTarget as HTMLInputElement).checked,
									api_key: '',
								})}
						/>
						{m.settings_unifi_api_key_clear()}
					</label>
				{/if}

				<p class="field-label" id="unifi-tls-label">{m.settings_unifi_tls()}</p>
				<div class="segment">
					{#key tlsUiKey}
						<Segmented
							options={tlsOptions}
							value={profile.tls}
							label={m.settings_unifi_tls()}
							onchange={onTlsChange}
						/>
					{/key}
				</div>

				{#if profile.tls === 'pin'}
					<label class="field-label" for="unifi-pin">{m.settings_unifi_pin_label()}</label>
					<input
						id="unifi-pin"
						class="field mono"
						type="text"
						autocomplete="off"
						spellcheck="false"
						placeholder="sha256:…"
						value={profile.tls_pin_sha256}
						oninput={(event) =>
							updateProfile({
								tls_pin_sha256: (event.currentTarget as HTMLInputElement).value,
							})}
					/>
				{/if}

				{#if profile.tls === 'ca_file'}
					<label class="field-label" for="unifi-ca">{m.settings_unifi_ca_label()}</label>
					<input
						id="unifi-ca"
						class="field mono"
						type="text"
						autocomplete="off"
						spellcheck="false"
						placeholder="/etc/dnscraft/unifi-ca.pem"
						value={profile.ca_file}
						oninput={(event) =>
							updateProfile({ ca_file: (event.currentTarget as HTMLInputElement).value })}
					/>
				{/if}

				<label class="field-label" for="unifi-poll">{m.settings_unifi_poll()}</label>
				<div class="poll-row">
					<input
						id="unifi-poll"
						class="field poll"
						type="number"
						min="5"
						max="3600"
						value={profile.poll_seconds}
						oninput={(event) =>
							updateProfile({
								poll_seconds: Number((event.currentTarget as HTMLInputElement).value) || 60,
							})}
						aria-describedby="unifi-poll-unit"
					/>
					<span id="unifi-poll-unit" class="unit">{m.settings_unifi_poll_unit()}</span>
				</div>

				<GroupedRow label={m.settings_unifi_classic()}>
					{#snippet trailing()}
						{#each form.profiles as row (row.id)}
							{#if row.id === form.selected_profile_id}
								<Switch
									bind:checked={row.classic_clients}
									aria-label={m.settings_unifi_classic()}
								/>
							{/if}
						{/each}
					{/snippet}
				</GroupedRow>

				<label class="field-label" for="unifi-domain">{m.settings_unifi_local_domain()}</label>
				<input
					id="unifi-domain"
					class="field mono"
					type="text"
					autocomplete="off"
					spellcheck="false"
					bind:value={form.local_domain}
				/>

				<p class="field-label">{m.settings_unifi_domain_mode()}</p>
				<div class="segment">
					<Segmented
						options={domainModeOptions}
						bind:value={form.local_domain_mode}
						label={m.settings_unifi_domain_mode()}
					/>
				</div>

				<p class="field-label">{m.settings_unifi_bindings()}</p>
				{#each nodeIds as nodeId (nodeId)}
					<div class="binding-row">
						<span class="binding-node mono">{nodeId}</span>
						<select
							class="field binding-select"
							aria-label={m.settings_unifi_binding_for({ node: nodeId })}
							value={form.bindings[nodeId] ?? ''}
							onchange={(event) =>
								setBinding(nodeId, (event.currentTarget as HTMLSelectElement).value)}
						>
							<option value="">{m.settings_unifi_binding_none()}</option>
							{#each form.profiles as row (row.id)}
								<option value={row.id}>{row.id}</option>
							{/each}
						</select>
					</div>
				{/each}

				{#if saveFailure}
					<div class="notice">
						<ErrorNotice code={saveFailure.code} params={saveFailure.params} />
					</div>
				{/if}
				{#if syncNote}
					<p class="note">{syncNote}</p>
				{/if}
				{#if remoteOwner}
					<p class="note">{m.settings_unifi_sync_remote({ owner: remoteOwner })}</p>
				{/if}

				<div class="actions">
					<Button variant="primary" disabled={saveBusy} onclick={() => void save()}
						>{m.action_save()}</Button
					>
					<Button disabled={syncBusy || !canSync} onclick={() => void syncNow()}
						>{m.clients_sync()}</Button
					>
				</div>
			</div>
		{/if}
	</GroupedList>
{/if}

{#if insecureConfirmOpen}
	<Sheet open={true} title={m.settings_unifi_insecure_confirm_title()} onclose={cancelInsecure}>
		<p class="body">{m.settings_unifi_insecure_body()}</p>
		<div class="sheet-actions">
			<Button onclick={cancelInsecure}>{m.action_cancel()}</Button>
			<Button variant="danger" onclick={acceptInsecure}
				>{m.settings_unifi_insecure_confirm()}</Button
			>
		</div>
	</Sheet>
{/if}

<style>
	.fields {
		padding: 0.25rem 1rem 1rem;
	}

	.field-label {
		display: block;
		margin: 0.75rem 0 0.375rem;
		font-size: 0.84375rem;
		color: var(--label-2);
	}

	.field {
		display: block;
		box-sizing: border-box;
		width: 100%;
		min-height: 2.75rem;
		padding: 0.5rem 0.75rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-control);
		background: var(--surface);
		color: var(--label);
		font: inherit;
	}

	.field.mono,
	.binding-node {
		font-family: var(--font-mono, ui-monospace, SFMono-Regular, Menlo, monospace);
	}

	.profile-row {
		display: flex;
		flex-wrap: wrap;
		gap: 0.5rem;
		align-items: center;
	}

	.profile-row .field {
		flex: 1 1 10rem;
		margin: 0;
	}

	.poll-row {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}

	.field.poll {
		width: 6rem;
		margin: 0;
	}

	.unit {
		font-size: 0.84375rem;
		color: var(--label-2);
	}

	.segment {
		margin-bottom: 0.25rem;
	}

	.binding-row {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		margin-bottom: 0.5rem;
	}

	.binding-node {
		min-width: 5rem;
		font-size: 0.84375rem;
		color: var(--label-2);
	}

	.binding-select {
		flex: 1;
		margin: 0;
	}

	.clear-key {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		margin-top: 0.5rem;
		font-size: 0.84375rem;
		color: var(--label-2);
	}

	.actions {
		display: flex;
		flex-wrap: wrap;
		gap: 0.5rem;
		margin-top: 1rem;
	}

	.notice {
		padding: 0.5rem 0;
	}

	.note {
		margin: 0.75rem 0 0;
		font-size: 0.84375rem;
		color: var(--label-2);
	}

	.body {
		margin: 0;
		color: var(--label-2);
	}

	.sheet-actions {
		display: flex;
		justify-content: flex-end;
		flex-wrap: wrap;
		gap: 0.625rem;
		margin-top: 1.125rem;
	}
</style>
