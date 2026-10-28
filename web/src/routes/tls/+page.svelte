<script lang="ts">
	import { onMount } from 'svelte';
	import Banner from '$lib/components/Banner.svelte';
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import Sheet from '$lib/components/Sheet.svelte';
	import UnavailableNotice from '$lib/components/UnavailableNotice.svelte';
	import {
		getTlsConfig,
		getTlsStatus,
		preflightTls,
		renewTls,
		revokeTls,
		rotateTls,
		saveTlsConfig,
		triggerDyndns,
		uploadCertificate,
		type TlsStatus,
	} from '$lib/api/tls';
	import { getConfig, ifMatchFor } from '$lib/api/config';
	import { failureOf, settle, type Result } from '$lib/api/result';
	import { auth } from '$lib/auth/state.svelte';
	import { formatFingerprint } from '$lib/format';
	import { m } from '$lib/paraglide/messages';

	const isAdmin = $derived(auth.role === 'admin');

	let status = $state<Result<TlsStatus>>({ kind: 'loading' });
	let configVersion = $state<number | null>(null);
	let tlsConfig = $state<Record<string, unknown>>({});
	let busy = $state(false);
	let failure = $state<{ code: string; params: Record<string, unknown> } | null>(null);
	let uploadOpen = $state(false);
	let revokeOpen = $state(false);
	let revokeReason = $state('');
	let formDomain = $state('');
	let formDyndnsHost = $state('');
	let certPem = $state('');
	let keyPem = $state('');

	const bootstrap = $derived.by(() => {
		if (status.kind !== 'ok') return null;
		if (status.data.mode !== 'self_signed' && status.data.self_signed !== true) return null;
		const fp = status.data.fingerprint_sha256 ?? '';
		return {
			fingerprint: fp === '' ? '' : formatFingerprint(fp),
			names: (status.data.identifiers ?? []).join(', ') || '—',
		};
	});

	const modeLabel = $derived.by(() => {
		if (status.kind !== 'ok' || !status.data.mode) return '—';
		const mode = status.data.mode;
		if (mode === 'acme') return m.tls_mode_acme();
		if (mode === 'manual') return m.tls_mode_manual();
		return m.tls_mode_self_signed();
	});

	async function load(): Promise<void> {
		const [st, cfg] = await Promise.all([settle(getTlsStatus()), getConfig().catch(() => null)]);
		status = st;
		configVersion = cfg?.version ?? null;
		try {
			const tls = await getTlsConfig();
			tlsConfig = tls.tls;
			formDomain = String(tls.tls.public_domain ?? '');
			const dyndns = tls.tls.dyndns as Record<string, unknown> | undefined;
			formDyndnsHost = String(dyndns?.hostname ?? '');
		} catch {
			/* status may still be enough for viewers */
		}
	}

	async function saveDyndnsForm(): Promise<void> {
		busy = true;
		failure = null;
		const next = {
			...tlsConfig,
			public_domain: formDomain.trim(),
			dyndns: {
				...(typeof tlsConfig.dyndns === 'object' && tlsConfig.dyndns !== null
					? tlsConfig.dyndns
					: {}),
				enabled: true,
				hostname: formDyndnsHost.trim(),
				proxied: false,
			},
		};
		try {
			const saved = await saveTlsConfig(next, { ifMatch: ifMatchFor(configVersion) });
			configVersion = saved.version;
			tlsConfig = saved.tls;
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	async function runAction(task: () => Promise<unknown>): Promise<void> {
		busy = true;
		failure = null;
		try {
			await task();
			await load();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	async function submitUpload(): Promise<void> {
		await runAction(() => uploadCertificate({ cert_pem: certPem, key_pem: keyPem }));
		uploadOpen = false;
		certPem = '';
		keyPem = '';
	}

	async function submitRevoke(): Promise<void> {
		await runAction(() => revokeTls(revokeReason.trim() || 'unspecified'));
		revokeOpen = false;
		revokeReason = '';
	}

	onMount(() => {
		void load();
	});
</script>

<p class="lead">{m.tls_lead()}</p>

{#if bootstrap}
	<div class="banner-wrap">
		<Banner title={m.dashboard_selfsigned_title()}>
			<p>{m.dashboard_selfsigned_body({ names: bootstrap.names })}</p>
			{#if bootstrap.fingerprint}
				<p class="mono fp">{bootstrap.fingerprint}</p>
			{/if}
		</Banner>
	</div>
{/if}

{#if failure}
	<div class="notice">
		<ErrorNotice code={failure.code} params={failure.params} />
	</div>
{/if}

{#if status.kind === 'loading'}
	<p class="state">{m.state_loading()}</p>
{:else if status.kind === 'unavailable'}
	<UnavailableNotice />
{:else if status.kind === 'error'}
	<ErrorNotice code={status.code} params={status.params} />
{:else}
	<GroupedList header={m.tls_status_group()}>
		<GroupedRow label={m.dashboard_tls_label()} detail={modeLabel} />
		{#if status.data.fingerprint_sha256}
			<GroupedRow
				label={m.tls_fingerprint_label()}
				detail={formatFingerprint(status.data.fingerprint_sha256)}
				detailMono
			/>
		{/if}
		{#if status.data.not_after}
			<GroupedRow label={m.tls_expires_label()} detail={status.data.not_after} detailMono />
		{/if}
	</GroupedList>

	{#if isAdmin}
		<GroupedList header={m.tls_acme_dyndns_group()}>
			<GroupedRow label={m.tls_public_domain_label()}>
				{#snippet trailing()}
					<input
						class="inline field mono"
						bind:value={formDomain}
						aria-label={m.tls_public_domain_label()}
					/>
				{/snippet}
			</GroupedRow>
			<GroupedRow label={m.tls_dyndns_host_label()}>
				{#snippet trailing()}
					<input
						class="inline field mono"
						bind:value={formDyndnsHost}
						aria-label={m.tls_dyndns_host_label()}
					/>
				{/snippet}
			</GroupedRow>
			<GroupedRow label={m.tls_save_config()}>
				{#snippet trailing()}
					<Button disabled={busy} onclick={() => void saveDyndnsForm()}>{m.action_save()}</Button>
				{/snippet}
			</GroupedRow>
		</GroupedList>

		<GroupedList header={m.tls_actions_group()}>
			<GroupedRow label={m.tls_action_renew()}>
				{#snippet trailing()}
					<Button disabled={busy} onclick={() => void runAction(renewTls)}>{m.tls_run()}</Button>
				{/snippet}
			</GroupedRow>
			<GroupedRow label={m.tls_action_rotate()}>
				{#snippet trailing()}
					<Button disabled={busy} onclick={() => void runAction(rotateTls)}>{m.tls_run()}</Button>
				{/snippet}
			</GroupedRow>
			<GroupedRow label={m.tls_action_preflight()}>
				{#snippet trailing()}
					<Button disabled={busy} onclick={() => void runAction(preflightTls)}>{m.tls_run()}</Button
					>
				{/snippet}
			</GroupedRow>
			<GroupedRow label={m.tls_action_dyndns()}>
				{#snippet trailing()}
					<Button disabled={busy} onclick={() => void runAction(triggerDyndns)}
						>{m.tls_run()}</Button
					>
				{/snippet}
			</GroupedRow>
			<GroupedRow label={m.tls_action_upload()}>
				{#snippet trailing()}
					<Button disabled={busy} onclick={() => (uploadOpen = true)}>{m.tls_open()}</Button>
				{/snippet}
			</GroupedRow>
			<GroupedRow label={m.tls_action_revoke()}>
				{#snippet trailing()}
					<Button variant="danger" disabled={busy} onclick={() => (revokeOpen = true)}>
						{m.tls_open()}
					</Button>
				{/snippet}
			</GroupedRow>
		</GroupedList>
	{/if}

	<p class="footnote">{m.tls_private_key_never()}</p>
{/if}

{#if uploadOpen}
	<Sheet open={true} title={m.tls_upload_title()} onclose={() => (uploadOpen = false)}>
		<p class="hint">{m.tls_upload_hint()}</p>
		<label class="field-label" for="cert-pem">{m.tls_cert_pem_label()}</label>
		<textarea id="cert-pem" class="area mono" bind:value={certPem} rows={5}></textarea>
		<label class="field-label" for="key-pem">{m.tls_key_pem_label()}</label>
		<textarea id="key-pem" class="area mono" bind:value={keyPem} rows={5}></textarea>
		<div class="actions">
			<Button onclick={() => (uploadOpen = false)}>{m.action_cancel()}</Button>
			<Button variant="primary" disabled={busy} onclick={() => void submitUpload()}>
				{m.action_save()}
			</Button>
		</div>
	</Sheet>
{/if}

{#if revokeOpen}
	<Sheet open={true} title={m.tls_revoke_title()} onclose={() => (revokeOpen = false)}>
		<p class="hint">{m.tls_revoke_body()}</p>
		<label class="field-label" for="revoke-reason">{m.tls_revoke_reason_label()}</label>
		<input id="revoke-reason" class="field" bind:value={revokeReason} />
		<div class="actions">
			<Button onclick={() => (revokeOpen = false)}>{m.action_cancel()}</Button>
			<Button variant="danger" disabled={busy} onclick={() => void submitRevoke()}>
				{m.tls_revoke_confirm()}
			</Button>
		</div>
	</Sheet>
{/if}

<style>
	.lead {
		margin: 0 0 1rem;
		color: var(--label-2);
	}

	.banner-wrap {
		margin-bottom: 1rem;
	}

	.fp {
		margin: 0.5rem 0 0;
		font-size: 0.8125rem;
		overflow-wrap: anywhere;
	}

	.state,
	.footnote,
	.hint {
		margin: 0.75rem 0 0;
		color: var(--label-2);
		font-size: 0.84375rem;
	}

	.notice {
		margin-bottom: 0.75rem;
	}

	.inline.field {
		width: min(100%, 16rem);
		min-height: 2.75rem;
		padding: 0.375rem 0.5rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-control);
		background: var(--surface);
	}

	.field-label {
		display: block;
		margin: 0 0 0.375rem;
		font-size: 0.84375rem;
		color: var(--label-2);
	}

	.field {
		width: 100%;
		min-height: 2.75rem;
		margin-bottom: 1rem;
		padding: 0.5rem 0.75rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-control);
		background: var(--surface);
	}

	.area {
		width: 100%;
		margin-bottom: 1rem;
		padding: 0.5rem 0.75rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-control);
		background: var(--surface);
		font-size: 0.8125rem;
	}

	.actions {
		display: flex;
		flex-wrap: wrap;
		justify-content: flex-end;
		gap: 0.5rem;
		margin-top: 1rem;
	}
</style>
