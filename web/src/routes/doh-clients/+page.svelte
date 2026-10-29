<script lang="ts">
	import { onMount } from 'svelte';
	import { resolve } from '$app/paths';
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import Icon from '$lib/components/Icon.svelte';
	import ResultNotice from '$lib/components/ResultNotice.svelte';
	import Segmented from '$lib/components/Segmented.svelte';
	import Sheet from '$lib/components/Sheet.svelte';
	import UnavailableNotice from '$lib/components/UnavailableNotice.svelte';
	import { listClients, type DirectoryClient } from '$lib/api/clients';
	import { listListeners } from '$lib/api/listeners';
	import { listQueryLog, type QueryRecord } from '$lib/api/query-log';
	import {
		createClientId,
		listClientIds,
		listRecords,
		listViews,
		revokeClientId,
		saveRecord,
		updateClientId,
		type ClientIdEntry,
		type PolicyRecord,
		type PolicyView,
	} from '$lib/api/policy';
	import { listClusterNodes } from '$lib/api/cluster';
	import { getTlsConfig } from '$lib/api/tls';
	import { failureOf, settle, type Result } from '$lib/api/result';
	import { auth } from '$lib/auth/state.svelte';
	import { buildMobileConfig, dohUrl, dotHostname } from '$lib/doh/mobileconfig';
	import type { MobileConfigError } from '$lib/doh/mobileconfig';
	import {
		isIpLiteral,
		isLanAddress,
		nameHasHomeAddress,
		isValidClientId,
		labelTaken,
		LABEL_MAX,
		randomSuffix,
		splitAddresses,
		suggestClientId,
	} from '$lib/doh/client-id';
	import { getLocale } from '$lib/i18n/locale';
	import { announce } from '$lib/live.svelte';
	import { m } from '$lib/paraglide/messages';
	import { formatDateTime } from '$lib/format';
	import { displayText } from '$lib/safe-text';

	type Failure = { code: string; params: Record<string, unknown> };
	type Seen =
		| { kind: 'never' }
		| {
				kind: 'seen';
				time: string;
				protocol: string;
				cause: QueryRecord['selection']['cause'];
				viewId: string;
				sourceIp: string;
		  };
	type Check = 'ok' | 'warn' | 'unknown';
	type SheetKind = 'none' | 'create' | 'edit' | 'profile' | 'record';
	type Address =
		| { ok: true; url: string; dot: string }
		| { ok: false; reason: 'no_domain' | 'self_signed' | 'invalid' };

	const isAdmin = $derived(auth.role === 'admin');
	let result = $state<Result<ClientIdEntry[]>>({ kind: 'loading' });
	let publicDomain = $state<string | null>(null);
	let tlsMode = $state<string | null>(null);
	/** Null for viewers or when the directory fails: device names then show a generic text. */
	let clients = $state<DirectoryClient[] | null>(null);
	let listenerProtocols = $state<string[] | null>(null);
	let records = $state<PolicyRecord[] | null>(null);
	let views = $state<PolicyView[] | null>(null);
	let seen = $state<Record<string, Seen>>({});

	let sheet = $state<SheetKind>('none');
	let busy = $state(false);
	let failure = $state<Failure | null>(null);
	let editing = $state<ClientIdEntry | null>(null);
	let confirmDelete = $state(false);

	let formLabel = $state('');
	let formSuffix = $state(randomSuffix());
	let formId = $state('');
	let idTouched = $state(false);
	let labelSubmitted = $state(false);
	let formDevice = $state('');
	let formView = $state('');

	let profileSsid = $state('');
	let profileProtocol = $state<'https' | 'tls'>('https');
	let profileServers = $state('');
	let nodeHosts = $state<{ hostname: string; name: string }[]>([]);
	let profileHosts = $state<string[]>([]);
	let profileError = $state<MobileConfigError | null>(null);

	let recordView = $state('');
	let recordLan = $state('');
	let recordPublic = $state('');

	const rows = $derived(result.kind === 'ok' ? result.data : []);
	const protocolOptions = $derived([
		{ value: 'https' as const, label: m.doh_protocol_https() },
		{ value: 'tls' as const, label: m.doh_protocol_tls() },
	]);

	const labelError = $derived.by<'required' | 'taken' | 'long' | null>(() => {
		const label = formLabel.trim();
		if (label === '' && labelSubmitted) return 'required';
		if (Array.from(label).length > LABEL_MAX) return 'long';
		if (labelTaken(label, rows, editing?.id ?? null)) return 'taken';
		return null;
	});
	const idValid = $derived(sheet !== 'create' || isValidClientId(formId));
	/** The server names the field when the chosen Netzbereich is unknown; that error sits next to the select. */
	const viewRefused = $derived(failure?.params.field === 'view');
	const canSave = $derived(
		!busy &&
			labelError === null &&
			((sheet === 'create' && isValidClientId(formId)) || (sheet === 'edit' && editing !== null)),
	);
	const canSaveRecord = $derived(!busy && recordView !== '' && isIpLiteral(recordLan.trim()));

	/** Setup checks: `unknown` means the read failed, and the item is left out. */
	const checks = $derived.by(() => {
		const domain: Check = publicDomain ? 'ok' : 'warn';
		const cert: Check =
			tlsMode === 'acme' || tlsMode === 'manual'
				? 'ok'
				: tlsMode === 'self_signed'
					? 'warn'
					: 'unknown';
		const listener: Check =
			listenerProtocols === null ? 'unknown' : listenerProtocols.includes('doh') ? 'ok' : 'warn';
		const recordName = publicDomain ? `dns.${publicDomain}`.toLowerCase() : null;
		let record: Check = 'unknown';
		if (recordName && records !== null && views !== null) {
			const homeViews = new Set(
				views.filter((view) => view.is_default || view.subnets.length > 0).map((view) => view.id),
			);
			record = nameHasHomeAddress(records, recordName, homeViews) ? 'ok' : 'warn';
		}
		return { domain, cert, listener, record, recordName };
	});
	const openChecks = $derived(
		[checks.domain, checks.cert, checks.listener, checks.record].filter((state) => state === 'warn')
			.length,
	);

	async function loadList(): Promise<void> {
		result = await settle(listClientIds());
	}

	/** The public name and certificate mode come from the TLS config; a failure leaves both unset. */
	async function loadTls(): Promise<void> {
		try {
			const { tls } = await getTlsConfig();
			const domain = typeof tls.public_domain === 'string' ? tls.public_domain.trim() : '';
			publicDomain = domain === '' ? null : domain;
			tlsMode = typeof tls.mode === 'string' ? tls.mode : null;
		} catch {
			publicDomain = null;
			tlsMode = null;
		}
	}

	/** Admin-only reads for the setup check; any failure just leaves that check out. */
	async function loadSetup(): Promise<void> {
		const [listeners, recs, vws] = await Promise.all([
			settle(listListeners()),
			settle(listRecords()),
			settle(listViews()),
		]);
		listenerProtocols = listeners.kind === 'ok' ? listeners.data.map((row) => row.protocol) : null;
		records = recs.kind === 'ok' ? recs.data : null;
		views = vws.kind === 'ok' ? vws.data : null;
	}

	async function loadNodeHosts(): Promise<void> {
		try {
			nodeHosts = (await listClusterNodes())
				.filter((node) => node.hostname && !node.revoked)
				.map((node) => ({ hostname: node.hostname!, name: node.display_name || node.node_id }));
		} catch {
			nodeHosts = [];
		}
	}

	async function loadClients(): Promise<void> {
		try {
			clients = (await listClients()).clients;
		} catch {
			clients = null;
		}
	}

	function toSeen(row: QueryRecord): Seen {
		return {
			kind: 'seen',
			time: row.time,
			protocol: row.protocol,
			cause: row.selection.cause,
			viewId: row.view_id,
			sourceIp: row.source_ip,
		};
	}

	/** Newest query per Client ID. A failed read leaves that card without a last-seen line. */
	async function loadSeen(ids: string[]): Promise<void> {
		await Promise.all(
			ids.map(async (id) => {
				try {
					const page = await listQueryLog(new URLSearchParams({ client_id: id, limit: '1' }));
					const row = page.queries[0];
					seen = { ...seen, [id]: row ? toSeen(row) : { kind: 'never' } };
				} catch {
					// no last-seen line for this card
				}
			}),
		);
	}

	async function afterChange(): Promise<void> {
		await loadList();
		if (isAdmin && result.kind === 'ok') void loadSeen(result.data.map((entry) => entry.id));
	}

	function addressOf(id: string): Address {
		if (!publicDomain) return { ok: false, reason: 'no_domain' };
		if (tlsMode === 'self_signed') return { ok: false, reason: 'self_signed' };
		const url = dohUrl(publicDomain, id);
		const dot = dotHostname(publicDomain, id);
		if (!url.ok || !dot.ok) return { ok: false, reason: 'invalid' };
		return { ok: true, url: url.value, dot: dot.value };
	}

	function addressWarning(reason: 'no_domain' | 'self_signed' | 'invalid'): string {
		if (reason === 'self_signed') return m.doh_url_self_signed();
		if (reason === 'invalid') return m.doh_url_invalid();
		return m.doh_url_no_domain();
	}

	function deviceName(device: string | null): DirectoryClient | undefined {
		return device === null ? undefined : clients?.find((client) => client.id === device);
	}

	function seenText(entry: Seen & { kind: 'seen' }): string {
		const time = formatDateTime(new Date(entry.time), getLocale());
		const protocol = entry.protocol.toUpperCase();
		if (entry.cause === 'subnet' && entry.viewId !== '') {
			return m.doh_seen_subnet({ time, protocol, view: displayText(entry.viewId, 60).text });
		}
		if (entry.cause === 'client_id' && entry.viewId !== '') {
			return m.doh_seen_client_id({ time, protocol, view: displayText(entry.viewId, 60).text });
		}
		return m.doh_seen_default({ time, protocol });
	}

	/** A linked device that came from the LAN (or its known address) but got the default range. */
	function seenWarning(entry: ClientIdEntry, last: Seen & { kind: 'seen' }): boolean {
		if (entry.device === null || last.cause !== 'default') return false;
		const known = deviceName(entry.device)?.ips ?? [];
		return isLanAddress(last.sourceIp) || known.includes(last.sourceIp);
	}

	function closeSheet(): void {
		sheet = 'none';
		confirmDelete = false;
		failure = null;
	}

	function openCreate(): void {
		editing = null;
		formLabel = '';
		formSuffix = randomSuffix();
		formId = suggestClientId('', formSuffix);
		idTouched = false;
		formDevice = '';
		formView = '';
		failure = null;
		confirmDelete = false;
		labelSubmitted = false;
		sheet = 'create';
	}

	function onLabelInput(): void {
		if (!idTouched) formId = suggestClientId(formLabel, formSuffix);
	}

	function regenerateId(): void {
		formSuffix = randomSuffix();
		formId = suggestClientId(formLabel, formSuffix);
		idTouched = false;
	}

	function openEdit(entry: ClientIdEntry): void {
		editing = entry;
		formLabel = entry.label ?? '';
		formDevice = entry.device ?? '';
		formView = entry.view ?? '';
		failure = null;
		confirmDelete = false;
		labelSubmitted = false;
		sheet = 'edit';
	}

	function openProfile(entry: ClientIdEntry): void {
		editing = entry;
		profileSsid = '';
		profileProtocol = 'https';
		profileServers = '';
		profileHosts = nodeHosts.map((node) => node.hostname);
		profileError = null;
		failure = null;
		sheet = 'profile';
	}

	function openRecord(): void {
		const home = (views ?? []).filter((view) => view.is_default || view.subnets.length > 0);
		const preferred = home.find((view) => view.is_default) ?? home[0];
		recordView = preferred?.id ?? '';
		recordLan = '';
		recordPublic = '';
		failure = null;
		sheet = 'record';
	}

	async function submit(): Promise<void> {
		labelSubmitted = true;
		if (formLabel.trim() === '') return;
		busy = true;
		failure = null;
		const label = formLabel.trim();
		try {
			if (sheet === 'create') {
				await createClientId(formId, {
					...(label === '' ? {} : { label }),
					...(formDevice === '' ? {} : { device: formDevice }),
					...(formView === '' ? {} : { view: formView }),
				});
				announce(m.doh_announce_created());
			} else if (editing) {
				await updateClientId(editing.id, {
					label: label === '' ? null : label,
					device: formDevice === '' ? null : formDevice,
					view: formView === '' ? null : formView,
				});
				announce(m.doh_announce_saved());
			}
			closeSheet();
			await afterChange();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	async function removeEntry(): Promise<void> {
		if (!editing) return;
		busy = true;
		failure = null;
		try {
			await revokeClientId(editing.id);
			announce(m.doh_announce_deleted());
			closeSheet();
			await afterChange();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	async function saveRecordForDomain(): Promise<void> {
		const name = checks.recordName;
		if (!name || !publicDomain) return;
		busy = true;
		failure = null;
		try {
			const existing = records?.find(
				(row) => row.type === 'A' && row.name.replace(/\.$/, '').toLowerCase() === name,
			);
			await saveRecord({
				name: `dns.${publicDomain}`,
				type: 'A',
				ttl: existing?.ttl ?? 60,
				rdata: existing?.rdata ?? recordPublic.trim(),
				overrides: { ...(existing?.overrides ?? {}), [recordView]: recordLan.trim() },
			});
			announce(m.doh_announce_record());
			closeSheet();
			await loadSetup();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	/** Clipboard API first; a hidden textarea and execCommand when it is missing or refused. */
	function fallbackCopy(text: string): boolean {
		const area = document.createElement('textarea');
		area.value = text;
		area.setAttribute('readonly', '');
		area.style.position = 'fixed';
		area.style.opacity = '0';
		document.body.append(area);
		area.select();
		let copied = false;
		try {
			copied = document.execCommand('copy');
		} catch {
			copied = false;
		}
		area.remove();
		return copied;
	}

	async function copyText(text: string): Promise<void> {
		let copied = false;
		try {
			await globalThis.navigator.clipboard.writeText(text);
			copied = true;
		} catch {
			copied = fallbackCopy(text);
		}
		if (copied) announce(m.action_copied());
	}

	function downloadProfile(entry: ClientIdEntry): void {
		const built = buildMobileConfig({
			publicDomain: publicDomain ?? '',
			clientId: entry.id,
			label: entry.label,
			protocol: profileProtocol,
			homeSsid: profileSsid,
			serverAddresses: splitAddresses(profileServers),
			hosts: profileHosts,
		});
		if (!built.ok) {
			profileError = built.error;
			return;
		}
		profileError = null;
		const url = URL.createObjectURL(
			new Blob([built.xml], { type: 'application/x-apple-aspen-config' }),
		);
		const link = document.createElement('a');
		link.href = url;
		link.download = built.fileName;
		document.body.append(link);
		link.click();
		link.remove();
		setTimeout(() => URL.revokeObjectURL(url), 1_000);
	}

	function profileErrorText(error: MobileConfigError): string {
		if (error === 'no_public_domain') return m.doh_profile_err_no_public_domain();
		if (error === 'invalid_domain') return m.doh_profile_err_invalid_domain();
		return m.doh_profile_err_invalid_client_id();
	}

	onMount(() => {
		void loadTls();
		void loadList().then(() => {
			if (isAdmin && result.kind === 'ok') void loadSeen(result.data.map((entry) => entry.id));
		});
		if (isAdmin) {
			void loadClients();
			void loadSetup();
			void loadNodeHosts();
		}
	});
</script>

<div class="doh">
	<div class="page-head">
		<p class="lead">{m.doh_lead()}</p>
		{#if isAdmin && result.kind === 'ok'}
			<Button variant="primary" onclick={openCreate}>{m.doh_add()}</Button>
		{/if}
	</div>

	{#if isAdmin}
		<details class="setup" open={openChecks > 0}>
			<summary>
				<Icon name={openChecks > 0 ? 'alert-triangle' : 'check-circle'} size="1rem" />
				<span class="setup-title">{m.doh_setup_title()}</span>
				<span class="setup-state">
					{openChecks > 0 ? m.doh_setup_open({ count: openChecks }) : m.doh_setup_ok()}
				</span>
			</summary>
			<ul class="checks">
				<li class="check" data-state={checks.domain}>
					<Icon name={checks.domain === 'ok' ? 'check-circle' : 'alert-triangle'} size="1rem" />
					<span class="check-text">
						{checks.domain === 'ok'
							? m.doh_check_domain_ok({ domain: displayText(publicDomain, 80).text })
							: m.doh_check_domain_missing()}
					</span>
					{#if checks.domain === 'warn'}
						<a class="check-link" href={resolve('/tls')}>{m.doh_check_open()}</a>
					{/if}
				</li>
				{#if checks.cert !== 'unknown'}
					<li class="check" data-state={checks.cert}>
						<Icon name={checks.cert === 'ok' ? 'check-circle' : 'alert-triangle'} size="1rem" />
						<span class="check-text">
							{checks.cert === 'ok' ? m.doh_check_cert_ok() : m.doh_check_cert_missing()}
						</span>
						{#if checks.cert === 'warn'}
							<a class="check-link" href={resolve('/tls')}>{m.doh_check_open()}</a>
						{/if}
					</li>
				{/if}
				{#if checks.listener !== 'unknown'}
					<li class="check" data-state={checks.listener}>
						<Icon name={checks.listener === 'ok' ? 'check-circle' : 'alert-triangle'} size="1rem" />
						<span class="check-text">
							{checks.listener === 'ok'
								? m.doh_check_listener_ok()
								: m.doh_check_listener_missing()}
						</span>
						{#if checks.listener === 'warn'}
							<a class="check-link" href={resolve('/listeners')}>{m.doh_check_open()}</a>
						{/if}
					</li>
				{/if}
				{#if checks.record !== 'unknown' && checks.recordName}
					<li class="check" data-state={checks.record}>
						<Icon name={checks.record === 'ok' ? 'check-circle' : 'alert-triangle'} size="1rem" />
						<span class="check-text">
							{checks.record === 'ok'
								? m.doh_check_record_ok({ name: displayText(checks.recordName, 80).text })
								: m.doh_check_record_missing({ name: displayText(checks.recordName, 80).text })}
						</span>
						{#if checks.record === 'warn' && views !== null}
							<Button variant="secondary" onclick={openRecord}>{m.doh_record_action()}</Button>
						{/if}
					</li>
				{/if}
			</ul>
		</details>
	{/if}

	{#if result.kind === 'loading'}
		<p class="state">{m.state_loading()}</p>
	{:else if result.kind === 'unavailable'}
		<UnavailableNotice />
	{:else if result.kind === 'error'}
		<ResultNotice {result} onretry={() => void loadList()} />
	{:else if rows.length === 0}
		<section class="empty">
			<p>{m.doh_empty()}</p>
		</section>
	{:else}
		<ul class="cards">
			{#each rows as entry (entry.id)}
				{@const address = addressOf(entry.id)}
				{@const device = deviceName(entry.device)}
				{@const last = seen[entry.id]}
				<li class="card">
					<div class="card-head">
						{#if isAdmin}
							<button type="button" class="card-title card-open" onclick={() => openEdit(entry)}>
								{displayText(entry.label ?? entry.id, 80).text}
							</button>
						{:else}
							<span class="card-title">{displayText(entry.label ?? entry.id, 80).text}</span>
						{/if}
					</div>
					<p class="card-id">{displayText(entry.id, 80).text}</p>

					{#if address.ok}
						<div class="addr">
							<span class="addr-label">{m.doh_url_label()}</span>
							<code class="addr-value">{address.url}</code>
							<Button variant="secondary" onclick={() => void copyText(address.url)}>
								{m.doh_copy()}
							</Button>
						</div>
					{:else}
						{#if address.reason === 'invalid'}
							<p class="warn-line">
								<Icon name="alert-triangle" size="0.9375rem" />
								<span>{addressWarning(address.reason)}</span>
							</p>
						{:else}
							<p class="meta">{m.doh_url_pending()}</p>
						{/if}
					{/if}

					<p class="meta">
						<span>{m.doh_device_label()}</span>
						{#if entry.device === null}
							<span>{m.doh_device_none()}</span>
						{:else if clients === null}
							<span>{m.doh_device_hidden()}</span>
						{:else if device}
							<a class="device-link" href={resolve('/clients')}
								>{displayText(device.name, 60).text}</a
							>
						{:else}
							<span>{m.doh_device_unknown()}</span>
						{/if}
					</p>

					<p class="meta">
						{#if entry.view === null}
							<span>{m.doh_roam_default()}</span>
						{:else}
							<a class="device-link" href={resolve('/zones')}
								>{m.doh_roam_view({ view: displayText(entry.view, 60).text })}</a
							>
						{/if}
					</p>

					{#if isAdmin && last}
						{#if last.kind === 'never'}
							<p class="seen">{m.doh_seen_never()}</p>
						{:else}
							<p class="seen">{seenText(last)}</p>
							{#if seenWarning(entry, last)}
								<p class="warn-line">
									<Icon name="alert-triangle" size="0.9375rem" />
									<span>{m.doh_seen_warn()}</span>
								</p>
							{/if}
						{/if}
					{/if}

					{#if isAdmin}
						<div class="card-actions">
							<Button variant="secondary" onclick={() => openProfile(entry)}>
								{m.doh_profile_open()}
							</Button>
						</div>
					{/if}
				</li>
			{/each}
		</ul>
		<p class="note">{m.doh_footnote()}</p>
	{/if}

	{#if (sheet === 'create' || sheet === 'edit') && (sheet === 'create' || editing)}
		<Sheet
			open
			title={sheet === 'create' ? m.doh_add() : m.doh_edit_title()}
			onclose={closeSheet}
			centeredOnWide
		>
			<div class="field-row">
				<label class="field-label" for="doh-label">{m.doh_label_label()}</label>
				<input
					id="doh-label"
					class="field"
					bind:value={formLabel}
					oninput={onLabelInput}
					autocomplete="off"
					aria-invalid={labelError ? 'true' : undefined}
					aria-describedby="doh-label-help"
				/>
				<p
					id="doh-label-help"
					class="hint"
					class:error-text={labelError !== null}
					role={labelError ? 'alert' : undefined}
				>
					{labelError === 'required'
						? m.doh_label_required()
						: labelError === 'taken'
							? m.doh_label_taken()
							: labelError === 'long'
								? m.doh_label_too_long()
								: m.doh_label_hint()}
				</p>
			</div>

			<div class="field-row">
				<label class="field-label" for="doh-device">{m.doh_device_select_label()}</label>
				<select id="doh-device" class="field" bind:value={formDevice}>
					<option value="">{m.doh_device_none()}</option>
					{#each clients ?? [] as client (client.id)}
						<option value={client.id}>{displayText(client.name, 60).text}</option>
					{/each}
					{#if formDevice !== '' && !(clients ?? []).some((client) => client.id === formDevice)}
						<option value={formDevice}>{m.doh_device_unknown()}</option>
					{/if}
				</select>
				<p class="hint">{m.doh_device_hint()}</p>
			</div>

			<div class="field-row">
				<label class="field-label" for="doh-view">{m.doh_view_label()}</label>
				<select
					id="doh-view"
					class="field"
					bind:value={formView}
					aria-invalid={viewRefused ? 'true' : undefined}
					aria-describedby="doh-view-help"
				>
					<option value="">{m.doh_view_none()}</option>
					{#each views ?? [] as view (view.id)}
						<option value={view.id}>{displayText(view.id, 60).text}</option>
					{/each}
					{#if formView !== '' && !(views ?? []).some((view) => view.id === formView)}
						<option value={formView}>{displayText(formView, 60).text}</option>
					{/if}
				</select>
				{#if viewRefused}
					<p id="doh-view-help" class="error-text" role="alert">{m.doh_view_invalid()}</p>
				{:else}
					<p id="doh-view-help" class="hint">{m.doh_view_hint()}</p>
				{/if}
			</div>

			{#if sheet === 'create'}
				<div class="field-row">
					<label class="field-label" for="doh-id">{m.doh_id_label()}</label>
					<div class="id-row">
						<input
							id="doh-id"
							class="field mono"
							bind:value={formId}
							autocomplete="off"
							aria-invalid={idValid ? undefined : 'true'}
							aria-describedby="doh-id-help"
							oninput={() => (idTouched = true)}
						/>
						<Button variant="secondary" onclick={regenerateId}>{m.doh_regenerate()}</Button>
					</div>
					<p
						id="doh-id-help"
						class="hint"
						class:error-text={!idValid}
						role={idValid ? undefined : 'alert'}
					>
						{idValid ? m.doh_id_hint() : m.doh_id_invalid()}
					</p>
				</div>
			{:else if editing}
				<div class="field-row">
					<span class="field-label">{m.doh_id_label()}</span>
					<code class="mono static">{displayText(editing.id, 80).text}</code>
				</div>
				{@const address = addressOf(editing.id)}
				{#if address.ok}
					<div class="addr">
						<span class="addr-label">{m.doh_url_label()}</span>
						<code class="addr-value">{address.url}</code>
						<Button variant="secondary" onclick={() => void copyText(address.url)}>
							{m.doh_copy()}
						</Button>
					</div>
					<div class="addr">
						<span class="addr-label">{m.doh_dot_label()}</span>
						<code class="addr-value">{address.dot}</code>
						<Button variant="secondary" onclick={() => void copyText(address.dot)}>
							{m.doh_copy()}
						</Button>
					</div>
				{:else}
					<p class="warn-line">
						<Icon name="alert-triangle" size="0.9375rem" />
						<span>{addressWarning(address.reason)}</span>
					</p>
				{/if}
			{/if}

			{#snippet footer()}
				{#if failure && !viewRefused}
					<div class="footer-error">
						<ErrorNotice code={failure.code} params={failure.params} />
					</div>
				{/if}
				{#if sheet === 'edit' && editing && confirmDelete}
					<p class="confirm-text">{m.doh_delete_body()}</p>
					<div class="actions">
						<Button variant="secondary" onclick={() => (confirmDelete = false)}>
							{m.action_cancel()}
						</Button>
						<Button variant="danger" disabled={busy} onclick={() => void removeEntry()}>
							{m.action_delete()}
						</Button>
					</div>
				{:else}
					{#if sheet === 'edit'}
						<button type="button" class="quiet-danger" onclick={() => (confirmDelete = true)}>
							{m.action_delete()}
						</button>
					{:else}
						<span></span>
					{/if}
					<div class="actions">
						<Button variant="secondary" onclick={closeSheet}>{m.action_cancel()}</Button>
						<Button variant="primary" disabled={!canSave} onclick={() => void submit()}>
							{sheet === 'create' ? m.doh_create_submit() : m.action_save()}
						</Button>
					</div>
				{/if}
			{/snippet}
		</Sheet>
	{/if}

	{#if sheet === 'profile' && editing}
		<Sheet open title={m.doh_profile_title()} onclose={closeSheet} centeredOnWide>
			<p class="secret-note">
				<Icon name="lock" size="0.9375rem" />
				<span>{m.doh_profile_secret()}</span>
			</p>

			<div class="field-row">
				<label class="field-label" for="doh-ssid">{m.doh_profile_ssid_label()}</label>
				<input
					id="doh-ssid"
					class="field"
					bind:value={profileSsid}
					autocomplete="off"
					aria-describedby="doh-ssid-hint"
				/>
				<p id="doh-ssid-hint" class="hint">{m.doh_profile_ssid_hint()}</p>
			</div>

			<div class="field-row">
				<span class="field-label">{m.doh_profile_protocol_label()}</span>
				<Segmented
					options={protocolOptions}
					bind:value={profileProtocol}
					label={m.doh_profile_protocol_label()}
				/>
			</div>

			{#if profileProtocol === 'https' && nodeHosts.length > 0}
				<div class="field-row">
					<span class="field-label">{m.doh_profile_nodes_label()}</span>
					{#each nodeHosts as node (node.hostname)}
						<label class="node-pick">
							<input type="checkbox" value={node.hostname} bind:group={profileHosts} />
							<span>{node.name} · <code>{node.hostname}</code></span>
						</label>
					{/each}
					<p class="hint">{m.doh_profile_nodes_hint()}</p>
				</div>
			{/if}

			<div class="field-row">
				<label class="field-label" for="doh-servers">{m.doh_server_ips_label()}</label>
				<textarea
					id="doh-servers"
					class="field area mono"
					rows="2"
					bind:value={profileServers}
					aria-describedby="doh-servers-hint"></textarea>
				<p id="doh-servers-hint" class="hint">{m.doh_server_ips_hint()}</p>
			</div>

			{#if profileError}
				<p class="error-text" role="alert">{profileErrorText(profileError)}</p>
			{/if}
			<div class="actions">
				<Button variant="primary" onclick={() => editing && downloadProfile(editing)}>
					{m.doh_profile_download()}
				</Button>
			</div>

			<h3 class="sub">{m.doh_android_title()}</h3>
			{@const dot = addressOf(editing.id)}
			{#if dot.ok}
				<div class="addr">
					<code class="addr-value">{dot.dot}</code>
					<Button variant="secondary" onclick={() => void copyText(dot.dot)}>{m.doh_copy()}</Button>
				</div>
				<p class="hint">{m.doh_android_hint()}</p>
			{:else}
				<p class="warn-line">
					<Icon name="alert-triangle" size="0.9375rem" />
					<span>{addressWarning(dot.reason)}</span>
				</p>
			{/if}
		</Sheet>
	{/if}

	{#if sheet === 'record' && checks.recordName}
		<Sheet open title={m.doh_record_title()} onclose={closeSheet} centeredOnWide>
			<p class="hint">{displayText(checks.recordName, 80).text}</p>

			<div class="field-row">
				<label class="field-label" for="doh-rec-view">{m.doh_record_view_label()}</label>
				<select id="doh-rec-view" class="field" bind:value={recordView}>
					{#each views ?? [] as view (view.id)}
						<option value={view.id}>{displayText(view.id, 60).text}</option>
					{/each}
				</select>
			</div>

			<div class="field-row">
				<label class="field-label" for="doh-rec-lan">{m.doh_record_lan_label()}</label>
				<input
					id="doh-rec-lan"
					class="field mono"
					bind:value={recordLan}
					autocomplete="off"
					aria-invalid={recordLan.trim() !== '' && !isIpLiteral(recordLan.trim())
						? 'true'
						: undefined}
					aria-describedby="doh-rec-lan-help"
				/>
				<p id="doh-rec-lan-help" class="hint">
					{recordLan.trim() !== '' && !isIpLiteral(recordLan.trim())
						? m.doh_record_lan_invalid()
						: m.doh_record_lan_hint()}
				</p>
			</div>

			<div class="field-row">
				<label class="field-label" for="doh-rec-public">{m.doh_record_public_label()}</label>
				<input
					id="doh-rec-public"
					class="field mono"
					bind:value={recordPublic}
					autocomplete="off"
				/>
				<p class="hint">
					{m.doh_record_public_note()}
					<a class="check-link" href={resolve('/names')}>{m.doh_record_public_cta()}</a>
				</p>
			</div>

			{#snippet footer()}
				{#if failure}
					<div class="footer-error">
						<ErrorNotice code={failure.code} params={failure.params} />
					</div>
				{/if}
				<span></span>
				<div class="actions">
					<Button variant="secondary" onclick={closeSheet}>{m.action_cancel()}</Button>
					<Button
						variant="primary"
						disabled={!canSaveRecord}
						onclick={() => void saveRecordForDomain()}
					>
						{m.action_save()}
					</Button>
				</div>
			{/snippet}
		</Sheet>
	{/if}
</div>

<style>
	.doh {
		container: doh / inline-size;
		max-width: 60rem;
	}
	.page-head {
		display: flex;
		flex-wrap: wrap;
		align-items: flex-start;
		justify-content: space-between;
		gap: var(--space-4);
		margin-bottom: var(--space-4);
	}
	.lead {
		max-width: 40rem;
		margin: 0;
		color: var(--label-2);
		line-height: 1.45;
	}
	.state {
		color: var(--label-2);
	}
	.note {
		margin: var(--space-3) 0 0;
		font-size: 0.8125rem;
		color: var(--label-3);
	}

	.setup {
		margin-bottom: var(--space-4);
		padding: var(--space-3) var(--space-4);
		border: 1px solid var(--separator);
		border-radius: var(--r-card);
		background: var(--surface);
	}
	.setup summary {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: var(--space-2);
		cursor: pointer;
		font-weight: 600;
	}
	.setup-state {
		font-weight: 400;
		color: var(--label-2);
	}
	.checks {
		display: grid;
		gap: var(--space-2);
		margin: var(--space-3) 0 0;
		padding: 0;
		list-style: none;
	}
	.check {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: var(--space-2);
		font-size: 0.9375rem;
	}
	.check[data-state='warn'] {
		color: var(--warn);
	}
	.check-text {
		flex: 1 1 14rem;
		min-width: 0;
		overflow-wrap: anywhere;
	}
	.check-link {
		color: var(--accent);
	}

	.empty {
		padding: var(--space-5);
		background: var(--surface);
		border: 1px solid var(--separator);
		border-radius: var(--r-card);
	}
	.empty p {
		margin: 0;
		color: var(--label-2);
	}

	.cards {
		display: grid;
		grid-template-columns: minmax(0, 1fr);
		gap: var(--space-3);
		margin: 0;
		padding: 0;
		list-style: none;
	}
	@container doh (min-width: 40rem) {
		.cards {
			grid-template-columns: repeat(2, minmax(0, 1fr));
		}
	}
	.card {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		min-width: 0;
		padding: var(--space-3) var(--space-4);
		border: 1px solid var(--separator);
		border-radius: var(--r-card);
		background: var(--surface);
		box-shadow: var(--shadow);
	}
	.card-title {
		font: inherit;
		font-size: 1rem;
		font-weight: 600;
		color: var(--label);
		overflow-wrap: anywhere;
	}
	.card-open {
		padding: 0;
		border: none;
		background: transparent;
		text-align: start;
		cursor: pointer;
	}
	.card-id,
	.static {
		margin: 0;
		font-family: var(--font-mono);
		font-size: 0.8125rem;
		color: var(--label-2);
		overflow-wrap: anywhere;
	}
	.meta,
	.seen {
		margin: 0;
		font-size: 0.875rem;
		color: var(--label-2);
		overflow-wrap: anywhere;
	}
	.meta {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-1);
	}
	.meta > span:first-child {
		color: var(--label-3);
	}
	.device-link {
		color: var(--accent);
	}
	.addr {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: var(--space-2);
	}
	.addr-label {
		font-size: 0.8125rem;
		color: var(--label-3);
	}
	.addr-value {
		flex: 1 1 12rem;
		min-width: 0;
		font-family: var(--font-mono);
		font-size: 0.8125rem;
		overflow-wrap: anywhere;
	}
	.warn-line {
		display: flex;
		align-items: flex-start;
		gap: var(--space-2);
		margin: 0;
		font-size: 0.875rem;
		color: var(--label-2);
	}
	.card-actions {
		margin-top: auto;
	}

	.field-row {
		margin-bottom: var(--space-3);
	}
	.field-label {
		display: block;
		margin: 0 0 0.25rem;
		font-size: 0.8125rem;
		color: var(--label-2);
	}
	.field {
		width: 100%;
		min-height: var(--control-h);
		padding: 0.5rem 0.75rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		background: var(--surface);
		color: var(--label);
		font: inherit;
	}
	.area {
		min-height: 3.5rem;
	}
	.mono {
		font-family: var(--font-mono);
	}
	.id-row {
		display: flex;
		gap: var(--space-2);
		align-items: center;
	}
	.id-row .field {
		flex: 1 1 auto;
	}
	.node-pick {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}

	.hint {
		margin: var(--space-1) 0 0;
		font-size: 0.8125rem;
		color: var(--label-3);
	}
	.error-text {
		margin: var(--space-1) 0 0;
		font-size: 0.8125rem;
		color: var(--warn);
	}
	.secret-note {
		display: flex;
		align-items: flex-start;
		gap: var(--space-2);
		margin: 0 0 var(--space-3);
		padding: var(--space-2) var(--space-3);
		border-radius: var(--r-ctl);
		background: var(--surface-2);
		font-size: 0.875rem;
	}
	.sub {
		margin: var(--space-4) 0 var(--space-2);
		font-size: 0.9375rem;
		font-weight: 600;
	}
	.actions {
		display: flex;
		flex-wrap: wrap;
		justify-content: flex-end;
		gap: var(--space-2);
	}
	.confirm-text {
		margin: 0;
		font-size: 0.875rem;
		color: var(--label-2);
	}
	.quiet-danger {
		padding: 0;
		border: none;
		background: transparent;
		color: var(--warn);
		font: inherit;
		font-size: 0.875rem;
		cursor: pointer;
	}
	.footer-error {
		flex-basis: 100%;
	}
</style>
