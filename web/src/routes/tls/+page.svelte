<script lang="ts">
	import { onMount } from 'svelte';
	import { SvelteMap } from 'svelte/reactivity';
	import Banner from '$lib/components/Banner.svelte';
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import Icon from '$lib/components/Icon.svelte';
	import Segmented from '$lib/components/Segmented.svelte';
	import Sheet from '$lib/components/Sheet.svelte';
	import Switch from '$lib/components/Switch.svelte';
	import UnavailableNotice from '$lib/components/UnavailableNotice.svelte';
	import {
		getTlsConfig,
		getTlsStatus,
		preflightTls,
		putCloudflareToken,
		renewTls,
		revokeTls,
		rotateTls,
		saveTlsConfig,
		triggerDyndns,
		uploadCertificate,
		dyndnsDiscoveredIpv4,
		dyndnsDiscoveredIpv6,
		type TlsStatus,
	} from '$lib/api/tls';
	import { listClusterNodes } from '$lib/api/cluster';
	import { getConfig, ifMatchFor } from '$lib/api/config';
	import type { TlsMode } from '$lib/api/stats';
	import { failureOf, settle, type Result } from '$lib/api/result';
	import { auth } from '$lib/auth/state.svelte';
	import { formatDateTime, formatFingerprint, formatRelativeTime } from '$lib/format';
	import { getLocale } from '$lib/i18n/locale';
	import { m } from '$lib/paraglide/messages';
	import { displayText } from '$lib/safe-text';

	type Tab = 'overview' | 'cert' | 'provider' | 'dns';

	type Ipv6Mode = 'eui64' | 'stable_privacy' | 'static';
	type DnsProviderKind = 'cloudflare' | 'manual' | 'none';

	type DynDnsNodeForm = {
		node_id: string;
		hostname: string;
		enabled: boolean;
		ipv4: boolean;
		ipv6: boolean;
		public_entry: boolean;
		ipv6_mode: Ipv6Mode;
		interfaces: string;
		static_address: string;
	};

	type ExtraZoneForm = { name: string; zone_id: string };

	const isAdmin = $derived(auth.role === 'admin');
	const locale = getLocale();
	const dash = () => m.tls_value_none();

	const tabOptions: { value: Tab; label: string }[] = [
		{ value: 'overview', label: m.tls_tab_overview() },
		{ value: 'cert', label: m.tls_tab_cert() },
		{ value: 'provider', label: m.tls_tab_provider() },
		{ value: 'dns', label: m.tls_tab_dns() },
	];

	const sourceOptions: { value: TlsMode; label: string }[] = [
		{ value: 'self_signed', label: m.tls_source_self_signed() },
		{ value: 'acme', label: m.tls_source_acme() },
		{ value: 'manual', label: m.tls_source_manual() },
	];

	const dnsProviderOptions: { value: DnsProviderKind; label: string }[] = [
		{ value: 'cloudflare', label: m.tls_dns_provider_cloudflare() },
		{ value: 'manual', label: m.tls_dns_provider_manual() },
		{ value: 'none', label: m.tls_dns_provider_none() },
	];

	let tab = $state<Tab>('overview');
	let status = $state<Result<TlsStatus>>({ kind: 'loading' });
	let configVersion = $state<number | null>(null);
	let tlsConfig = $state<Record<string, unknown>>({});
	let busy = $state(false);
	let failure = $state<{ code: string; params: Record<string, unknown> } | null>(null);
	let uploadOpen = $state(false);
	let revokeOpen = $state(false);
	let confirmOpen = $state(false);
	let ipv6HelpOpen = $state(false);
	let revokeReason = $state('');
	let formDomain = $state('');
	let formDyndnsHost = $state('');
	let formDyndnsEnabled = $state(false);
	let formPublishV4 = $state(true);
	let formPublishV6 = $state(true);
	let formPublicEntry = $state(false);
	let formIpv6Mode = $state<Ipv6Mode>('eui64');
	let formIpv6Interfaces = $state('');
	let formIpv6Static = $state('');
	let formNodeProfiles = $state<DynDnsNodeForm[]>([]);
	let clusterNodeIds = $state<string[]>([]);
	let formAcmeEmail = $state('');
	let formSource = $state<TlsMode>('self_signed');
	let formDnsProvider = $state<DnsProviderKind>('cloudflare');
	let formCfZoneId = $state('');
	let formCfZones = $state<ExtraZoneForm[]>([]);
	let formCfToken = $state('');
	let formCfTokenClear = $state(false);
	let hasCloudflareToken = $state(false);
	let certPem = $state('');
	let keyPem = $state('');

	const data = $derived(status.kind === 'ok' ? status.data : null);
	const hasClusterProfiles = $derived(formNodeProfiles.length > 0);
	const detectedV4 = $derived(dyndnsDiscoveredIpv4(data));
	const detectedV6 = $derived(dyndnsDiscoveredIpv6(data));
	const showStandaloneIpv6Options = $derived(formDyndnsEnabled && !hasClusterProfiles && formPublishV6);

	const ipv6ModeOptions: { value: Ipv6Mode; label: string }[] = [
		{ value: 'eui64', label: m.tls_dyndns_ipv6_mode_eui64() },
		{ value: 'stable_privacy', label: m.tls_dyndns_ipv6_mode_stable() },
		{ value: 'static', label: m.tls_dyndns_ipv6_mode_static() },
	];

	function dnsProviderLabel(kind: DnsProviderKind): string {
		if (kind === 'manual') return m.tls_dns_provider_manual();
		if (kind === 'none') return m.tls_dns_provider_none();
		return m.tls_dns_provider_cloudflare();
	}

	function publishTag(detected: string | null, optedIn: boolean): string {
		if (!detected) return m.tls_dyndns_not_seen();
		if (!formDyndnsEnabled || !optedIn) return m.tls_dyndns_opted_out();
		return m.tls_dyndns_will_publish();
	}

	const entryHostname = $derived.by(() => {
		const fromProfiles = formNodeProfiles.find((p) => p.enabled && p.public_entry)?.hostname.trim();
		if (fromProfiles) return fromProfiles;
		return formPublicEntry ? formDyndnsHost.trim() : '';
	});

	const expectedNodeHosts = $derived.by(() => {
		if (formNodeProfiles.length > 0) {
			return formNodeProfiles
				.filter((p) => p.enabled && p.hostname.trim())
				.map((p) => ({
					hostname: p.hostname.trim(),
					self: p.hostname.trim() === formDyndnsHost.trim(),
				}));
		}
		const host = formDyndnsHost.trim();
		return host ? [{ hostname: host, self: true }] : [];
	});

	const bootstrap = $derived.by(() => {
		if (!data) return null;
		if (data.mode !== 'self_signed' && data.self_signed !== true) return null;
		const fp = data.fingerprint_sha256 ?? '';
		return {
			fingerprint: fp === '' ? '' : formatFingerprint(fp),
			names: (data.identifiers ?? []).join(', ') || dash(),
		};
	});

	const modeLabel = $derived.by(() => {
		if (!data?.mode) return dash();
		if (data.mode === 'acme') return m.tls_mode_acme();
		if (data.mode === 'manual') return m.tls_mode_manual();
		return m.tls_mode_self_signed();
	});

	const daysLeft = $derived.by(() => {
		if (!data) return null;
		if (typeof data.days_to_expiry === 'number') return data.days_to_expiry;
		if (!data.not_after) return null;
		const ms = Date.parse(data.not_after) - Date.now();
		if (Number.isNaN(ms)) return null;
		return Math.max(0, Math.floor(ms / 86_400_000));
	});

	const domain = $derived(
		formDomain.trim() || String(tlsConfig.public_domain ?? '').trim(),
	);

	const autoSans = $derived.by(() => {
		if (!domain) return [] as string[];
		return [`dns.${domain}`, `*.dns.${domain}`];
	});

	const nodeHostHint = $derived(
		domain ? `ns1.dns.${domain}` : 'ns1.dns.example.com',
	);

	const acme = $derived.by(() => {
		const raw = tlsConfig.acme;
		return raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {};
	});

	const acmeEnabled = $derived(acme.enabled === true || formSource === 'acme');

	function asText(value: unknown): string {
		if (value == null || value === '') return dash();
		return displayText(String(value), 120).text;
	}

	function formatInstant(value: string | null | undefined): string {
		if (!value) return dash();
		const date = new Date(value);
		if (Number.isNaN(date.getTime())) return asText(value);
		return formatDateTime(date, locale);
	}

	function formatRelative(value: string | null | undefined): string {
		if (!value) return dash();
		const date = new Date(value);
		if (Number.isNaN(date.getTime())) return asText(value);
		return formatRelativeTime(date, new Date(), locale);
	}

	function objectField(source: Record<string, unknown>, key: string): Record<string, unknown> {
		const value = source[key];
		return value && typeof value === 'object' ? { ...(value as Record<string, unknown>) } : {};
	}

	function defaultHostnameFor(nodeId: string, publicDomain: string): string {
		const domain = publicDomain.trim();
		if (!domain) return '';
		const label = nodeId.startsWith('node') ? `ns${nodeId.slice(4)}` : nodeId;
		return `${label}.dns.${domain}`;
	}

	function parseIpv6Mode(value: unknown): Ipv6Mode {
		const mode = String(value ?? 'eui64');
		return mode === 'stable_privacy' || mode === 'static' || mode === 'eui64' ? mode : 'eui64';
	}

	function profileFromItem(item: Record<string, unknown>, node_id: string, publicDomain: string): DynDnsNodeForm {
		const ident = objectField(item, 'ipv6_identifier');
		return {
			node_id,
			hostname: String(item.hostname ?? '').trim() || defaultHostnameFor(node_id, publicDomain),
			enabled: item.enabled !== false,
			ipv4: item.ipv4 !== false,
			ipv6: item.ipv6 !== false,
			public_entry: item.public_entry === true,
			ipv6_mode: parseIpv6Mode(ident.mode),
			static_address: String(ident.static_address ?? ''),
			interfaces: Array.isArray(item.interfaces) ? item.interfaces.map(String).join(', ') : '',
		};
	}

	function profilesFromWire(
		dyndns: Record<string, unknown>,
		nodeIds: string[],
		publicDomain: string,
	): DynDnsNodeForm[] {
		const raw = Array.isArray(dyndns.nodes) ? dyndns.nodes : [];
		const byId = new SvelteMap<string, DynDnsNodeForm>();
		for (const row of raw) {
			if (!row || typeof row !== 'object') continue;
			const item = row as Record<string, unknown>;
			const node_id = String(item.node_id ?? '').trim();
			if (!node_id) continue;
			byId.set(node_id, profileFromItem(item, node_id, publicDomain));
		}
		const ids = nodeIds.length > 0 ? nodeIds : [...byId.keys()];
		if (ids.length === 0) return [];
		let sawEntry = false;
		return ids.map((node_id) => {
			const existing = byId.get(node_id) ?? profileFromItem({}, node_id, publicDomain);
			const enabled = existing.enabled;
			const public_entry = enabled && !sawEntry && existing.public_entry;
			if (public_entry) sawEntry = true;
			return { ...existing, public_entry };
		});
	}

	function patchProfile(nodeId: string, patch: Partial<DynDnsNodeForm>): void {
		formNodeProfiles = formNodeProfiles.map((p) => {
			if (p.node_id !== nodeId) return p;
			const next = { ...p, ...patch };
			if (next.enabled === false) next.public_entry = false;
			if (next.public_entry) next.enabled = true;
			return next;
		});
	}

	function setProfileHostname(nodeId: string, hostname: string): void {
		const prev = formNodeProfiles.find((p) => p.node_id === nodeId);
		patchProfile(nodeId, { hostname });
		if (prev && (prev.public_entry || formDyndnsHost === prev.hostname)) {
			formDyndnsHost = hostname;
		}
	}

	function setPublicEntryNode(nodeId: string): void {
		formNodeProfiles = formNodeProfiles.map((p) => ({
			...p,
			public_entry: p.node_id === nodeId,
			enabled: p.node_id === nodeId ? true : p.enabled,
		}));
		const entry = formNodeProfiles.find((p) => p.node_id === nodeId);
		if (entry) {
			formDyndnsHost = entry.hostname;
			formPublicEntry = true;
		}
	}

	function parseInterfaces(raw: string): string[] {
		return raw
			.split(/[\s,]+/)
			.map((s) => s.trim())
			.filter(Boolean);
	}

	function ipv6ModeHint(mode: Ipv6Mode): string {
		if (mode === 'stable_privacy') return m.tls_dyndns_ipv6_mode_stable_hint();
		if (mode === 'static') return m.tls_dyndns_ipv6_mode_static_hint();
		return m.tls_dyndns_ipv6_mode_eui64_hint();
	}

	async function load(): Promise<void> {
		const [st, cfg, nodes] = await Promise.all([
			settle(getTlsStatus()),
			getConfig().catch(() => null),
			listClusterNodes().catch(() => []),
		]);
		status = st;
		configVersion = cfg?.version ?? null;
		clusterNodeIds = nodes.filter((n) => !n.revoked).map((n) => n.node_id);
		try {
			const tls = await getTlsConfig();
			tlsConfig = tls.tls;
			hasCloudflareToken = tls.has_cloudflare_token === true;
			formCfToken = '';
			formCfTokenClear = false;
			formDomain = String(tls.tls.public_domain ?? '');
			const provider = objectField(tls.tls, 'dns_provider');
			const kind = String(provider.kind ?? 'cloudflare');
			formDnsProvider =
				kind === 'manual' || kind === 'none' || kind === 'cloudflare' ? kind : 'cloudflare';
			formCfZoneId = String(objectField(provider, 'cloudflare').zone_id ?? '');
			formCfZones = Array.isArray(provider.zones)
				? provider.zones.map((row) => {
						const zone = row && typeof row === 'object' ? (row as Record<string, unknown>) : {};
						return {
							name: String(zone.name ?? ''),
							zone_id: String(zone.zone_id ?? ''),
						};
					})
				: [];
			const dyndns = objectField(tls.tls, 'dyndns');
			formDyndnsHost = String(dyndns.hostname ?? '');
			formDyndnsEnabled = dyndns.enabled === true;
			formPublishV4 = dyndns.ipv4 !== false;
			formPublishV6 = dyndns.ipv6 !== false;
			formPublicEntry = dyndns.public_entry === true;
			const ident = objectField(dyndns, 'ipv6_identifier');
			formIpv6Mode = parseIpv6Mode(ident.mode);
			formIpv6Static = String(ident.static_address ?? '');
			formIpv6Interfaces = Array.isArray(dyndns.interfaces)
				? dyndns.interfaces.map(String).join(', ')
				: '';
			formNodeProfiles = profilesFromWire(dyndns, clusterNodeIds, formDomain);
			if (formNodeProfiles.length > 0) {
				const entry = formNodeProfiles.find((p) => p.public_entry);
				if (entry) {
					formPublicEntry = true;
					if (!formDyndnsHost) formDyndnsHost = entry.hostname;
				} else {
					formPublicEntry = false;
				}
			}
			const acmeCfg = objectField(tls.tls, 'acme');
			formAcmeEmail = String(acmeCfg.email ?? '');
			const tlsMode = tls.tls.mode;
			if (tlsMode === 'acme' || tlsMode === 'manual' || tlsMode === 'self_signed') {
				formSource = tlsMode;
			} else if (st.kind === 'ok' && st.data.mode) {
				formSource = st.data.mode;
			}
		} catch {
			/* viewers may only have status */
		}
	}

	function openConfirm(): void {
		failure = null;
		confirmOpen = true;
	}

	async function saveConfig(): Promise<void> {
		busy = true;
		failure = null;
		const profiles = formNodeProfiles
			.map((p) => ({
				node_id: p.node_id.trim(),
				hostname: p.hostname.trim(),
				enabled: p.enabled,
				ipv4: p.ipv4,
				ipv6: p.ipv6,
				public_entry: p.enabled && p.public_entry,
				ipv6_identifier: {
					mode: p.ipv6_mode,
					static_address:
						p.ipv6_mode === 'static' ? p.static_address.trim() || null : null,
				},
				interfaces: p.ipv6_mode === 'static' ? [] : parseInterfaces(p.interfaces),
			}))
			.filter((p) => p.node_id && p.hostname);
		const entry = profiles.find((p) => p.public_entry);
		const ipv6Source =
			profiles.find((p) => p.enabled && p.ipv6) ?? profiles.find((p) => p.enabled) ?? null;
		const flatHost =
			formDyndnsHost.trim() || entry?.hostname || profiles[0]?.hostname || '';
		const flatEntry = profiles.length > 0 ? Boolean(entry) : formPublicEntry;
		const flatV4 =
			profiles.length > 0 ? profiles.some((p) => p.enabled && p.ipv4) : formPublishV4;
		const flatV6 =
			profiles.length > 0 ? profiles.some((p) => p.enabled && p.ipv6) : formPublishV6;
		const flatIpv6Ident =
			profiles.length > 0 && ipv6Source
				? ipv6Source.ipv6_identifier
				: {
						mode: formIpv6Mode,
						static_address:
							formIpv6Mode === 'static' ? formIpv6Static.trim() || null : null,
					};
		const flatInterfaces =
			profiles.length > 0 && ipv6Source
				? ipv6Source.interfaces
				: formIpv6Mode === 'static'
					? []
					: parseInterfaces(formIpv6Interfaces);
		const next = {
			...tlsConfig,
			mode: formSource,
			public_domain: formDomain.trim(),
			dns_provider: {
				...objectField(tlsConfig, 'dns_provider'),
				kind: formDnsProvider,
				cloudflare: {
					...objectField(objectField(tlsConfig, 'dns_provider'), 'cloudflare'),
					zone_id: formCfZoneId.trim() || null,
				},
				zones: formCfZones
					.map((z) => ({
						name: z.name.trim(),
						zone_id: z.zone_id.trim() || null,
					}))
					.filter((z) => z.name),
			},
			acme: {
				...objectField(tlsConfig, 'acme'),
				enabled: formSource === 'acme',
				email: formAcmeEmail.trim(),
			},
			dyndns: {
				...objectField(tlsConfig, 'dyndns'),
				enabled: formDyndnsEnabled,
				hostname: flatHost,
				public_entry: flatEntry,
				nodes: profiles,
				ipv4: flatV4,
				ipv6: flatV6,
				ipv6_identifier: flatIpv6Ident,
				interfaces: flatInterfaces,
				proxied: false,
			},
		};
		try {
			if (formCfTokenClear) {
				await putCloudflareToken(null);
			} else if (formCfToken.trim() !== '') {
				await putCloudflareToken(formCfToken.trim());
			}
			const saved = await saveTlsConfig(next, { ifMatch: ifMatchFor(configVersion) });
			configVersion = saved.version;
			tlsConfig = saved.tls;
			confirmOpen = false;
			await load();
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
		formSource = 'manual';
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

{#snippet dnsProviderStatus()}
	<GroupedList header={m.tls_dns_provider_group()}>
		<GroupedRow label={m.tls_dns_provider_label()} detail={dnsProviderLabel(formDnsProvider)}>
			{#snippet trailing()}
				{#if isAdmin}
					<Button onclick={() => (tab = 'provider')}>{m.tls_dns_provider_configure()}</Button>
				{/if}
			{/snippet}
		</GroupedRow>
		{#if formDnsProvider === 'cloudflare'}
			<GroupedRow
				label={m.tls_cf_token_status()}
				detail={hasCloudflareToken
					? m.tls_cf_token_status_set()
					: m.tls_cf_token_status_missing()}
			/>
			<GroupedRow
				label={m.tls_cf_zone_label()}
				detail={formCfZoneId.trim() ? formCfZoneId : dash()}
				detailMono={Boolean(formCfZoneId.trim())}
			/>
		{/if}
	</GroupedList>
	<p class="hint tight">{m.tls_dns_provider_status_hint()}</p>
{/snippet}

<div class="tls">
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
	{:else if data}
		<div class="tabs">
			<Segmented options={tabOptions} bind:value={tab} label={m.tls_tabs_label()} />
		</div>

		{#if tab === 'overview'}
			<section class="panel">
				<GroupedList header={m.tls_status_group()}>
					<GroupedRow label={m.dashboard_tls_label()} detail={modeLabel} />
					{#if data.issuer}
						<GroupedRow label={m.tls_issuer_label()} detail={asText(data.issuer)} />
					{/if}
					{#if data.subject}
						<GroupedRow label={m.tls_subject_label()} detail={asText(data.subject)} detailMono />
					{/if}
					{#if data.not_before}
						<GroupedRow
							label={m.tls_valid_from_label()}
							detail={formatInstant(data.not_before)}
							detailMono
						/>
					{/if}
					{#if data.not_after}
						<GroupedRow
							label={m.tls_expires_label()}
							detail={formatInstant(data.not_after)}
							detailMono
						/>
					{/if}
					{#if daysLeft !== null}
						<GroupedRow
							label={m.tls_days_left_label()}
							detail={m.tls_days_left_value({ count: daysLeft })}
						/>
					{/if}
					{#if data.identifiers && data.identifiers.length > 0}
						<GroupedRow
							label={m.tls_sans_label()}
							detail={data.identifiers.join(' · ')}
							detailMono
						/>
					{/if}
					{#if data.key_type}
						<GroupedRow label={m.tls_key_type_label()} detail={asText(data.key_type)} />
					{/if}
					{#if data.fingerprint_sha256}
						<GroupedRow
							label={m.tls_fingerprint_label()}
							detail={formatFingerprint(data.fingerprint_sha256)}
							detailMono
						/>
					{/if}
					<GroupedRow label={m.tls_last_issue_label()} detail={formatInstant(data.last_issue)} detailMono />
					<GroupedRow
						label={m.tls_last_renew_label()}
						detail={formatInstant(data.last_renew_attempt)}
						detailMono
					/>
					<GroupedRow label={m.tls_last_error_label()} detail={asText(data.last_error)} />
				</GroupedList>

				<GroupedList header={m.tls_acme_group()}>
					<GroupedRow
						label={m.tls_acme_status_label()}
						detail={acme.enabled === true ? m.tls_acme_status_ready() : m.tls_acme_status_off()}
					/>
					<GroupedRow label={m.tls_acme_directory_label()} detail={asText(acme.directory)} />
					<GroupedRow label={m.tls_acme_email_label()} detail={asText(acme.email)} />
				</GroupedList>

				{@render dnsProviderStatus()}

				<GroupedList header={m.tls_dyndns_status_group()}>
					<GroupedRow
						label={m.tls_dyndns_last_v4()}
						detail={asText(dyndnsDiscoveredIpv4(data))}
						detailMono
					/>
					<GroupedRow
						label={m.tls_dyndns_last_v6()}
						detail={asText(dyndnsDiscoveredIpv6(data))}
						detailMono
					/>
					<GroupedRow
						label={m.tls_dyndns_last_change()}
						detail={formatRelative(data.last_dyndns_success)}
					/>
					<GroupedRow label={m.tls_last_error_label()} detail={dash()} />
				</GroupedList>

				{#if isAdmin}
					<GroupedList header={m.tls_actions_group()}>
						<GroupedRow label={m.tls_action_renew()} detail={m.tls_action_renew_detail()}>
							{#snippet trailing()}
								<Button disabled={busy} onclick={() => void runAction(renewTls)}>{m.tls_run()}</Button>
							{/snippet}
						</GroupedRow>
						<GroupedRow label={m.tls_action_dyndns()} detail={m.tls_action_dyndns_detail()}>
							{#snippet trailing()}
								<Button disabled={busy} onclick={() => void runAction(triggerDyndns)}
									>{m.tls_run()}</Button
								>
							{/snippet}
						</GroupedRow>
						<GroupedRow label={m.tls_action_rotate()} detail={m.tls_action_rotate_detail()}>
							{#snippet trailing()}
								<Button disabled={busy} onclick={() => void runAction(rotateTls)}>{m.tls_run()}</Button>
							{/snippet}
						</GroupedRow>
						<GroupedRow label={m.tls_action_preflight()} detail={m.tls_action_preflight_detail()}>
							{#snippet trailing()}
								<Button disabled={busy} onclick={() => void runAction(preflightTls)}
									>{m.tls_run()}</Button
								>
							{/snippet}
						</GroupedRow>
						<GroupedRow label={m.tls_action_revoke()} detail={m.tls_action_revoke_detail()}>
							{#snippet trailing()}
								<Button variant="danger" disabled={busy} onclick={() => (revokeOpen = true)}>
									{m.tls_open()}
								</Button>
							{/snippet}
						</GroupedRow>
					</GroupedList>
				{/if}
			</section>
		{:else if tab === 'cert'}
			<section class="panel">
				{#if isAdmin}
					<p class="section-label">{m.tls_source_label()}</p>
					<Segmented
						options={sourceOptions}
						bind:value={formSource}
						label={m.tls_source_label()}
					/>

					<div class="form-card">
						<label class="field-label" for="tls-domain">{m.tls_public_domain_label()}</label>
						<input id="tls-domain" class="field mono" bind:value={formDomain} autocomplete="off" />
						<p class="hint">{m.tls_public_domain_hint()}</p>

						<p class="field-label">{m.tls_sans_auto_label()}</p>
						{#if autoSans.length > 0}
							<ul class="sans-list mono">
								{#each autoSans as san (san)}
									<li>{san}</li>
								{/each}
							</ul>
						{:else}
							<p class="hint">{dash()}</p>
						{/if}

						{#if formSource === 'acme' || acmeEnabled}
							<label class="field-label" for="tls-acme-email">{m.tls_acme_email_label()}</label>
							<input
								id="tls-acme-email"
								class="field"
								type="email"
								bind:value={formAcmeEmail}
								autocomplete="email"
							/>
						{/if}

						{#if formSource === 'manual'}
							<p class="hint">{m.tls_source_hint_manual()}</p>
							<Button disabled={busy} onclick={() => (uploadOpen = true)}>{m.tls_action_upload()}</Button>
						{/if}
					</div>

					{@render dnsProviderStatus()}

					<div class="save-row">
						<Button variant="primary" disabled={busy} onclick={openConfirm}>{m.tls_save_config()}</Button>
					</div>
				{:else}
					<GroupedList header={m.tls_status_group()}>
						<GroupedRow label={m.dashboard_tls_label()} detail={modeLabel} />
						<GroupedRow label={m.tls_public_domain_label()} detail={asText(tlsConfig.public_domain)} detailMono />
					</GroupedList>
					{@render dnsProviderStatus()}
				{/if}
			</section>
		{:else if tab === 'provider'}
			<section class="panel">
				{#if isAdmin}
					<div class="form-card">
						<p class="field-label">{m.tls_dns_provider_group()}</p>
						<p class="hint tight">{m.tls_dns_provider_hint()}</p>
						<Segmented
							options={dnsProviderOptions}
							bind:value={formDnsProvider}
							label={m.tls_dns_provider_label()}
						/>

						{#if formDnsProvider === 'cloudflare'}
							<label class="field-label" for="tls-cf-token">{m.tls_cf_token_label()}</label>
							<input
								id="tls-cf-token"
								class="field mono"
								type="password"
								autocomplete="off"
								placeholder={hasCloudflareToken
									? m.tls_cf_token_set()
									: m.tls_cf_token_detail()}
								disabled={formCfTokenClear}
								bind:value={formCfToken}
							/>
							<p class="hint tight">{m.tls_cf_token_hint()}</p>
							{#if hasCloudflareToken}
								<label class="entry-pick">
									<input
										type="checkbox"
										bind:checked={formCfTokenClear}
										onchange={() => {
											if (formCfTokenClear) formCfToken = '';
										}}
									/>
									<span>{m.tls_cf_token_clear()}</span>
								</label>
							{/if}

							<label class="field-label" for="tls-cf-zone">{m.tls_cf_zone_label()}</label>
							<input
								id="tls-cf-zone"
								class="field mono"
								bind:value={formCfZoneId}
								placeholder={m.tls_placeholder_optional()}
								autocomplete="off"
							/>
							<p class="hint tight">{m.tls_cf_zone_hint()}</p>

							<p class="field-label">{m.tls_cf_zones_label()}</p>
							<p class="hint tight">{m.tls_cf_zones_hint()}</p>
							{#each formCfZones as zone, index (index)}
								<div class="zone-row">
									<input
										class="field mono"
										aria-label={m.tls_cf_zones_name()}
										placeholder={m.tls_cf_zones_name()}
										value={zone.name}
										oninput={(event) => {
											const next = [...formCfZones];
											next[index] = {
												...next[index],
												name: (event.currentTarget as HTMLInputElement).value,
											};
											formCfZones = next;
										}}
									/>
									<input
										class="field mono"
										aria-label={m.tls_cf_zones_id()}
										placeholder={m.tls_cf_zones_id()}
										value={zone.zone_id}
										oninput={(event) => {
											const next = [...formCfZones];
											next[index] = {
												...next[index],
												zone_id: (event.currentTarget as HTMLInputElement).value,
											};
											formCfZones = next;
										}}
									/>
									<Button
										onclick={() => {
											formCfZones = formCfZones.filter((_, i) => i !== index);
										}}>{m.tls_cf_zones_remove()}</Button
									>
								</div>
							{/each}
							<Button
								onclick={() => {
									formCfZones = [...formCfZones, { name: '', zone_id: '' }];
								}}>{m.tls_cf_zones_add()}</Button
							>
						{:else if formDnsProvider === 'manual'}
							<p class="hint">{m.tls_cf_manual_hint()}</p>
						{:else}
							<p class="hint">{m.tls_cf_none_hint()}</p>
						{/if}
					</div>

					<div class="save-row">
						<Button variant="primary" disabled={busy} onclick={openConfirm}>{m.tls_save_config()}</Button>
					</div>
				{:else}
					{@render dnsProviderStatus()}
				{/if}
			</section>
		{:else}
			<section class="panel">
				<div class="banner-wrap">
					<Banner title={m.tls_dot_resolve_title()}>
						<p>{m.tls_dot_resolve_body()}</p>
					</Banner>
				</div>

				{#if isAdmin}
					{@render dnsProviderStatus()}

					<p class="hint tight">{m.tls_dyndns_detected_hint()}</p>
					<GroupedList header={m.tls_dyndns_detected_group()}>
						<GroupedRow
							label={m.tls_dyndns_last_v4()}
							detail={detectedV4 ?? m.tls_dyndns_detected_none()}
							detailMono={Boolean(detectedV4)}
						>
							{#snippet trailing()}
								<span class="tag">{publishTag(detectedV4, formPublishV4)}</span>
							{/snippet}
						</GroupedRow>
						<GroupedRow
							label={m.tls_dyndns_last_v6()}
							detail={detectedV6 ?? m.tls_dyndns_detected_none()}
							detailMono={Boolean(detectedV6)}
						>
							{#snippet trailing()}
								<span class="tag">{publishTag(detectedV6, formPublishV6)}</span>
							{/snippet}
						</GroupedRow>
						<GroupedRow
							label={m.tls_dyndns_last_change()}
							detail={formatRelative(data?.last_dyndns_success)}
						/>
					</GroupedList>

					<div class="form-card">
						<div class="switch-row">
							<div>
								<p class="switch-title">{m.tls_dyndns_enabled()}</p>
								<p class="hint tight">{m.tls_dyndns_enabled_hint()}</p>
							</div>
							<Switch bind:checked={formDyndnsEnabled} aria-label={m.tls_dyndns_enabled()} />
						</div>

						{#if hasClusterProfiles}
							<p class="field-label">{m.tls_dyndns_nodes_group()}</p>
							<p class="hint tight">{m.tls_dyndns_nodes_hint()}</p>
							<div class="node-dns-list" role="group" aria-label={m.tls_dyndns_nodes_group()}>
								{#each formNodeProfiles as profile (profile.node_id)}
									<div class="node-dns-row" class:node-dns-off={!profile.enabled}>
										<div class="node-dns-id">
											<span class="mono">{displayText(profile.node_id).text}</span>
											<div class="node-dns-toggles">
												<label class="entry-pick">
													<input
														type="checkbox"
														checked={profile.enabled}
														disabled={!formDyndnsEnabled}
														onchange={(event) =>
															patchProfile(profile.node_id, {
																enabled: (event.currentTarget as HTMLInputElement)
																	.checked,
															})}
													/>
													<span>{m.tls_dyndns_node_enabled()}</span>
												</label>
												<label class="entry-pick">
													<input
														type="radio"
														name="tls-public-entry"
														checked={profile.public_entry}
														disabled={!formDyndnsEnabled || !profile.enabled}
														onchange={() => setPublicEntryNode(profile.node_id)}
													/>
													<span>{m.tls_dyndns_node_entry()}</span>
												</label>
											</div>
										</div>
										<label class="sr-only" for={`tls-node-host-${profile.node_id}`}
											>{m.tls_dyndns_node_host_label()}</label
										>
										<input
											id={`tls-node-host-${profile.node_id}`}
											class="field mono"
											value={profile.hostname}
											placeholder={defaultHostnameFor(profile.node_id, domain)}
											autocomplete="off"
											disabled={!formDyndnsEnabled || !profile.enabled}
											oninput={(event) =>
												setProfileHostname(
													profile.node_id,
													(event.currentTarget as HTMLInputElement).value,
												)}
										/>
										<div class="node-family">
											<label class="entry-pick">
												<input
													type="checkbox"
													checked={profile.ipv4}
													disabled={!formDyndnsEnabled || !profile.enabled}
													onchange={(event) =>
														patchProfile(profile.node_id, {
															ipv4: (event.currentTarget as HTMLInputElement).checked,
														})}
												/>
												<span>{m.tls_dyndns_node_v4()}</span>
											</label>
											<label class="entry-pick">
												<input
													type="checkbox"
													checked={profile.ipv6}
													disabled={!formDyndnsEnabled || !profile.enabled}
													onchange={(event) =>
														patchProfile(profile.node_id, {
															ipv6: (event.currentTarget as HTMLInputElement).checked,
														})}
												/>
												<span>{m.tls_dyndns_node_v6()}</span>
											</label>
										</div>
										{#if profile.enabled && profile.ipv6 && formDyndnsEnabled}
											<div class="node-ipv6">
												<div class="ipv6-head">
													<p class="hint tight">{m.tls_dyndns_ipv6_hint()}</p>
													<button
														type="button"
														class="help-btn"
														aria-label={m.tls_dyndns_ipv6_help()}
														onclick={() => (ipv6HelpOpen = true)}
													>
														<Icon name="help-circle" size="1rem" />
													</button>
												</div>
												<div class="node-ipv6-modes" role="radiogroup" aria-label={m.tls_dyndns_ipv6_group()}>
													{#each ipv6ModeOptions as opt (opt.value)}
														<label class="entry-pick">
															<input
																type="radio"
																name={`tls-ipv6-mode-${profile.node_id}`}
																checked={profile.ipv6_mode === opt.value}
																onchange={() =>
																	patchProfile(profile.node_id, { ipv6_mode: opt.value })}
															/>
															<span>{opt.label}</span>
														</label>
													{/each}
												</div>
												<p class="hint tight">{ipv6ModeHint(profile.ipv6_mode)}</p>
												{#if profile.ipv6_mode === 'static'}
													<label class="sr-only" for={`tls-ipv6-static-${profile.node_id}`}
														>{m.tls_dyndns_ipv6_static_label()}</label
													>
													<input
														id={`tls-ipv6-static-${profile.node_id}`}
														class="field mono"
														value={profile.static_address}
														placeholder={m.tls_placeholder_ipv6()}
														autocomplete="off"
														oninput={(event) =>
															patchProfile(profile.node_id, {
																static_address: (event.currentTarget as HTMLInputElement)
																	.value,
															})}
													/>
												{:else}
													<label class="sr-only" for={`tls-ipv6-ifaces-${profile.node_id}`}
														>{m.tls_dyndns_ipv6_ifaces_label()}</label
													>
													<input
														id={`tls-ipv6-ifaces-${profile.node_id}`}
														class="field mono"
														value={profile.interfaces}
														placeholder={m.tls_placeholder_interfaces()}
														autocomplete="off"
														oninput={(event) =>
															patchProfile(profile.node_id, {
																interfaces: (event.currentTarget as HTMLInputElement).value,
															})}
													/>
													<p class="hint tight">{m.tls_dyndns_ipv6_ifaces_hint()}</p>
												{/if}
											</div>
										{/if}
									</div>
								{/each}
							</div>
						{:else}
							<div class="switch-row">
								<div>
									<p class="switch-title">{m.tls_dyndns_publish_v4()}</p>
									<p class="hint tight">{m.tls_dyndns_publish_v4_hint()}</p>
								</div>
								<Switch
									bind:checked={formPublishV4}
									disabled={!formDyndnsEnabled}
									aria-label={m.tls_dyndns_publish_v4()}
								/>
							</div>

							<div class="switch-row">
								<div>
									<p class="switch-title">{m.tls_dyndns_publish_v6()}</p>
									<p class="hint tight">{m.tls_dyndns_publish_v6_hint()}</p>
								</div>
								<Switch
									bind:checked={formPublishV6}
									disabled={!formDyndnsEnabled}
									aria-label={m.tls_dyndns_publish_v6()}
								/>
							</div>

							<label class="field-label" for="tls-dyndns-host">{m.tls_dyndns_host_label()}</label>
							<input
								id="tls-dyndns-host"
								class="field mono"
								bind:value={formDyndnsHost}
								placeholder={nodeHostHint}
								autocomplete="off"
							/>
							<p class="hint">{m.tls_dyndns_host_hint({ example: nodeHostHint })}</p>
							<p class="hint tight">{m.tls_dyndns_nodes_solo()}</p>

							<div class="switch-row">
								<div>
									<p class="switch-title">{m.tls_public_entry_label()}</p>
									<p class="hint tight">{m.tls_public_entry_hint()}</p>
								</div>
								<Switch bind:checked={formPublicEntry} aria-label={m.tls_public_entry_label()} />
							</div>
						{/if}

						{#if showStandaloneIpv6Options}
							<div class="ipv6-head">
								<p class="field-label">{m.tls_dyndns_ipv6_group()}</p>
								<button
									type="button"
									class="help-btn"
									aria-label={m.tls_dyndns_ipv6_help()}
									onclick={() => (ipv6HelpOpen = true)}
								>
									<Icon name="help-circle" size="1rem" />
								</button>
							</div>
							<p class="hint tight">{m.tls_dyndns_ipv6_hint()}</p>
							<Segmented
								options={ipv6ModeOptions}
								bind:value={formIpv6Mode}
								label={m.tls_dyndns_ipv6_group()}
							/>
							<p class="hint tight">{ipv6ModeHint(formIpv6Mode)}</p>
							{#if formIpv6Mode === 'static'}
								<label class="field-label" for="tls-ipv6-static"
									>{m.tls_dyndns_ipv6_static_label()}</label
								>
								<input
									id="tls-ipv6-static"
									class="field mono"
									bind:value={formIpv6Static}
									placeholder={m.tls_placeholder_ipv6()}
									autocomplete="off"
								/>
							{:else}
								<label class="field-label" for="tls-ipv6-ifaces"
									>{m.tls_dyndns_ipv6_ifaces_label()}</label
								>
								<input
									id="tls-ipv6-ifaces"
									class="field mono"
									bind:value={formIpv6Interfaces}
									placeholder={m.tls_placeholder_interfaces()}
									autocomplete="off"
								/>
								<p class="hint tight">{m.tls_dyndns_ipv6_ifaces_hint()}</p>
							{/if}
						{/if}

						<div class="meta-row">
							<span>{m.tls_dyndns_proxied_label()}</span>
							<span class="mono muted">{m.tls_dyndns_proxied_value()}</span>
						</div>
					</div>

					{#if domain}
						<p class="records-lead">{m.tls_records_lead({ domain })}</p>
						<GroupedList header={m.tls_records_group()}>
							{#each expectedNodeHosts as node (node.hostname)}
								<GroupedRow
									label={node.hostname}
									detail={node.self ? m.tls_record_node_meta() : m.tls_record_node_peer()}
									detailMono
								>
									{#snippet trailing()}
										<span class="tag">{m.tls_record_tag_dyndns()}</span>
									{/snippet}
								</GroupedRow>
							{/each}
							<GroupedRow
								label={`dns.${domain}`}
								detail={entryHostname
									? m.tls_record_apex_meta({ target: entryHostname })
									: m.tls_record_apex_other()}
								detailMono
							>
								{#snippet trailing()}
									<span class="tag">{m.tls_record_tag_cname()}</span>
								{/snippet}
							</GroupedRow>
							<GroupedRow
								label={`*.dns.${domain}`}
								detail={entryHostname
									? m.tls_record_wild_meta({ target: entryHostname })
									: m.tls_record_wild_other()}
								detailMono
							>
								{#snippet trailing()}
									<span class="tag">{m.tls_record_tag_cname()}</span>
								{/snippet}
							</GroupedRow>
							<GroupedRow
								label={`<id>.dns.${domain}`}
								detail={m.tls_record_client_meta()}
								detailMono
							>
								{#snippet trailing()}
									<span class="tag">{m.tls_record_tag_dot()}</span>
								{/snippet}
							</GroupedRow>
							<GroupedRow
								label={`_acme-challenge.dns.${domain}`}
								detail={m.tls_record_challenge_meta()}
								detailMono
							>
								{#snippet trailing()}
									<span class="tag">{m.tls_record_tag_acme()}</span>
								{/snippet}
							</GroupedRow>
						</GroupedList>
					{/if}

					<GroupedList header={m.tls_actions_group()}>
						<GroupedRow label={m.tls_action_dyndns()} detail={m.tls_action_dyndns_detail()}>
							{#snippet trailing()}
								<Button disabled={busy} onclick={() => void runAction(triggerDyndns)}
									>{m.tls_run()}</Button
								>
							{/snippet}
						</GroupedRow>
					</GroupedList>

					<div class="save-row">
						<Button variant="primary" disabled={busy} onclick={openConfirm}>{m.tls_save_config()}</Button>
					</div>
				{:else}
					{@render dnsProviderStatus()}
					<GroupedList header={m.tls_dyndns_status_group()}>
						<GroupedRow
							label={m.tls_dyndns_host_label()}
							detail={asText(objectField(tlsConfig, 'dyndns').hostname)}
							detailMono
						/>
						<GroupedRow
							label={m.tls_public_entry_label()}
							detail={objectField(tlsConfig, 'dyndns').public_entry === true
								? m.tls_public_entry_yes()
								: m.tls_public_entry_no()}
						/>
					</GroupedList>
				{/if}
			</section>
		{/if}

		<p class="footnote">{m.tls_private_key_never()}</p>
	{/if}
</div>

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

{#if ipv6HelpOpen}
	<Sheet open={true} title={m.tls_dyndns_ipv6_help_title()} onclose={() => (ipv6HelpOpen = false)}>
		<p class="hint">{m.tls_dyndns_ipv6_help_lead()}</p>
		<GroupedList>
			<GroupedRow
				label={m.tls_dyndns_ipv6_help_eui64_title()}
				detail={m.tls_dyndns_ipv6_help_eui64_body()}
			/>
			<GroupedRow
				label={m.tls_dyndns_ipv6_help_stable_title()}
				detail={m.tls_dyndns_ipv6_help_stable_body()}
			/>
			<GroupedRow
				label={m.tls_dyndns_ipv6_help_static_title()}
				detail={m.tls_dyndns_ipv6_help_static_body()}
			/>
			<GroupedRow
				label={m.tls_dyndns_ipv6_help_ifaces_title()}
				detail={m.tls_dyndns_ipv6_help_ifaces_body()}
			/>
		</GroupedList>
		<div class="actions">
			<Button variant="primary" onclick={() => (ipv6HelpOpen = false)}>{m.action_close()}</Button>
		</div>
	</Sheet>
{/if}

{#if confirmOpen}
	<Sheet open={true} title={m.tls_confirm_title()} onclose={() => (confirmOpen = false)}>
		<div class="banner-wrap">
			<Banner title={m.tls_confirm_banner_title()}>
				<p>{m.tls_confirm_banner_body()}</p>
			</Banner>
		</div>
		<GroupedList>
			<GroupedRow label={m.tls_public_domain_label()} detail={formDomain.trim() || dash()} detailMono />
			<GroupedRow label={m.tls_source_label()} detail={sourceOptions.find((o) => o.value === formSource)?.label ?? formSource} />
			<GroupedRow
				label={m.tls_dyndns_enabled()}
				detail={formDyndnsEnabled
					? [
							formPublishV4 ? m.tls_dyndns_publish_v4() : null,
							formPublishV6 ? m.tls_dyndns_publish_v6() : null,
						]
							.filter(Boolean)
							.join(' · ') || m.tls_dyndns_opted_out()
					: m.tls_dyndns_opted_out()}
			/>
			{#if hasClusterProfiles}
				{#each formNodeProfiles as profile (profile.node_id)}
					<GroupedRow
						label={profile.node_id}
						detail={[
							profile.hostname || dash(),
							profile.enabled ? null : m.tls_dyndns_opted_out(),
							profile.enabled && profile.ipv4 ? m.tls_dyndns_node_v4() : null,
							profile.enabled && profile.ipv6 ? m.tls_dyndns_node_v6() : null,
							profile.public_entry ? m.tls_dyndns_node_entry() : null,
						]
							.filter(Boolean)
							.join(' · ')}
						detailMono
					/>
				{/each}
			{:else}
				<GroupedRow label={m.tls_dyndns_host_label()} detail={formDyndnsHost.trim() || dash()} detailMono />
				<GroupedRow
					label={m.tls_public_entry_label()}
					detail={formPublicEntry ? m.tls_public_entry_yes() : m.tls_public_entry_no()}
				/>
			{/if}
			{#if data?.fingerprint_sha256}
				<GroupedRow
					label={m.tls_fingerprint_label()}
					detail={formatFingerprint(data.fingerprint_sha256)}
					detailMono
				/>
			{/if}
		</GroupedList>
		<div class="actions">
			<Button onclick={() => (confirmOpen = false)}>{m.action_cancel()}</Button>
			<Button variant="primary" disabled={busy} onclick={() => void saveConfig()}>
				{m.tls_confirm_apply()}
			</Button>
		</div>
	</Sheet>
{/if}

<style>
	.tls {
		display: flex;
		flex-direction: column;
		gap: 1rem;
		max-width: 44rem;
	}

	.lead {
		margin: 0;
		color: var(--label-2);
		font-size: 0.9375rem;
		line-height: 1.35;
	}

	.banner-wrap {
		margin: 0;
	}

	.fp {
		margin: 0.5rem 0 0;
		font-size: 0.8125rem;
		overflow-wrap: anywhere;
	}

	.notice {
		margin: 0;
	}

	.state,
	.footnote,
	.hint {
		margin: 0;
		color: var(--label-2);
		font-size: 0.84375rem;
		line-height: 1.35;
	}

	.hint.tight {
		margin-top: 0.125rem;
	}

	.tabs :global(.segmented) {
		width: 100%;
	}

	.panel {
		display: flex;
		flex-direction: column;
		gap: 1.125rem;
	}

	.section-label {
		margin: 0;
		font-size: 0.8125rem;
		color: var(--label-2);
	}

	.form-card {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
		padding: 0.875rem 1rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-card);
		background: var(--surface);
	}

	.zone-row {
		display: grid;
		grid-template-columns: 1fr 1fr auto;
		gap: 0.5rem;
		align-items: center;
	}

	.node-dns-list {
		overflow: hidden;
		margin: 0.25rem 0 0.5rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		background: var(--surface-2);
	}

	.node-dns-row {
		display: flex;
		flex-direction: column;
		gap: 0.375rem;
		padding: 0.625rem 0.75rem;
	}

	.node-dns-row + .node-dns-row {
		border-top: 1px solid var(--separator);
	}

	.node-dns-id {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 0.75rem;
		flex-wrap: wrap;
	}

	.node-dns-toggles,
	.node-family {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 0.75rem;
	}

	.node-dns-off {
		opacity: 0.55;
	}

	.node-ipv6 {
		display: flex;
		flex-direction: column;
		gap: 0.375rem;
		margin-top: 0.25rem;
	}

	.node-ipv6-modes {
		display: flex;
		flex-wrap: wrap;
		gap: 0.75rem;
	}

	.ipv6-head {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 0.5rem;
	}

	.ipv6-head .field-label {
		margin: 0;
	}

	.ipv6-head .hint {
		flex: 1;
		margin: 0;
	}

	.help-btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 2rem;
		height: 2rem;
		padding: 0;
		border: none;
		border-radius: var(--r-ctl);
		background: transparent;
		color: var(--label-2);
		cursor: pointer;
	}

	.help-btn:hover,
	.help-btn:focus-visible {
		color: var(--label);
		background: var(--surface-2);
	}

	.entry-pick {
		display: inline-flex;
		align-items: center;
		gap: 0.375rem;
		font-size: 0.8125rem;
		color: var(--label-2);
		cursor: pointer;
	}

	.entry-pick input {
		accent-color: var(--accent-solid);
	}

	.sr-only {
		position: absolute;
		width: 1px;
		height: 1px;
		padding: 0;
		margin: -1px;
		overflow: hidden;
		clip: rect(0, 0, 0, 0);
		white-space: nowrap;
		border: 0;
	}

	.field-label {
		display: block;
		margin: 0.5rem 0 0.25rem;
		font-size: 0.8125rem;
		color: var(--label-2);
	}

	.field-label:first-child {
		margin-top: 0;
	}

	.field {
		box-sizing: border-box;
		width: 100%;
		min-height: 2.75rem;
		padding: 0.5rem 0.75rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		background: var(--canvas);
		color: var(--label);
		font: inherit;
	}

	.mono,
	.field.mono,
	.area.mono {
		font-family: var(--font-mono, ui-monospace, SFMono-Regular, Menlo, monospace);
	}

	.sans-list {
		margin: 0;
		padding: 0.5rem 0.75rem;
		list-style: none;
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		background: var(--surface-2);
		font-size: 0.875rem;
		color: var(--label-2);
	}

	.sans-list li + li {
		margin-top: 0.25rem;
	}

	.switch-row,
	.meta-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 1rem;
		min-height: 2.75rem;
	}

	.switch-title {
		margin: 0;
		font-size: 0.9375rem;
		font-weight: 500;
		color: var(--label);
	}

	.meta-row {
		margin-top: 0.5rem;
		padding-top: 0.75rem;
		border-top: 1px solid var(--separator);
		font-size: 0.84375rem;
		color: var(--label-2);
	}

	.muted {
		color: var(--label-3);
		text-align: end;
	}

	.records-lead {
		margin: 0;
		color: var(--label-2);
		font-size: 0.875rem;
		line-height: 1.4;
	}

	.tag {
		display: inline-flex;
		align-items: center;
		min-height: 1.5rem;
		padding: 0 0.45rem;
		border: 1px solid var(--separator);
		border-radius: 999px;
		font-size: 0.6875rem;
		font-weight: 600;
		color: var(--label-2);
		white-space: nowrap;
	}

	.save-row {
		display: flex;
		justify-content: flex-end;
	}

	.area {
		box-sizing: border-box;
		width: 100%;
		margin-bottom: 1rem;
		padding: 0.5rem 0.75rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
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
