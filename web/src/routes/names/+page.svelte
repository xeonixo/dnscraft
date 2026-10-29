<script lang="ts">
	import { onMount } from 'svelte';
	import { SvelteMap, SvelteSet } from 'svelte/reactivity';
	import { resolve } from '$app/paths';
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import Icon from '$lib/components/Icon.svelte';
	import ResultNotice from '$lib/components/ResultNotice.svelte';
	import Sheet from '$lib/components/Sheet.svelte';
	import UnavailableNotice from '$lib/components/UnavailableNotice.svelte';
	import {
		attachDomainZone,
		detachDomainZone,
		findMatchingRecord,
		isInventoryDnsName,
		listAllDomainZoneRecords,
		listDomainZoneRecords,
		listDomainZones,
		normalizeDnsName,
		parseTtlInput,
		PUBLIC_RECORD_TYPES,
		CF_TTL_AUTO,
		ttlLabel,
		supportsProxied,
		upsertPublicRecord,
		zoneForName,
		type DomainZone,
		type DomainZoneRecord,
	} from '$lib/api/domain-zones';
	import { zoneOfName } from '$lib/names-zones';
	import {
		deleteRecord,
		listRecords,
		listViews,
		saveRecord,
		type PolicyRecord,
		type PolicyView,
	} from '$lib/api/policy';
	import { ApiError } from '$lib/api/client';
	import { failureOf, settle, type Result } from '$lib/api/result';
	import { auth } from '$lib/auth/state.svelte';
	import Switch from '$lib/components/Switch.svelte';
	import { toDomainName } from '$lib/domain-name';
	import { parseIp } from '$lib/policy/cidr';
	import { domainLabel } from '$lib/policy/display';
	import { displayText } from '$lib/safe-text';
	import { m } from '$lib/paraglide/messages';

	const RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'TXT', 'SRV', 'MX', 'PTR'];
	const isAdmin = $derived(auth.role === 'admin');
	let result = $state<Result<PolicyRecord[]>>({ kind: 'loading' });
	let views = $state<PolicyView[]>([]);
	let attachedZones = $state<DomainZone[]>([]);
	let hasCloudflareToken = $state(false);
	let domainZonesReady = $state(false);
	let sheetOpen = $state(false);
	let zonesSheetOpen = $state(false);
	let confirmDelete = $state(false);
	let busy = $state(false);
	let zonesBusy = $state(false);
	let failure = $state<{ code: string; params: Record<string, unknown> } | null>(null);
	let zonesFailure = $state<{ code: string; params: Record<string, unknown> } | null>(null);
	let editing = $state<PolicyRecord | null>(null);
	let query = $state('');
	let formName = $state('');
	let formType = $state('A');
	let formTtl = $state('60');
	let formRdata = $state('');
	let formPublicContent = $state('');
	let formPublicProxied = $state(false);
	/** Snapshot of public fields when the lookup finished — detects Öffentlich dirty. */
	let publicBaseline = $state<{
		content: string;
		proxied: boolean;
		ttl: string;
		recordId: string | null;
	}>({
		content: '',
		proxied: false,
		ttl: '60',
		recordId: null,
	});

	/** One editable deviation row. `noAnswer` → empty override string (NODATA). */
	type OverrideRow = { key: number; view: string; value: string; noAnswer: boolean };
	let overrideRows = $state<OverrideRow[]>([]);
	let nextOverrideKey = 0;

	type PublicLookup =
		| { kind: 'idle' }
		| { kind: 'loading' }
		| { kind: 'token_missing' }
		| { kind: 'unavailable' }
		| { kind: 'internal' }
		| { kind: 'absent' }
		| { kind: 'found'; record: DomainZoneRecord }
		| { kind: 'error'; code: string };

	let publicLookup = $state<PublicLookup>({ kind: 'idle' });
	let publicLookupSeq = 0;
	/** Cached CF records by attached zone id (sheet lookups). */
	const recordsByZone = new SvelteMap<string, DomainZoneRecord[]>();
	/** name+type keys known to have a public CF match (list badge). */
	let publicKeys = new SvelteSet<string>();
	/** Zone filter from `?zone=` (empty = all zones). */
	let zoneKey = $state('');
	let cloudflareLoading = $state(false);
	let cloudflareFailed = $state(false);

	let discoverableZones = $state<DomainZone[]>([]);
	let zonesDiscoverReady = $state(false);

	const rows = $derived(result.kind === 'ok' ? result.data : []);

	type NameRow = {
		key: string;
		owner: string;
		type: string;
		/** Zone apex, or a derived local zone (`.lan`, `10.20.172.in-addr.arpa`). */
		zone: string;
		ttl: number;
		rdata: string;
		local: PolicyRecord | null;
		/** Cloudflare-only record (no local record with the same owner and type). */
		cf: DomainZoneRecord | null;
	};

	/** Local records plus the Cloudflare-only records of every loaded attached zone. */
	const allRows = $derived.by(() => {
		const out: NameRow[] = [];
		const seen = new SvelteSet<string>();
		for (const record of rows) {
			const key = recordKey(record.name, record.type);
			seen.add(key);
			out.push({
				key,
				owner: record.name,
				type: record.type,
				zone: zoneOfName(attachedZones, record.name).name,
				ttl: record.ttl,
				rdata: record.rdata,
				local: record,
				cf: null,
			});
		}
		for (const zone of attachedZones) {
			const cfRecords = zone.id ? recordsByZone.get(zone.id) : undefined;
			if (!cfRecords) continue;
			for (const cf of cfRecords) {
				if (zoneForName(attachedZones, cf.name)?.id !== zone.id) continue;
				const key = recordKey(cf.name, cf.record_type);
				if (seen.has(key)) continue;
				seen.add(key);
				out.push({
					key,
					owner: cf.name.replace(/\.+$/, ''),
					type: cf.record_type.toUpperCase(),
					zone: normalizeDnsName(zone.name),
					ttl: cf.ttl,
					rdata: cf.content,
					local: null,
					cf,
				});
			}
		}
		return out;
	});

	/** Attached zones (always) plus derived local zones, alphabetical. Counts are rows in the zone. */
	const zoneChips = $derived.by(() => {
		const byName = new SvelteMap<string, { name: string; attached: boolean; count: number }>();
		for (const zone of attachedZones) {
			const name = normalizeDnsName(zone.name);
			byName.set(name, { name, attached: true, count: 0 });
		}
		for (const row of allRows) {
			const chip = byName.get(row.zone) ?? { name: row.zone, attached: false, count: 0 };
			chip.count += 1;
			byName.set(row.zone, chip);
		}
		return [...byName.values()].sort((a, b) => a.name.localeCompare(b.name));
	});

	const activeZone = $derived(zoneChips.some((chip) => chip.name === zoneKey) ? zoneKey : '');

	/** One card per owner (sorted); A/AAAA for the same name stay together. */
	const groups = $derived.by(() => {
		const needle = query.trim().toLowerCase();
		const byOwner = new SvelteMap<string, { name: string; records: NameRow[] }>();
		for (const row of allRows) {
			if (activeZone !== '' && row.zone !== activeZone) continue;
			if (needle && !`${row.owner} ${row.type} ${row.rdata}`.toLowerCase().includes(needle)) {
				continue;
			}
			const owner = normalizeDnsName(row.owner);
			const group = byOwner.get(owner) ?? { name: row.owner, records: [] };
			group.records.push(row);
			byOwner.set(owner, group);
		}
		return [...byOwner.entries()]
			.sort(([a], [b]) => a.localeCompare(b))
			.map(([, group]) => ({
				name: group.name,
				records: group.records.sort((a, b) => a.type.localeCompare(b.type)),
			}));
	});

	const canAddOverride = $derived(
		views.some((view) => !overrideRows.some((row) => row.view === view.id)),
	);

	const publicTypeSupported = $derived(
		(PUBLIC_RECORD_TYPES as readonly string[]).includes(formType.trim().toUpperCase()),
	);

	/** Attached zone + supported type: Öffentlich is the single answer field. */
	const showPublicAnswer = $derived(
		publicTypeSupported && (publicLookup.kind === 'found' || publicLookup.kind === 'absent'),
	);

	const publicEditable = $derived(isAdmin && showPublicAnswer);

	const publicDirty = $derived(
		publicEditable &&
			(formPublicContent.trim() !== publicBaseline.content ||
				formPublicProxied !== publicBaseline.proxied ||
				ttlWrite(formTtl) !== ttlWrite(publicBaseline.ttl)),
	);

	const showPublicClearHint = $derived(publicEditable && publicBaseline.recordId !== null);

	const showProxiedWarn = $derived(
		publicEditable &&
			formPublicProxied &&
			supportsProxied(formType) &&
			isInventoryDnsName(
				formName,
				attachedZones.map((zone) => zone.name),
			),
	);

	const inheritPlaceholder = $derived(
		publicLookup.kind === 'found' ||
			(publicLookup.kind === 'absent' && formPublicContent.trim() !== '')
			? m.names_overrides_inherit_public()
			: m.names_overrides_inherit_standard(),
	);

	const overridesEmptyText = $derived(
		publicLookup.kind === 'found' || formPublicContent.trim() !== ''
			? m.names_overrides_empty()
			: m.names_overrides_empty_standard(),
	);

	const sheetTitle = $derived(
		!isAdmin ? m.names_view_title() : editing ? m.names_edit_title() : m.names_add_title(),
	);

	const attachCandidates = $derived.by(() => {
		const attachedNames = new SvelteSet(attachedZones.map((zone) => normalizeDnsName(zone.name)));
		return discoverableZones.filter((zone) => !attachedNames.has(normalizeDnsName(zone.name)));
	});

	async function loadDomainZones(discover = false): Promise<void> {
		const zonesResult = await settle(listDomainZones({ discover: discover && isAdmin }));
		if (zonesResult.kind === 'ok') {
			attachedZones = zonesResult.data.zones;
			hasCloudflareToken = zonesResult.data.has_cloudflare_token;
			if (discover) {
				discoverableZones = zonesResult.data.discoverable ?? [];
				zonesDiscoverReady = true;
			}
			domainZonesReady = true;
			recordsByZone.clear();
			await loadCloudflareRecords();
			await refreshPublicBadges(rows);
		} else if (zonesResult.kind === 'unavailable') {
			attachedZones = [];
			hasCloudflareToken = false;
			domainZonesReady = true;
			if (discover) {
				discoverableZones = [];
				zonesDiscoverReady = true;
			}
			publicKeys.clear();
		} else {
			attachedZones = [];
			hasCloudflareToken = false;
			domainZonesReady = true;
			if (discover) {
				discoverableZones = [];
				zonesDiscoverReady = true;
				if (zonesResult.kind === 'error') {
					zonesFailure = { code: zonesResult.code, params: zonesResult.params ?? {} };
				}
			}
			publicKeys.clear();
		}
	}

	async function openZonesSheet(): Promise<void> {
		if (!isAdmin) return;
		zonesFailure = null;
		zonesSheetOpen = true;
		zonesDiscoverReady = false;
		await loadDomainZones(true);
	}

	function closeZonesSheet(): void {
		zonesSheetOpen = false;
		zonesFailure = null;
	}

	async function attachZone(zone: DomainZone): Promise<void> {
		if (!isAdmin) return;
		zonesBusy = true;
		zonesFailure = null;
		try {
			await attachDomainZone({
				name: zone.name,
				zone_id: zone.id ?? undefined,
			});
			recordsByZone.clear();
			await loadDomainZones(true);
		} catch (cause) {
			zonesFailure = failureOf(cause);
		} finally {
			zonesBusy = false;
		}
	}

	async function detachZone(zone: DomainZone): Promise<void> {
		if (!isAdmin || zone.source === 'public_domain') return;
		zonesBusy = true;
		zonesFailure = null;
		try {
			await detachDomainZone(zone.name);
			recordsByZone.clear();
			await loadDomainZones(true);
		} catch (cause) {
			zonesFailure = failureOf(cause);
		} finally {
			zonesBusy = false;
		}
	}

	function applyPublicBaseline(record: DomainZoneRecord | null): void {
		if (record) {
			formPublicContent = record.content;
			formPublicProxied = record.proxied;
			formTtl = ttlFieldFor(record.ttl);
			publicBaseline = {
				content: record.content,
				proxied: record.proxied,
				ttl: ttlFieldFor(record.ttl),
				recordId: record.id,
			};
		} else {
			formPublicContent = '';
			formPublicProxied = false;
			publicBaseline = {
				content: '',
				proxied: false,
				ttl: formTtl,
				recordId: null,
			};
		}
	}

	/** All records of a zone (cached); with `nameSubstr`, one search page for the sheet lookup. */
	async function recordsForZone(zoneId: string, nameSubstr?: string): Promise<DomainZoneRecord[]> {
		if (nameSubstr == null) {
			const cached = recordsByZone.get(zoneId);
			if (cached) return cached;
			const all = await listAllDomainZoneRecords(zoneId);
			recordsByZone.set(zoneId, all);
			return all;
		}
		const page = await listDomainZoneRecords(zoneId, {
			per_page: 100,
			name_substr: nameSubstr,
		});
		return page.records;
	}

	/** Loads every record of every attached zone that is not cached yet. */
	async function loadCloudflareRecords(): Promise<void> {
		if (!hasCloudflareToken) return;
		const ids = attachedZones
			.map((zone) => zone.id)
			.filter((id): id is string => id !== null && !recordsByZone.has(id));
		if (ids.length === 0) return;
		cloudflareLoading = true;
		cloudflareFailed = false;
		await Promise.all(
			ids.map(async (id) => {
				try {
					await recordsForZone(id);
				} catch {
					cloudflareFailed = true;
				}
			}),
		);
		cloudflareLoading = false;
	}

	function recordKey(name: string, type: string): string {
		return `${normalizeDnsName(name)}\0${type.trim().toUpperCase()}`;
	}

	async function refreshPublicBadges(records: PolicyRecord[]): Promise<void> {
		if (!hasCloudflareToken || attachedZones.length === 0) {
			publicKeys.clear();
			return;
		}
		const next = new SvelteSet<string>();
		const byZone = new SvelteMap<string, PolicyRecord[]>();
		for (const record of records) {
			const zone = zoneForName(attachedZones, record.name);
			if (!zone?.id) continue;
			const list = byZone.get(zone.id) ?? [];
			list.push(record);
			byZone.set(zone.id, list);
		}
		await Promise.all(
			[...byZone.entries()].map(async ([zoneId, zoneRecords]) => {
				try {
					const cfRecords = await recordsForZone(zoneId);
					for (const record of zoneRecords) {
						if (findMatchingRecord(cfRecords, record.name, record.type)) {
							next.add(recordKey(record.name, record.type));
						}
					}
				} catch {
					/* list badges are best-effort */
				}
			}),
		);
		publicKeys.clear();
		for (const key of next) publicKeys.add(key);
	}

	async function refreshPublicLookup(): Promise<void> {
		const seq = ++publicLookupSeq;
		const name = formName.trim();
		if (name === '') {
			publicLookup = { kind: 'idle' };
			return;
		}
		if (!domainZonesReady) {
			publicLookup = { kind: 'loading' };
			return;
		}
		if (!hasCloudflareToken) {
			publicLookup = { kind: 'token_missing' };
			return;
		}
		const zone = zoneForName(attachedZones, name);
		if (!zone) {
			publicLookup = { kind: 'internal' };
			return;
		}
		if (!zone.id) {
			publicLookup = { kind: 'token_missing' };
			return;
		}
		if (!(PUBLIC_RECORD_TYPES as readonly string[]).includes(formType.trim().toUpperCase())) {
			publicLookup = { kind: 'internal' };
			return;
		}
		publicLookup = { kind: 'loading' };
		try {
			const records = await recordsForZone(zone.id, normalizeDnsName(name));
			if (seq !== publicLookupSeq) return;
			const match = findMatchingRecord(records, name, formType);
			publicLookup = match ? { kind: 'found', record: match } : { kind: 'absent' };
			applyPublicBaseline(match);
		} catch (cause) {
			if (seq !== publicLookupSeq) return;
			if (cause instanceof ApiError && cause.code === 'tls.secret.missing') {
				publicLookup = { kind: 'token_missing' };
				return;
			}
			if (
				cause instanceof ApiError &&
				(cause.status === 404 || cause.code === 'control_api.not_ready')
			) {
				publicLookup = { kind: 'unavailable' };
				return;
			}
			publicLookup = {
				kind: 'error',
				code: cause instanceof ApiError ? cause.code : 'client.malformed',
			};
		}
	}

	async function load(): Promise<void> {
		const [records, vws] = await Promise.all([settle(listRecords()), settle(listViews())]);
		result = records;
		if (vws.kind === 'ok') views = vws.data;
		if (records.kind === 'ok' && domainZonesReady) {
			await loadCloudflareRecords();
			await refreshPublicBadges(records.data);
		}
	}

	let submitted = $state(false);

	const ownerError = $derived.by(() => {
		if (editing) return null;
		const name = formName.trim();
		if (name === '') return submitted ? m.names_owner_required() : null;
		return toDomainName(name.replace(/^\*\./, '')) ? null : m.names_owner_invalid();
	});

	function validateRdata(data: string, required: boolean): string | null {
		if (data === '') return required && submitted ? m.names_rdata_required() : null;
		if (data === '') return null;
		if (formType === 'A') return parseIp(data)?.family === 4 ? null : m.names_rdata_ipv4();
		if (formType === 'AAAA') return parseIp(data)?.family === 6 ? null : m.names_rdata_ipv6();
		if (formType === 'CNAME' || formType === 'PTR') {
			return toDomainName(data) ? null : m.names_rdata_name();
		}
		return null;
	}

	const rdataError = $derived.by(() => {
		// When Öffentlich is editable and non-empty, local default aligns to it on save.
		const data =
			publicEditable && formPublicContent.trim() !== ''
				? formPublicContent.trim()
				: formRdata.trim();
		const required = !(
			(publicEditable && formPublicContent.trim() === '' && publicBaseline.recordId) ||
			Object.values(overridesFromRows(overrideRows)).some((value) => value !== '')
		);
		return validateRdata(
			data,
			required || formRdata.trim() !== '' || formPublicContent.trim() !== '',
		);
	});

	const publicContentError = $derived.by(() => {
		if (!publicEditable) return null;
		const data = formPublicContent.trim();
		if (data === '') return null;
		return validateRdata(data, false);
	});

	function rowsFromOverrides(map: Record<string, string>): OverrideRow[] {
		return Object.entries(map).map(([view, value]) => ({
			key: nextOverrideKey++,
			view,
			value,
			noAnswer: value === '',
		}));
	}

	/**
	 * Missing key = inherit. Empty string = no answer (NODATA). Non-empty = replacement.
	 * Rows without a view, or with neither value nor noAnswer, are dropped (inherit).
	 */
	function overridesFromRows(list: OverrideRow[]): Record<string, string> {
		const map: Record<string, string> = {};
		for (const row of list) {
			const view = row.view.trim();
			if (view === '') continue;
			if (row.noAnswer) {
				map[view] = '';
				continue;
			}
			const value = row.value.trim();
			if (value === '') continue;
			map[view] = value;
		}
		return map;
	}

	function viewOptionsFor(row: OverrideRow): string[] {
		const taken = new SvelteSet(
			overrideRows.filter((other) => other.key !== row.key && other.view !== '').map((o) => o.view),
		);
		const ids = new SvelteSet(views.map((view) => view.id));
		if (row.view !== '') ids.add(row.view);
		return [...ids].filter((id) => !taken.has(id)).sort((a, b) => a.localeCompare(b));
	}

	function addOverrideRow(): void {
		const taken = new SvelteSet(overrideRows.map((row) => row.view));
		const next = views.find((view) => !taken.has(view.id));
		if (!next) return;
		overrideRows = [
			...overrideRows,
			{ key: nextOverrideKey++, view: next.id, value: '', noAnswer: false },
		];
	}

	function removeOverrideRow(key: number): void {
		overrideRows = overrideRows.filter((row) => row.key !== key);
	}

	function openCreate(): void {
		editing = null;
		formName = '';
		formType = 'A';
		formTtl = '60';
		formRdata = '';
		formPublicContent = '';
		formPublicProxied = false;
		publicBaseline = { content: '', proxied: false, ttl: '60', recordId: null };
		overrideRows = [];
		confirmDelete = false;
		failure = null;
		submitted = false;
		publicLookup = { kind: 'idle' };
		sheetOpen = true;
	}

	function openEdit(record: PolicyRecord): void {
		editing = record;
		formName = record.name;
		formType = record.type;
		formTtl = String(record.ttl);
		formRdata = record.rdata;
		formPublicContent = '';
		formPublicProxied = false;
		publicBaseline = {
			content: '',
			proxied: false,
			ttl: String(record.ttl),
			recordId: null,
		};
		overrideRows = rowsFromOverrides(record.overrides);
		confirmDelete = false;
		failure = null;
		submitted = false;
		sheetOpen = true;
		void refreshPublicLookup();
	}

	/** TTL as shown in the editor: Cloudflare Auto (1) reads as the localized label. */
	function ttlFieldFor(ttl: number): string {
		return ttlLabel(ttl, m.names_ttl_auto());
	}

	/** TTL sent to Cloudflare; Auto stays 1. */
	function ttlWrite(text: string): number {
		return parseTtlInput(text, m.names_ttl_auto()) ?? 60;
	}

	/** Local records need real seconds: Auto mirrors as 60. */
	function localTtl(text: string): number {
		const ttl = ttlWrite(text);
		return ttl === CF_TTL_AUTO ? 60 : ttl;
	}

	/** Cloudflare-only record: the editor opens as a create flow; viewers get the read-only sheet. */
	function openPublicOnly(record: DomainZoneRecord): void {
		editing = null;
		formName = record.name.replace(/\.+$/, '');
		formType = record.record_type.toUpperCase();
		formTtl = ttlFieldFor(record.ttl);
		formRdata = record.content;
		formPublicContent = '';
		formPublicProxied = false;
		publicBaseline = { content: '', proxied: false, ttl: formTtl, recordId: null };
		overrideRows = [];
		confirmDelete = false;
		failure = null;
		submitted = false;
		publicLookup = { kind: 'idle' };
		sheetOpen = true;
		void refreshPublicLookup();
	}

	function openRow(row: NameRow): void {
		if (row.local) openEdit(row.local);
		else if (row.cf) openPublicOnly(row.cf);
	}

	/** Only types the editor knows can be opened; other Cloudflare-only types stay read-only. */
	function canOpen(row: NameRow): boolean {
		return row.local !== null || (row.cf !== null && RECORD_TYPES.includes(row.type));
	}

	function setZone(key: string): void {
		zoneKey = key;
		const url = new URL(window.location.href);
		if (key) url.searchParams.set('zone', key);
		else url.searchParams.delete('zone');
		window.history.replaceState(window.history.state, '', url);
	}

	function closeSheet(): void {
		sheetOpen = false;
		confirmDelete = false;
		publicLookupSeq += 1;
		publicLookup = { kind: 'idle' };
	}

	function onPublicContentInput(): void {
		const next = formPublicContent.trim();
		if (next !== '' && publicEditable) {
			formRdata = formPublicContent;
		}
	}

	function overrideCount(record: PolicyRecord): number {
		return Object.keys(record.overrides).length;
	}

	function hasPublic(record: PolicyRecord): boolean {
		return publicKeys.has(recordKey(record.name, record.type));
	}

	async function submit(): Promise<void> {
		if (!isAdmin) return;
		submitted = true;
		if (formName.trim() === '' || ownerError || publicContentError) return;

		const overrides = overridesFromRows(overrideRows);
		const publicContent = formPublicContent.trim();
		const writingPublic = publicEditable && publicDirty;
		// Öffentlich non-empty → local default mirrors it; clearing public keeps formRdata.
		let rdata = publicEditable && publicContent !== '' ? publicContent : formRdata.trim();
		if (rdata === '' && editing) rdata = editing.rdata;
		// Local-only record without a default answer: the backend needs a base value, so reuse an override.
		if (rdata === '') rdata = Object.values(overrides).find((value) => value !== '') ?? '';
		if (rdata === '' || validateRdata(rdata, true)) return;

		busy = true;
		failure = null;
		try {
			if (writingPublic) {
				const zone = zoneForName(attachedZones, formName.trim());
				if (!zone?.id) throw new ApiError(400, 'tls.secret.missing');
				const existing =
					publicLookup.kind === 'found'
						? publicLookup.record
						: publicBaseline.recordId
							? {
									id: publicBaseline.recordId,
									name: formName.trim(),
									record_type: formType,
									content: publicBaseline.content,
									ttl: ttlWrite(publicBaseline.ttl),
									proxied: publicBaseline.proxied,
								}
							: null;
				await upsertPublicRecord(zone.id, existing, {
					name: formName.trim().replace(/\.+$/, ''),
					type: formType,
					content: publicContent,
					ttl: ttlWrite(formTtl),
					proxied: supportsProxied(formType) ? formPublicProxied : false,
				});
				recordsByZone.delete(zone.id);
			}

			await saveRecord({
				name: formName.trim(),
				type: formType,
				ttl: localTtl(formTtl),
				rdata,
				overrides,
			});
			closeSheet();
			await load();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	async function confirmRemove(): Promise<void> {
		if (!editing || !isAdmin) return;
		busy = true;
		failure = null;
		try {
			await deleteRecord({ name: editing.name, type: editing.type });
			closeSheet();
			editing = null;
			await load();
		} catch (cause) {
			failure = failureOf(cause);
			confirmDelete = false;
		} finally {
			busy = false;
		}
	}

	onMount(() => {
		zoneKey = new URLSearchParams(window.location.search).get('zone') ?? '';
		zoneKey = new URLSearchParams(window.location.search).get('zone') ?? '';
		void Promise.all([load(), loadDomainZones()]);
	});
</script>

<div class="names">
	<div class="page-head">
		<p class="lead">{m.names_lead()}</p>
		{#if isAdmin && result.kind === 'ok'}
			<div class="page-actions">
				<Button variant="secondary" onclick={() => void openZonesSheet()}
					>{m.names_zones_manage()}</Button
				>
				<Button variant="primary" onclick={openCreate}>{m.names_add()}</Button>
			</div>
		{/if}
	</div>

	{#if isAdmin && domainZonesReady && !hasCloudflareToken}
		<p class="token-banner" role="status">
			{m.names_token_banner()}
			<a class="cta-link inline" href={resolve('/tls')}>{m.names_token_banner_cta()}</a>
		</p>
	{/if}

	{#if result.kind === 'loading'}
		<p class="state">{m.state_loading()}</p>
	{:else if result.kind === 'unavailable'}
		<UnavailableNotice />
	{:else if result.kind === 'error'}
		<ResultNotice {result} onretry={() => void load()} />
	{:else}
		<label class="sr-only" for="names-search">{m.names_search_label()}</label>
		<input
			id="names-search"
			class="search mono"
			type="search"
			bind:value={query}
			placeholder={m.names_search_placeholder()}
			autocomplete="off"
		/>

		{#if zoneChips.length > 0}
			<div class="zone-chips" role="group" aria-label={m.names_zones_filter()}>
				<button
					type="button"
					class="zone-chip"
					aria-pressed={activeZone === ''}
					onclick={() => setZone('')}
				>
					<span>{m.names_zone_all()}</span>
					<span class="chip-count">{allRows.length}</span>
				</button>
				{#each zoneChips as chip (chip.name)}
					<button
						type="button"
						class="zone-chip"
						aria-pressed={activeZone === chip.name}
						onclick={() => setZone(chip.name)}
					>
						<span class="mono">{displayText(chip.name, 80).text}</span>
						<span class="zone-kind" class:cf={chip.attached}
							>{chip.attached ? m.names_zone_cloudflare() : m.names_zone_local()}</span
						>
						<span class="chip-count">{chip.count}</span>
					</button>
				{/each}
			</div>
		{/if}
		{#if cloudflareLoading}
			<p class="hint muted" role="status">{m.names_cf_loading()}</p>
		{/if}
		{#if cloudflareFailed}
			<p class="hint muted" role="status">{m.names_cf_failed()}</p>
		{/if}
		{#if groups.length === 0}
			<section class="empty">
				<p>{query.trim() ? m.names_search_empty() : m.state_empty()}</p>
			</section>
		{:else}
			{#snippet rowBody(row: NameRow)}
				<span class="type">{row.type}</span>
				<span class="rdata mono">{row.rdata}</span>
				<span class="meta">
					{#if row.local}
						{m.names_ttl_short({ ttl: row.ttl })}{#if hasPublic(row.local)}
							{' · '}{m.names_public_badge()}{/if}{#if overrideCount(row.local) > 0}
							{' · '}{overrideCount(row.local) === 1
								? m.names_overrides_badge_one({ count: '1' })
								: m.names_overrides_badge_other({ count: String(overrideCount(row.local)) })}{/if}
					{:else}
						{m.names_public_only()} · {m.names_ttl_short({
							ttl: ttlFieldFor(row.ttl),
						})}{#if row.cf?.proxied}
							{' · '}{m.names_public_proxied()}{/if}
					{/if}
				</span>
				{#if canOpen(row)}
					<span class="chevron" aria-hidden="true">
						<Icon name="chevron-right" size="1rem" />
					</span>
				{/if}
			{/snippet}
			{#each groups as group (group.name)}
				<section class="owner">
					<header class="owner-head">
						<span class="owner-name mono">{domainLabel(group.name)}</span>
						<span class="owner-meta"
							>{group.records.length === 1
								? m.names_record_count_one({ count: '1' })
								: m.names_record_count_other({ count: String(group.records.length) })}</span
						>
					</header>
					<GroupedList>
						{#each group.records as row (row.key)}
							{#if canOpen(row)}
								<button type="button" class="rec-row" onclick={() => openRow(row)}>
									{@render rowBody(row)}
								</button>
							{:else}
								<div class="rec-row rec-row-static">
									{@render rowBody(row)}
								</div>
							{/if}
						{/each}
					</GroupedList>
				</section>
			{/each}
		{/if}
		<p class="footnote">{m.names_footnote()}</p>
	{/if}
</div>

{#if sheetOpen}
	<Sheet open={sheetOpen} title={sheetTitle} onclose={closeSheet} centeredOnWide>
		<label class="field-label" for="rec-name">{m.names_field_name()}</label>
		<input
			id="rec-name"
			class="field mono"
			bind:value={formName}
			disabled={editing !== null || !isAdmin}
			aria-invalid={ownerError ? 'true' : undefined}
			oninput={() => {
				if (isAdmin && editing === null) void refreshPublicLookup();
			}}
		/>
		{#if ownerError}<p class="error-text" role="alert">{ownerError}</p>{/if}

		<div class="meta-grid">
			<div class="meta-cell">
				<label class="field-label" for="rec-type">{m.names_field_type()}</label>
				<select
					id="rec-type"
					class="field"
					bind:value={formType}
					disabled={editing !== null || !isAdmin}
					onchange={() => void refreshPublicLookup()}
				>
					{#each RECORD_TYPES as type (type)}
						<option value={type}>{type}</option>
					{/each}
				</select>
			</div>
			<div class="meta-cell">
				<label class="field-label" for="rec-ttl">{m.names_field_ttl()}</label>
				<input
					id="rec-ttl"
					class="field"
					bind:value={formTtl}
					autocomplete="off"
					disabled={!isAdmin}
				/>
			</div>
		</div>

		<section class="sheet-section" aria-labelledby="rec-answer-label">
			<p class="section-label" id="rec-answer-label">{m.names_section_answer()}</p>

			{#if showPublicAnswer}
				{#if !isAdmin && publicLookup.kind === 'found'}
					<p class="public-value mono" aria-label={m.names_field_public()}>
						{displayText(publicLookup.record.content, 200).text}
					</p>
					<p class="hint muted">
						{m.names_ttl_short({
							ttl: ttlFieldFor(publicLookup.record.ttl),
						})}{#if publicLookup.record.proxied}
							{' · '}{m.names_public_proxied()}{/if}
					</p>
				{:else if !isAdmin && publicLookup.kind === 'absent'}
					<p class="hint muted">{m.names_public_absent()}</p>
				{:else}
					{#if publicLookup.kind === 'absent'}
						<p class="hint muted" id="rec-public-hint">{m.names_public_absent()}</p>
					{:else}
						<p class="hint muted" id="rec-public-hint">{m.names_public_hint()}</p>
					{/if}
					<label class="sr-only" for="rec-public">{m.names_field_public()}</label>
					<input
						id="rec-public"
						class="field mono"
						bind:value={formPublicContent}
						disabled={!publicEditable}
						aria-invalid={publicContentError ? 'true' : undefined}
						aria-describedby={showPublicClearHint ? 'rec-public-clear' : 'rec-public-hint'}
						oninput={onPublicContentInput}
					/>
					{#if publicContentError}<p class="error-text" role="alert">
							{publicContentError}
						</p>{:else if rdataError}<p class="error-text" role="alert">{rdataError}</p>{/if}
					{#if showPublicClearHint}
						<p class="hint muted" id="rec-public-clear">{m.names_public_clear_hint()}</p>
					{/if}
					{#if supportsProxied(formType)}
						<div class="proxied-row">
							<span class="proxied-label">{m.names_public_proxied_label()}</span>
							<Switch
								bind:checked={formPublicProxied}
								disabled={!publicEditable}
								aria-label={m.names_public_proxied_label()}
							/>
						</div>
						{#if showProxiedWarn}
							<p class="warn-text" role="status">{m.names_public_proxied_warn()}</p>
						{/if}
					{/if}
				{/if}
			{:else}
				{#if publicLookup.kind === 'loading'}
					<p class="hint muted">{m.names_public_loading()}</p>
				{/if}
				<label class="sr-only" for="rec-rdata">{m.names_field_rdata()}</label>
				<input
					id="rec-rdata"
					class="field mono"
					bind:value={formRdata}
					disabled={!isAdmin}
					aria-invalid={rdataError ? 'true' : undefined}
				/>
				{#if rdataError}<p class="error-text" role="alert">{rdataError}</p>{/if}
				{#if publicLookup.kind === 'token_missing'}
					<p class="hint muted">
						{m.names_public_token_missing()}
						<a class="cta-link inline" href={resolve('/tls')}>{m.names_public_token_cta()}</a>
					</p>
				{:else if publicLookup.kind === 'unavailable'}
					<p class="hint muted">{m.names_public_unavailable()}</p>
				{:else if publicLookup.kind === 'internal'}
					<p class="hint muted">{m.names_public_internal()}</p>
				{:else if publicLookup.kind === 'error'}
					<p class="hint muted">{m.names_public_error()}</p>
				{/if}
			{/if}
		</section>

		<section class="sheet-section" aria-labelledby="rec-overrides-label">
			<p class="section-label" id="rec-overrides-label">{m.names_section_overrides()}</p>
			<p class="hint" id="rec-overrides-hint">{m.names_overrides_hint()}</p>
			{#if overrideRows.length === 0}
				<p class="hint muted">{overridesEmptyText}</p>
			{:else}
				<ul
					class="override-list"
					aria-labelledby="rec-overrides-label"
					aria-describedby="rec-overrides-hint"
				>
					{#each overrideRows as row, i (row.key)}
						<li class="override-row">
							<label class="sr-only" for="ov-view-{row.key}">{m.names_overrides_view()}</label>
							<select
								id="ov-view-{row.key}"
								class="field"
								bind:value={overrideRows[i].view}
								disabled={!isAdmin}
							>
								<option value="">{m.names_overrides_choose()}</option>
								{#each viewOptionsFor(row) as viewId (viewId)}
									<option value={viewId}>{viewId}</option>
								{/each}
							</select>
							<label class="sr-only" for="ov-value-{row.key}">{m.names_overrides_value()}</label>
							<input
								id="ov-value-{row.key}"
								class="field mono"
								bind:value={overrideRows[i].value}
								placeholder={row.noAnswer ? m.names_overrides_no_answer() : inheritPlaceholder}
								autocomplete="off"
								disabled={!isAdmin || row.noAnswer}
							/>
							<div class="no-answer-row">
								<span class="no-answer-label">{m.names_overrides_no_answer()}</span>
								<Switch
									bind:checked={overrideRows[i].noAnswer}
									disabled={!isAdmin}
									aria-label={m.names_overrides_no_answer()}
								/>
							</div>
							{#if isAdmin}
								<button
									type="button"
									class="remove-override"
									aria-label={m.names_overrides_remove()}
									onclick={() => removeOverrideRow(row.key)}
								>
									<Icon name="x" size="1rem" />
								</button>
							{/if}
						</li>
					{/each}
				</ul>
			{/if}
			{#if isAdmin && canAddOverride}
				<button type="button" class="add-override" onclick={addOverrideRow}
					>{m.names_overrides_add()}</button
				>
			{/if}
		</section>

		{#snippet footer()}
			{#if failure}
				<div class="footer-error">
					<ErrorNotice code={failure.code} params={failure.params} />
				</div>
			{/if}
			{#if !isAdmin}
				<div class="actions">
					<Button variant="secondary" onclick={closeSheet}>{m.action_cancel()}</Button>
				</div>
			{:else if editing && confirmDelete}
				<p class="confirm-text">
					{m.names_delete_body({ name: domainLabel(editing.name), type: editing.type })}
				</p>
				<div class="actions">
					<Button variant="secondary" onclick={() => (confirmDelete = false)}
						>{m.action_cancel()}</Button
					>
					<Button variant="danger" disabled={busy} onclick={() => void confirmRemove()}
						>{m.action_delete()}</Button
					>
				</div>
			{:else}
				{#if editing}
					<button type="button" class="danger-text" onclick={() => (confirmDelete = true)}>
						{m.names_delete()}
					</button>
				{/if}
				<div class="actions">
					<Button variant="secondary" onclick={closeSheet}>{m.action_cancel()}</Button>
					<Button variant="primary" disabled={busy} onclick={() => void submit()}
						>{m.action_save()}</Button
					>
				</div>
			{/if}
		{/snippet}
	</Sheet>
{/if}

{#if zonesSheetOpen}
	<Sheet
		open={zonesSheetOpen}
		title={m.names_zones_title()}
		onclose={closeZonesSheet}
		centeredOnWide
	>
		<p class="hint">{m.names_zones_lead()}</p>
		{#if !hasCloudflareToken}
			<p class="hint">{m.names_zones_token_missing()}</p>
			<a class="cta-link" href={resolve('/tls')}>{m.names_public_token_cta()}</a>
		{:else if !zonesDiscoverReady}
			<p class="hint muted">{m.names_zones_loading()}</p>
		{:else}
			<p class="field-label">{m.names_zones_attached()}</p>
			{#if attachedZones.length === 0}
				<p class="hint muted">{m.state_empty()}</p>
			{:else}
				<ul class="zone-list">
					{#each attachedZones as zone (zone.name)}
						<li class="zone-row">
							<div class="zone-meta">
								<span class="mono">{displayText(zone.name, 80).text}</span>
								<span class="hint muted">
									{zone.source === 'public_domain'
										? m.names_zones_public_domain()
										: (zone.status ?? '')}
								</span>
							</div>
							{#if zone.source !== 'public_domain'}
								<Button
									variant="secondary"
									disabled={zonesBusy}
									onclick={() => void detachZone(zone)}>{m.names_zones_detach()}</Button
								>
							{/if}
						</li>
					{/each}
				</ul>
			{/if}

			<p class="field-label">{m.names_zones_discoverable()}</p>
			{#if attachCandidates.length === 0}
				<p class="hint muted">{m.names_zones_empty_discover()}</p>
			{:else}
				<ul class="zone-list">
					{#each attachCandidates as zone (zone.id ?? zone.name)}
						<li class="zone-row">
							<div class="zone-meta">
								<span class="mono">{displayText(zone.name, 80).text}</span>
								<span class="hint muted">{zone.status ?? ''}</span>
							</div>
							<Button variant="primary" disabled={zonesBusy} onclick={() => void attachZone(zone)}
								>{m.names_zones_attach()}</Button
							>
						</li>
					{/each}
				</ul>
			{/if}
		{/if}

		{#snippet footer()}
			{#if zonesFailure}
				<div class="footer-error">
					<ErrorNotice code={zonesFailure.code} params={zonesFailure.params} />
				</div>
			{/if}
			<div class="actions">
				<Button variant="secondary" onclick={closeZonesSheet}>{m.action_cancel()}</Button>
			</div>
		{/snippet}
	</Sheet>
{/if}

<style>
	.names {
		display: flex;
		flex-direction: column;
		gap: 1rem;
		max-width: 44rem;
	}
	.page-head {
		display: flex;
		flex-wrap: wrap;
		align-items: flex-start;
		justify-content: space-between;
		gap: 0.75rem;
	}
	.page-actions {
		display: flex;
		flex-wrap: wrap;
		gap: 0.5rem;
	}
	.lead {
		margin: 0;
		flex: 1 1 16rem;
		color: var(--label-2);
		font-size: 0.9375rem;
	}
	.token-banner {
		margin: 0;
		padding: 0.625rem 0.75rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		background: var(--surface-2);
		font-size: 0.8125rem;
		color: var(--label-2);
	}
	.error-text {
		margin: 0.375rem 0 0;
		font-size: 0.8125rem;
		color: var(--danger);
	}
	.warn-text {
		margin: 0.5rem 0 0;
		font-size: 0.8125rem;
		color: var(--warning, var(--danger));
	}
	.proxied-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 0.75rem;
		margin-top: 0.5rem;
	}
	.proxied-label {
		font-size: 0.8125rem;
		color: var(--label-2);
	}
	.zone-list {
		list-style: none;
		margin: 0 0 0.75rem;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}
	.zone-row {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		justify-content: space-between;
		gap: 0.5rem;
		padding: 0.5rem 0.75rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		background: var(--surface);
	}
	.zone-meta {
		display: flex;
		flex-direction: column;
		gap: 0.125rem;
		min-width: 0;
	}
	.hint {
		margin: 0.375rem 0 0;
		font-size: 0.8125rem;
		color: var(--label-3);
	}
	.hint.muted {
		color: var(--label-3);
	}
	#rec-overrides-hint {
		margin: 0 0 0.5rem;
	}
	.state,
	.empty {
		margin: 0;
		color: var(--label-2);
	}
	.search {
		width: 100%;
		min-height: 2.75rem;
		padding: 0.5rem 0.75rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		background: var(--surface);
		font: inherit;
	}
	.owner {
		display: flex;
		flex-direction: column;
		gap: 0.375rem;
	}
	.owner-head {
		display: flex;
		flex-wrap: wrap;
		align-items: baseline;
		justify-content: space-between;
		gap: 0.5rem;
		padding: 0 0.25rem;
	}
	.owner-name {
		font-size: 0.9375rem;
		font-weight: 600;
		overflow-wrap: anywhere;
	}
	.owner-meta {
		font-size: 0.75rem;
		color: var(--label-3);
	}
	.rec-row {
		display: grid;
		grid-template-columns: 3.5rem minmax(0, 1fr) auto auto;
		align-items: center;
		gap: 0.5rem 0.75rem;
		width: 100%;
		min-height: 2.75rem;
		padding: 0.5rem 1rem;
		border: none;
		border-top: 1px solid var(--separator);
		background: transparent;
		color: var(--label);
		font: inherit;
		text-align: start;
		cursor: pointer;
	}
	.zone-chips {
		display: flex;
		flex-wrap: wrap;
		gap: 0.375rem;
	}
	.zone-chip {
		display: inline-flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 0.375rem;
		min-height: 2.25rem;
		padding: 0.25rem 0.75rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		background: var(--surface);
		color: var(--label);
		font: inherit;
		font-size: 0.8125rem;
		cursor: pointer;
	}
	.zone-chip[aria-pressed='true'] {
		border-color: var(--accent);
		background: var(--surface-2);
		color: var(--accent);
		font-weight: 600;
	}
	.zone-kind {
		font-size: 0.6875rem;
		color: var(--label-3);
	}
	.zone-kind.cf {
		color: var(--accent);
	}
	.chip-count {
		font-size: 0.75rem;
		color: var(--label-3);
		font-variant-numeric: tabular-nums;
	}
	.rec-row-static,
	.rec-row.rec-row-static:hover {
		cursor: default;
		background: transparent;
	}
	.rec-row:first-child {
		border-top: none;
	}
	.rec-row:hover {
		background: var(--surface-2);
	}
	.type {
		font-size: 0.75rem;
		font-weight: 700;
		letter-spacing: 0.04em;
		color: var(--accent);
	}
	.rdata {
		min-width: 0;
		font-size: 0.875rem;
		overflow-wrap: anywhere;
	}
	.meta {
		font-size: 0.75rem;
		color: var(--label-3);
		white-space: nowrap;
	}
	.chevron {
		display: inline-flex;
		color: var(--label-3);
	}
	.footnote {
		margin: 0;
		font-size: 0.8125rem;
		color: var(--label-3);
	}
	.mono {
		font-family: var(--font-mono);
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
		margin: 0.75rem 0 0.25rem;
		font-size: 0.8125rem;
		color: var(--label-2);
	}
	.meta-grid {
		display: grid;
		grid-template-columns: minmax(0, 1fr);
		gap: 0;
	}
	@media (min-width: 28rem) {
		.meta-grid {
			grid-template-columns: repeat(2, minmax(0, 1fr));
			gap: 0 0.75rem;
		}
	}
	.meta-cell {
		min-width: 0;
	}
	.sheet-section {
		margin-top: 1rem;
		padding-top: 0.875rem;
		border-top: 1px solid var(--separator);
	}
	.section-label {
		display: block;
		margin: 0 0 0.5rem;
		font-size: 0.8125rem;
		font-weight: 600;
		color: var(--label);
	}
	.field {
		width: 100%;
		min-height: 2.75rem;
		padding: 0.5rem 0.75rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		background: var(--surface);
		font: inherit;
	}
	.field:disabled {
		opacity: 0.85;
		color: var(--label-2);
	}
	.public-value {
		margin: 0.25rem 0 0;
		font-size: 0.9375rem;
		overflow-wrap: anywhere;
	}
	.cta-link {
		display: inline-block;
		margin: 0.125rem 0 0.5rem;
		color: var(--accent);
		font-weight: 600;
		text-decoration: none;
	}
	.cta-link.inline {
		display: inline;
		margin: 0;
		font-weight: 600;
	}
	.cta-link:hover {
		text-decoration: underline;
	}
	.override-list {
		list-style: none;
		margin: 0;
		padding: 0.375rem;
		display: flex;
		flex-direction: column;
		gap: 0.375rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		background: var(--surface-2);
	}
	.override-row {
		display: grid;
		grid-template-columns: minmax(0, 1fr) minmax(0, 1.2fr) auto auto;
		gap: 0.375rem;
		align-items: center;
	}
	@media (max-width: 36rem) {
		.override-row {
			grid-template-columns: minmax(0, 1fr) auto;
		}
		.override-row .field.mono {
			grid-column: 1 / -1;
		}
	}
	.no-answer-row {
		display: inline-flex;
		align-items: center;
		gap: 0.375rem;
		min-height: 2.75rem;
		cursor: pointer;
	}
	.no-answer-label {
		font-size: 0.75rem;
		color: var(--label-2);
		white-space: nowrap;
	}
	.remove-override {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 2.75rem;
		height: 2.75rem;
		padding: 0;
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		background: var(--surface-2);
		color: var(--label-2);
		cursor: pointer;
	}
	.remove-override:hover {
		color: var(--danger);
	}
	.add-override {
		display: block;
		margin: 0.5rem 0 0;
		padding: 0;
		border: none;
		background: transparent;
		color: var(--accent);
		font: inherit;
		font-weight: 500;
		cursor: pointer;
		text-align: start;
	}
	.footer-error {
		margin-bottom: 0.75rem;
	}
	.confirm-text {
		margin: 0 0 0.75rem;
		color: var(--label-2);
	}
	.danger-text {
		display: block;
		margin: 0 0 0.75rem;
		padding: 0;
		border: none;
		background: transparent;
		color: var(--danger);
		font: inherit;
		font-weight: 600;
		cursor: pointer;
		text-align: start;
	}
	.actions {
		display: flex;
		justify-content: flex-end;
		gap: 0.5rem;
	}
</style>
