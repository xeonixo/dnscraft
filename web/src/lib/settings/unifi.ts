/** Wire / form helpers for UniFi profiles, bindings, and local domain. */

export type LocalDomainMode = 'unifi_then_config' | 'config';

export type UnifiTlsChoice = 'secure' | 'pin' | 'ca_file' | 'insecure';

export interface UnifiConnectionWire {
	enabled: boolean;
	base_url: string;
	site_id: string | null;
	poll_interval: string;
	classic_clients: boolean;
	tls_pin_sha256: string | null;
	ca_file: string | null;
	insecure_skip_verify: boolean;
}

export interface UnifiProfileForm {
	id: string;
	enabled: boolean;
	base_url: string;
	site_id: string;
	poll_seconds: number;
	classic_clients: boolean;
	tls: UnifiTlsChoice;
	tls_pin_sha256: string;
	ca_file: string;
	sync_owner: string;
	/** Write-only draft; empty means keep existing key. */
	api_key: string;
	has_api_key: boolean;
	/** When true, next save clears the stored key. */
	clear_api_key: boolean;
}

export interface ClientsUnifiForm {
	local_domain: string;
	local_domain_mode: LocalDomainMode;
	profiles: UnifiProfileForm[];
	/** node_id → profile_id; empty string means unbound. */
	bindings: Record<string, string>;
	selected_profile_id: string;
}

export const DEFAULT_PROFILE: UnifiProfileForm = {
	id: 'default',
	enabled: false,
	base_url: '',
	site_id: '',
	poll_seconds: 60,
	classic_clients: true,
	tls: 'secure',
	tls_pin_sha256: '',
	ca_file: '',
	sync_owner: 'local',
	api_key: '',
	has_api_key: false,
	clear_api_key: false,
};

export const DEFAULT_UNIFI_FORM: ClientsUnifiForm = {
	local_domain: 'home.arpa',
	local_domain_mode: 'unifi_then_config',
	profiles: [{ ...DEFAULT_PROFILE }],
	bindings: {},
	selected_profile_id: 'default',
};

function asRecord(value: unknown): Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: {};
}

function asString(value: unknown, fallback = ''): string {
	return typeof value === 'string' ? value : fallback;
}

function asBool(value: unknown, fallback: boolean): boolean {
	return typeof value === 'boolean' ? value : fallback;
}

/** Parses a duration like `60s` / `1m` into whole seconds; falls back when unknown. */
export function pollSecondsOf(value: unknown, fallback = 60): number {
	if (typeof value === 'number' && Number.isFinite(value) && value > 0) {
		return Math.round(value);
	}
	if (typeof value !== 'string') return fallback;
	const match = /^(\d+)(s|m|h)?$/i.exec(value.trim());
	if (!match) return fallback;
	const amount = Number(match[1]);
	const unit = (match[2] ?? 's').toLowerCase();
	if (unit === 'm') return amount * 60;
	if (unit === 'h') return amount * 3600;
	return amount;
}

export function tlsChoiceOf(unifi: Record<string, unknown>): UnifiTlsChoice {
	if (asBool(unifi.insecure_skip_verify, false)) return 'insecure';
	if (asString(unifi.tls_pin_sha256)) return 'pin';
	if (asString(unifi.ca_file)) return 'ca_file';
	return 'secure';
}

function connectionFromWire(raw: Record<string, unknown>): Omit<
	UnifiProfileForm,
	'id' | 'sync_owner' | 'api_key' | 'has_api_key' | 'clear_api_key'
> {
	return {
		enabled: asBool(raw.enabled, false),
		base_url: asString(raw.base_url),
		site_id: asString(raw.site_id),
		poll_seconds: pollSecondsOf(raw.poll_interval, 60),
		classic_clients: asBool(raw.classic_clients, true),
		tls: tlsChoiceOf(raw),
		tls_pin_sha256: asString(raw.tls_pin_sha256),
		ca_file: asString(raw.ca_file),
	};
}

function profileFromWire(raw: unknown): UnifiProfileForm | null {
	const row = asRecord(raw);
	const id = asString(row.id).trim();
	if (!id) return null;
	const connection = asRecord(row.connection);
	const source = Object.keys(connection).length > 0 ? connection : row;
	return {
		id,
		...connectionFromWire(source),
		sync_owner: asString(row.sync_owner, 'local') || 'local',
		api_key: '',
		has_api_key: asBool(row.has_api_key, false),
		clear_api_key: false,
	};
}

function connectionWire(profile: UnifiProfileForm): UnifiConnectionWire {
	return {
		enabled: profile.enabled,
		base_url: profile.base_url.trim(),
		site_id: profile.site_id.trim() === '' ? null : profile.site_id.trim(),
		poll_interval: `${Math.max(1, Math.round(profile.poll_seconds))}s`,
		classic_clients: profile.classic_clients,
		tls_pin_sha256: profile.tls === 'pin' ? profile.tls_pin_sha256.trim() || null : null,
		ca_file: profile.tls === 'ca_file' ? profile.ca_file.trim() || null : null,
		insecure_skip_verify: profile.tls === 'insecure',
	};
}

/** Reads editable UniFi fields from config and/or `GET /clients/unifi`. */
export function formFromClients(
	clients: unknown,
	unifiStatus?: unknown,
): ClientsUnifiForm {
	const section = asRecord(clients);
	const status = asRecord(unifiStatus);
	const mode = asString(section.local_domain_mode, 'unifi_then_config');
	const statusProfiles = Array.isArray(status.profiles) ? status.profiles : null;
	const configProfiles = Array.isArray(section.unifi_profiles) ? section.unifi_profiles : null;
	const rawProfiles = statusProfiles ?? configProfiles;

	let profiles: UnifiProfileForm[] = [];
	if (rawProfiles && rawProfiles.length > 0) {
		profiles = rawProfiles
			.map(profileFromWire)
			.filter((p): p is UnifiProfileForm => p !== null);
	} else {
		const legacy = asRecord(section.unifi);
		if (Object.keys(legacy).length > 0 || asBool(legacy.enabled, false)) {
			profiles = [
				{
					id: 'default',
					...connectionFromWire(legacy),
					sync_owner: 'local',
					api_key: '',
					has_api_key: false,
					clear_api_key: false,
				},
			];
		}
	}
	if (profiles.length === 0) {
		profiles = [{ ...DEFAULT_PROFILE }];
	}

	const bindingsRaw = asRecord(
		Object.keys(asRecord(status.bindings)).length > 0
			? status.bindings
			: section.unifi_bindings,
	);
	const bindings: Record<string, string> = {};
	for (const [node, profile] of Object.entries(bindingsRaw)) {
		if (typeof profile === 'string') bindings[node] = profile;
	}

	return {
		local_domain: asString(section.local_domain, 'home.arpa') || 'home.arpa',
		local_domain_mode: mode === 'config' ? 'config' : 'unifi_then_config',
		profiles,
		bindings,
		selected_profile_id: profiles[0]?.id ?? 'default',
	};
}

/** Builds the `clients` config patch (no API keys). */
export function clientsPatchFromForm(form: ClientsUnifiForm): Record<string, unknown> {
	const unifi_profiles = form.profiles.map((profile) => ({
		id: profile.id.trim(),
		sync_owner: profile.sync_owner.trim() || 'local',
		...connectionWire(profile),
	}));
	const unifi_bindings: Record<string, string> = {};
	for (const [node, profileId] of Object.entries(form.bindings)) {
		const trimmed = profileId.trim();
		if (trimmed) unifi_bindings[node] = trimmed;
	}
	return {
		local_domain: form.local_domain.trim() || 'home.arpa',
		local_domain_mode: form.local_domain_mode,
		unifi_profiles,
		unifi_bindings,
	};
}

/** Selected profile helper. */
export function selectedProfile(form: ClientsUnifiForm): UnifiProfileForm {
	return (
		form.profiles.find((p) => p.id === form.selected_profile_id) ??
		form.profiles[0] ??
		DEFAULT_PROFILE
	);
}

/** Whether `selfNodeId` is sync_owner of its bound profile. */
export function isSelfSyncOwner(form: ClientsUnifiForm, selfNodeId: string): boolean {
	const bound = form.bindings[selfNodeId];
	if (!bound) return form.profiles.some((p) => p.sync_owner === selfNodeId && p.enabled);
	const profile = form.profiles.find((p) => p.id === bound);
	return profile?.enabled === true && profile.sync_owner === selfNodeId;
}

export function syncOwnerLabel(form: ClientsUnifiForm, selfNodeId: string): string | null {
	const bound = form.bindings[selfNodeId];
	const profile = bound
		? form.profiles.find((p) => p.id === bound)
		: form.profiles.find((p) => p.sync_owner === selfNodeId);
	if (!profile?.enabled) return null;
	if (profile.sync_owner === selfNodeId) return null;
	return profile.sync_owner;
}
