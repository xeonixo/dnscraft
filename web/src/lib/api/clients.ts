import { del, get, post, put, type RequestOptions } from './client';

export interface DirectoryClient {
	id: string;
	name: string;
	dns_label: string;
	local_domain: string;
	source: string;
	ips: string[];
	macs: string[];
	vlan: number | null;
	online: boolean;
	last_seen: string | null;
}

export interface ManualClientEntry {
	name: string;
	ip?: string;
	cidr?: string;
	domain?: string;
	identity?: string;
}

export interface ClientsPage {
	clients: DirectoryClient[];
	manual: ManualClientEntry[];
}

export interface SyncSummary {
	generation: number;
	rebuilt: boolean;
	client_count: number;
	ip_conflicts: number;
}

function parseDirectory(value: unknown): DirectoryClient[] {
	if (!Array.isArray(value)) return [];
	return value.filter(isDirectoryClient);
}

function isDirectoryClient(value: unknown): value is DirectoryClient {
	if (typeof value !== 'object' || value === null) return false;
	const row = value as DirectoryClient;
	return (
		typeof row.id === 'string' && typeof row.name === 'string' && typeof row.source === 'string'
	);
}

function parseManual(value: unknown): ManualClientEntry[] {
	if (!Array.isArray(value)) return [];
	return value.filter(
		(entry): entry is ManualClientEntry =>
			typeof entry === 'object' &&
			entry !== null &&
			typeof (entry as ManualClientEntry).name === 'string',
	);
}

export const listClients = (): Promise<ClientsPage> =>
	get<{ clients?: unknown; manual?: unknown }>('/clients').then((data) => ({
		clients: parseDirectory(data.clients),
		manual: parseManual(data.manual),
	}));

export const createManualClient = (
	body: ManualClientEntry,
	options?: RequestOptions,
): Promise<{ version: number; entry: ManualClientEntry }> =>
	post('/clients/manual', { body, ...options });

export const saveManualClient = (
	body: ManualClientEntry,
	options?: RequestOptions,
): Promise<{ version: number; entry: ManualClientEntry; created: boolean }> =>
	put('/clients/manual', { body, ...options });

export const deleteManualClient = (
	name: string,
	options?: RequestOptions,
): Promise<{ version: number }> => del('/clients/manual', { body: { name }, ...options });

export const syncClients = (): Promise<SyncSummary> => post('/clients/sync');

/** UniFi profiles + bindings with `has_api_key` (no secrets). */
export interface UnifiStatus {
	profiles: unknown[];
	bindings: Record<string, string>;
}

export const getUnifiStatus = (): Promise<UnifiStatus> =>
	get<{ profiles?: unknown; bindings?: unknown }>('/clients/unifi').then((data) => ({
		profiles: Array.isArray(data.profiles) ? data.profiles : [],
		bindings:
			typeof data.bindings === 'object' && data.bindings !== null && !Array.isArray(data.bindings)
				? (data.bindings as Record<string, string>)
				: {},
	}));

/** Write-only UniFi API key. Omit body field to keep; `null` to clear. */
export const putUnifiApiKey = (
	profileId: string,
	api_key: string | null,
): Promise<{ id: string; updated: boolean; has_api_key?: boolean }> =>
	put(`/clients/unifi-profiles/${encodeURIComponent(profileId)}/api-key`, {
		body: { api_key },
	});
