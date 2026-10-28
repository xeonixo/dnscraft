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
