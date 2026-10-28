import { del, get, put, type RequestOptions } from './client';

/** One listener row from `GET /api/v1/listeners` (listener_routes.rs). */
export interface Listener {
	id: string;
	protocol: 'udp53' | 'tcp53' | 'dot' | 'doh' | 'doq';
	address: string;
	exposure: 'local' | 'public';
	h3: boolean;
	/** Empty = every cluster node. */
	nodes: string[];
}

export interface ListenerBody {
	id: string;
	protocol: Listener['protocol'];
	address: string;
	exposure?: 'local' | 'public';
	h3?: boolean;
	nodes?: string[];
}

export interface ListenerSaveResult {
	version: number;
	listener: Listener;
	created: boolean;
}

/** Normalises a wire `nodes` array (empty = every node). */
export function nodesFromWire(value: unknown): string[] {
	if (!Array.isArray(value)) return [];
	const out: string[] = [];
	for (const entry of value) {
		if (typeof entry !== 'string') continue;
		const trimmed = entry.trim();
		if (trimmed && !out.includes(trimmed)) out.push(trimmed);
	}
	return out;
}

/** Wire protocols may arrive as `udp53` or legacy `Udp53` from serde enum names. */
function parseProtocol(value: unknown): Listener['protocol'] | null {
	if (typeof value !== 'string') return null;
	const protocol = value.trim().toLowerCase();
	if (
		protocol === 'udp53' ||
		protocol === 'tcp53' ||
		protocol === 'dot' ||
		protocol === 'doh' ||
		protocol === 'doq'
	) {
		return protocol;
	}
	return null;
}

function parseListener(value: unknown): Listener | null {
	if (typeof value !== 'object' || value === null) return null;
	const row = value as Record<string, unknown>;
	if (typeof row.id !== 'string' || typeof row.address !== 'string') return null;
	const protocol = parseProtocol(row.protocol);
	if (!protocol) return null;
	const exposureRaw = typeof row.exposure === 'string' ? row.exposure.trim().toLowerCase() : '';
	return {
		id: row.id,
		protocol,
		address: row.address,
		exposure: exposureRaw === 'public' ? 'public' : 'local',
		h3: row.h3 === true,
		nodes: nodesFromWire(row.nodes),
	};
}

export const listListeners = (): Promise<Listener[]> =>
	get<{ listeners: unknown }>('/listeners').then((data) =>
		Array.isArray(data.listeners)
			? data.listeners.map(parseListener).filter((l): l is Listener => l !== null)
			: [],
	);

export const saveListener = (
	body: ListenerBody,
	options?: RequestOptions,
): Promise<ListenerSaveResult> => put('/listeners', { body, ...options });

export const deleteListener = (
	id: string,
	options?: RequestOptions,
): Promise<{ version: number; deleted: boolean; id: string }> =>
	del('/listeners', { body: { id }, ...options });
