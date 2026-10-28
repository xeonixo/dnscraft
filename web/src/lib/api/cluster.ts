import { del, get, post } from './client';

/** One row from `GET /api/v1/cluster/nodes` (the envelope `data` is the array). */
export interface ClusterNode {
	node_id: string;
	role: string;
	fingerprint: string | null;
	joined_at: string | null;
	last_seen: string | null;
	applied_config_version: number | null;
	revoked: boolean;
	/** This process; peers are `false`. */
	local?: boolean;
	/** Open downstream stream to the master (peers); local is always connected. */
	connected?: boolean;
	/** Last observed peer socket address (`ip:port`), when known. */
	remote_addr?: string | null;
	/** Cluster link: `"mtls"` for peers; `null` for the local row. */
	transport?: string | null;
}

export interface JoinTokenResult {
	token: string;
	expires_at: string;
}

export const listClusterNodes = (): Promise<ClusterNode[]> =>
	get<unknown>('/cluster/nodes').then((data) =>
		Array.isArray(data) ? (data as ClusterNode[]) : [],
	);

export const mintJoinToken = (node_id: string): Promise<JoinTokenResult> =>
	post('/cluster/join-tokens', { body: { node_id } });

export const revokeClusterNode = (nodeId: string): Promise<{ node_id: string; revoked: boolean }> =>
	del(`/cluster/nodes/${encodeURIComponent(nodeId)}`);
