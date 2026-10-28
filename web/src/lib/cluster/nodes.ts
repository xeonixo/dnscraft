import type { IconName, StatusTone } from '$lib/components/icons';
import { formatNumber } from '$lib/format';
import { m } from '$lib/paraglide/messages';

/** List detail for a `nodes[]` field: empty means every node in the cluster. */
export function formatNodesDetail(nodes: readonly string[]): string {
	if (nodes.length === 0) return m.listeners_nodes_all();
	return nodes.join(', ');
}

/** Merge cluster registry ids with any ids already selected on the form. */
export function nodeChoicesFor(
	clusterNodeIds: readonly string[],
	selected: readonly string[],
): string[] {
	const ids = [...clusterNodeIds];
	for (const id of selected) {
		if (!ids.includes(id)) ids.push(id);
	}
	return ids;
}

export function toggleNodeId(selected: readonly string[], id: string, checked: boolean): string[] {
	if (checked) {
		return selected.includes(id) ? [...selected] : [...selected, id];
	}
	return selected.filter((node) => node !== id);
}

/**
 * Config lag per node, aligned with `nodes`: the newest applied version among the non-revoked
 * nodes minus the node's own. A node that never reported a version counts as fully behind;
 * revoked nodes sit outside the comparison and report 0.
 */
export function nodeLag(
	nodes: readonly { applied_config_version: number | null; revoked: boolean }[],
): number[] {
	let newest = 0;
	for (const node of nodes) {
		if (!node.revoked && node.applied_config_version !== null) {
			newest = Math.max(newest, node.applied_config_version);
		}
	}
	return nodes.map((node) => {
		if (node.revoked) return 0;
		if (node.applied_config_version === null) return newest;
		return newest - node.applied_config_version;
	});
}

export function nodeRoleLabel(role: string): string {
	if (role === 'master') return m.sidebar_node_master();
	if (role === 'sub_node') return m.sidebar_node_sub();
	return role;
}

/** Config status of one node: revoked, unknown version, up to date, or versions behind. */
export function nodeStatusLabel(
	node: { applied_config_version: number | null; revoked: boolean },
	lag: number,
	locale: string,
): string {
	if (node.revoked) return m.cluster_revoked();
	if (node.applied_config_version === null) return m.cluster_status_unknown();
	if (lag === 0) return m.cluster_status_current();
	if (lag === 1) return m.cluster_status_behind_one();
	return m.cluster_status_behind({ count: formatNumber(lag, locale) });
}

/** Symbol and tone that carry a node's config status next to its label. */
export function nodeVerdict(
	node: { applied_config_version: number | null; revoked: boolean },
	lag: number,
): { icon: IconName; tone: StatusTone } {
	if (node.revoked) return { icon: 'x-circle', tone: 'neutral' };
	if (node.applied_config_version === null) return { icon: 'help-circle', tone: 'neutral' };
	if (lag > 0) return { icon: 'alert-triangle', tone: 'warn' };
	return { icon: 'check-circle', tone: 'ok' };
}
