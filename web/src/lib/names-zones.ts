import { normalizeDnsName, zoneForName, type DomainZone } from '$lib/api/domain-zones';

/**
 * Zone a local owner name belongs to: the longest attached Cloudflare apex, else a derived
 * local zone (see `localZoneName`). `attached` tells the two apart.
 */
export function zoneOfName(
	attached: readonly DomainZone[],
	fqdn: string,
): { name: string; attached: boolean } {
	const zone = zoneForName(attached, fqdn);
	if (zone) return { name: normalizeDnsName(zone.name), attached: true };
	return { name: localZoneName(fqdn), attached: false };
}

/**
 * Derived zone for names outside every attached apex.
 * `.arpa` names: the name minus its first label (5.10.20.172.in-addr.arpa -> 10.20.172.in-addr.arpa).
 * Everything else: the last label with a leading dot (nas.lan -> .lan, nas -> .nas).
 */
export function localZoneName(fqdn: string): string {
	const name = normalizeDnsName(fqdn);
	const labels = name.split('.');
	// ponytail: naive /24 heuristic; real reverse delegations can be /16 or /8. Add a zone list when that matters.
	if (labels.length > 2 && name.endsWith('.arpa')) return labels.slice(1).join('.');
	return `.${labels[labels.length - 1] ?? ''}`;
}
