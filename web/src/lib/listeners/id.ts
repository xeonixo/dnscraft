/** Listener ids must match `[a-z0-9-]{1,64}` (control-api / ListenerId). */

export type ListenerProtocol = 'udp53' | 'tcp53' | 'dot' | 'doh' | 'doq';
export type AddrFamily = 'ipv4' | 'ipv6';

export function allowsPublic(protocol: ListenerProtocol): boolean {
	return protocol === 'dot' || protocol === 'doh' || protocol === 'doq';
}

/**
 * Stable id from protocol, family and exposure. Appends `-2`, `-3`, … when the
 * base is already taken so create never asks the user for an id.
 */
export function suggestListenerId(
	protocol: ListenerProtocol,
	family: AddrFamily,
	isPublic: boolean,
	existing: readonly string[],
): string {
	const exposure = isPublic && allowsPublic(protocol) ? 'public' : 'local';
	const base = family === 'ipv6' ? `${exposure}-${protocol}-v6` : `${exposure}-${protocol}`;
	if (!existing.includes(base)) return base;
	for (let n = 2; n < 1000; n++) {
		const candidate = `${base}-${n}`;
		if (!existing.includes(candidate)) return candidate;
	}
	return `${base}-x`;
}
