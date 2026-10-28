const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * Normalises a domain typed by the owner: trims, lower-cases and drops one trailing dot.
 * Returns null for anything the resolver would refuse (empty, wildcard, non-ASCII, bad labels).
 */
export function toDomainName(input: string): string | null {
	const name = input.trim().toLowerCase().replace(/\.$/, '');
	if (name.length === 0 || name.length > 253) return null;
	return name.split('.').every((label) => LABEL.test(label)) ? name : null;
}
