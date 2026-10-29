import { displayText } from '$lib/safe-text';

/** Untrusted DNS name for list rows, without the trailing root dot so every name reads the same. */
export function domainLabel(name: string): string {
	return displayText(name.replace(/\.+$/, '')).text;
}

/** Comma-separated subnet list for a view row. */
export function subnetDetail(subnets: string[], emptyLabel: string): string {
	if (subnets.length === 0) return emptyLabel;
	return subnets.join(' · ');
}
