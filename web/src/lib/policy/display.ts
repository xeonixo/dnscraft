import { displayText } from '$lib/safe-text';

/** Untrusted DNS name for list rows. */
export function domainLabel(name: string): string {
	return displayText(name).text;
}

/** Comma-separated subnet list for a view row. */
export function subnetDetail(subnets: string[], emptyLabel: string): string {
	if (subnets.length === 0) return emptyLabel;
	return subnets.join(' · ');
}
