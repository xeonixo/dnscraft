// Helpers for the DoH-Clients screen: suggested Client IDs, id/label checks, address parsing and
// the "was it a home device" test used by the last-seen line. Pure, no DOM.

export const CLIENT_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}$/;
export const LABEL_MAX = 64;

const UMLAUTS: Record<string, string> = { ä: 'ae', ö: 'oe', ü: 'ue', ß: 'ss' };
const RANDOM_CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789';

/** Lower-case slug of the label (umlauts spelled out), without leading or trailing dashes. */
export function slugOf(label: string): string {
	return label
		.toLowerCase()
		.replace(/[äöüß]/g, (char) => UMLAUTS[char] ?? char)
		.normalize('NFKD')
		.replace(/[̀-ͯ]/g, '')
		.replace(/[^a-z0-9]+/g, '-')
		.replace(/^-+|-+$/g, '')
		.slice(0, 40)
		.replace(/-+$/, '');
}

/** Four random [a-z0-9] characters; `random` is injectable for tests. */
export function randomSuffix(random: () => number = Math.random): string {
	let suffix = '';
	for (let i = 0; i < 4; i++) suffix += RANDOM_CHARS[Math.floor(random() * RANDOM_CHARS.length)];
	return suffix;
}

/** Slug of the label plus the suffix; the suffix stays fixed while the label is typed. */
export function suggestClientId(label: string, suffix: string = randomSuffix()): string {
	const slug = slugOf(label);
	return slug === '' ? `client-${suffix}` : `${slug}-${suffix}`;
}

export function isValidClientId(id: string): boolean {
	return CLIENT_ID_PATTERN.test(id);
}

/** Labels are compared case-insensitively; `ownId` may keep its own label. */
export function labelTaken(
	label: string,
	entries: { id: string; label: string | null }[],
	ownId: string | null,
): boolean {
	const wanted = label.trim().toLowerCase();
	if (wanted === '') return false;
	return entries.some(
		(entry) => entry.id !== ownId && (entry.label ?? '').trim().toLowerCase() === wanted,
	);
}

/** One address per line or separated by commas; blanks dropped. */
export function splitAddresses(text: string): string[] {
	return text
		.split(/[\n,]/)
		.map((part) => part.trim())
		.filter((part) => part !== '');
}

/** RFC 1918, ULA, link-local: the addresses a home device has on the LAN. */
export function isLanAddress(ip: string): boolean {
	const v4 = /^(\d{1,3})\.(\d{1,3})\./.exec(ip);
	if (v4) {
		const first = Number(v4[1]);
		const second = Number(v4[2]);
		return (
			first === 10 ||
			(first === 172 && second >= 16 && second <= 31) ||
			(first === 192 && second === 168) ||
			(first === 169 && second === 254)
		);
	}
	return /^(f[cd]|fe[89ab])/i.test(ip);
}

/** Loose syntax check for a LAN address typed into the record sheet (IPv4 or IPv6 literal). */
export function isIpLiteral(value: string): boolean {
	const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(value);
	if (v4) return v4.slice(1).every((part) => Number(part) <= 255);
	return value.includes(':') && /^[0-9a-f:.]+$/i.test(value);
}
