/** Network-range parsing for IPv4 and IPv6. Pure, no DOM. Addresses compare as BigInt. */

export interface Cidr {
	family: 4 | 6;
	bits: number;
	prefix: number;
	address: bigint;
}

export interface InvalidRange {
	/** 1-based line number in the textarea, blank lines included. */
	line: number;
	text: string;
}

const BITS = { 4: 32, 6: 128 } as const;
const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const GROUP = /^[0-9a-fA-F]{1,4}$/;

function parseIpv4(text: string): bigint | null {
	const match = IPV4.exec(text);
	if (!match) return null;
	let value = 0n;
	for (const part of match.slice(1)) {
		const octet = Number(part);
		if (octet > 255) return null;
		value = (value << 8n) | BigInt(octet);
	}
	return value;
}

/** Groups of one side of "::". An embedded IPv4 tail counts as two groups. */
function ipv6Groups(part: string, allowV4: boolean): number[] | null {
	if (part === '') return [];
	const items = part.split(':');
	const groups: number[] = [];
	for (const [index, item] of items.entries()) {
		if (allowV4 && index === items.length - 1 && item.includes('.')) {
			const v4 = parseIpv4(item);
			if (v4 === null) return null;
			groups.push(Number(v4 >> 16n), Number(v4 & 0xffffn));
		} else if (GROUP.test(item)) {
			groups.push(parseInt(item, 16));
		} else {
			return null;
		}
	}
	return groups;
}

function parseIpv6(text: string): bigint | null {
	const halves = text.split('::');
	if (halves.length > 2) return null;
	const compressed = halves.length === 2;
	const head = ipv6Groups(halves[0], !compressed);
	const tail = compressed ? ipv6Groups(halves[1], true) : [];
	if (head === null || tail === null) return null;
	const missing = 8 - head.length - tail.length;
	if (compressed ? missing < 1 : missing !== 0) return null;
	const groups = [...head, ...Array<number>(compressed ? missing : 0).fill(0), ...tail];
	return groups.reduce((acc, group) => (acc << 16n) | BigInt(group), 0n);
}

/** A bare address, no prefix. */
export function parseIp(text: string): { family: 4 | 6; value: bigint } | null {
	if (text.includes(':')) {
		const value = parseIpv6(text);
		return value === null ? null : { family: 6, value };
	}
	const value = parseIpv4(text);
	return value === null ? null : { family: 4, value };
}

/** "address/prefix" with prefix 0-32 for IPv4 and 0-128 for IPv6. Surrounding spaces are ignored. */
export function parseCidr(text: string): Cidr | null {
	const parts = text.trim().split('/');
	if (parts.length !== 2 || !/^\d{1,3}$/.test(parts[1])) return null;
	const ip = parseIp(parts[0]);
	if (!ip) return null;
	const bits = BITS[ip.family];
	const prefix = Number(parts[1]);
	if (prefix > bits) return null;
	return { family: ip.family, bits, prefix, address: ip.value };
}

/** Parses every non-blank range; lines that are not ranges are dropped. */
export function parseRanges(lines: string[]): Cidr[] {
	return lines.map(parseCidr).filter((cidr): cidr is Cidr => cidr !== null);
}

/** Whether an address lies inside any of the ranges. Unparseable addresses never match. */
export function ipMatches(address: string, ranges: Cidr[]): boolean {
	const ip = parseIp(address.trim());
	if (!ip) return false;
	return ranges.some((range) => {
		if (range.family !== ip.family) return false;
		const shift = BigInt(range.bits - range.prefix);
		return ip.value >> shift === range.address >> shift;
	});
}

/** Longest prefix among the ranges that contain the address, or -1 when none does. */
export function bestPrefix(address: string, ranges: Cidr[]): number {
	const ip = parseIp(address.trim());
	if (!ip) return -1;
	let best = -1;
	for (const range of ranges) {
		if (range.family !== ip.family) continue;
		const shift = BigInt(range.bits - range.prefix);
		if (ip.value >> shift === range.address >> shift && range.prefix > best) best = range.prefix;
	}
	return best;
}

/** First line of a textarea that is not a range, or null when every non-blank line is valid. */
export function findInvalidRange(text: string): InvalidRange | null {
	const lines = text.split(/\r?\n/);
	for (const [index, raw] of lines.entries()) {
		const line = raw.trim();
		if (line !== '' && parseCidr(line) === null) return { line: index + 1, text: line };
	}
	return null;
}
