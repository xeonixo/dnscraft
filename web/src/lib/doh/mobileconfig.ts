import { parseIp } from '$lib/policy/cidr';
// Client-side builders for DNS over HTTPS/TLS: the DoH URL, the DoT/Android hostname and an Apple
// configuration profile (.mobileconfig). Pure: no DOM, no network. The Client ID is credential-like,
// so it only ever appears in the URL, the hostname, the payload identifiers, and as the fallback for
// the display name and file name when no label is set.

export type MobileConfigError = 'no_public_domain' | 'invalid_domain' | 'invalid_client_id';

export type Checked<T> = { ok: true; value: T } | { ok: false; error: MobileConfigError };

export type MobileConfigResult =
	{ ok: true; xml: string; fileName: string } | { ok: false; error: MobileConfigError };

export interface MobileConfigInput {
	publicDomain: string;
	clientId: string;
	label?: string | null;
	protocol?: 'https' | 'tls';
	homeSsid?: string | null;
	/** Optional bootstrap IPs of the DoH/DoT server (`ServerAddresses`); invalid entries are ignored. */
	serverAddresses?: string[];
	organization?: string;
}

const LABEL_MAX = 64;
const SSID_MAX = 32;
const ORGANIZATION_DEFAULT = 'DNScraft';

const CLIENT_ID = /^[a-z0-9][a-z0-9-]{0,62}$/;
const HOSTNAME =
	/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

// Control, lone-surrogate and noncharacter code points, plus bidi controls (RTL override and friends).
// Stripped from every free-text value before it reaches the XML.
const UNSAFE_TEXT = /[\p{Cc}\p{Cs}‎‏؜‪-‮⁦-⁩￾￿]/gu;

const XML_ESCAPES: Record<string, string> = {
	'&': '&amp;',
	'<': '&lt;',
	'>': '&gt;',
	'"': '&quot;',
	"'": '&apos;',
};

function checkDomain(raw: string): Checked<string> {
	const domain = raw.trim().toLowerCase();
	if (domain === '') return { ok: false, error: 'no_public_domain' };
	if (!HOSTNAME.test(domain)) return { ok: false, error: 'invalid_domain' };
	return { ok: true, value: domain };
}

function checkClientId(clientId: string): Checked<string> {
	if (!CLIENT_ID.test(clientId)) return { ok: false, error: 'invalid_client_id' };
	return { ok: true, value: clientId };
}

/** Strips unsafe code points, cuts to `max` code points, and trims. Empty string when nothing is left. */
function cleanText(value: string | null | undefined, max: number): string {
	if (!value) return '';
	return Array.from(value.replace(UNSAFE_TEXT, '')).slice(0, max).join('').trim();
}

function xml(value: string): string {
	return value.replace(/[&<>"']/g, (char) => XML_ESCAPES[char]);
}

/**
 * The certificate covers `dns.<publicDomain>` and `*.dns.<publicDomain>`, not the apex, so the DoH
 * host is `dns.<publicDomain>` unless the configured name already starts with a `dns.` label.
 */
function dohHost(domain: string): string {
	return domain.startsWith('dns.') ? domain : `dns.${domain}`;
}

/** https://dns.<publicDomain>/dns-query/<clientId> */
export function dohUrl(publicDomain: string, clientId: string): Checked<string> {
	const domain = checkDomain(publicDomain);
	if (!domain.ok) return domain;
	const id = checkClientId(clientId);
	if (!id.ok) return id;
	return {
		ok: true,
		value: `https://${dohHost(domain.value)}/dns-query/${encodeURIComponent(id.value)}`,
	};
}

/** <clientId>.dns.<publicDomain>: the DoT server name for iOS and the Android "Private DNS" host. */
export function dotHostname(publicDomain: string, clientId: string): Checked<string> {
	const domain = checkDomain(publicDomain);
	if (!domain.ok) return domain;
	const id = checkClientId(clientId);
	if (!id.ok) return id;
	return { ok: true, value: `${id.value}.dns.${domain.value}` };
}

// Deterministic 128-bit value from four 32-bit FNV-1a lanes with different seeds, each finished with
// murmur's fmix32 for spread. Not cryptographic: it only has to be stable and tell identifiers apart.
const LANE_SEEDS = [0x811c9dc5, 0x9e3779b9, 0x85ebca6b, 0xc2b2ae35];

function fnv1a(input: string, seed: number): number {
	let hash = seed;
	for (let i = 0; i < input.length; i++) {
		hash ^= input.charCodeAt(i);
		hash = Math.imul(hash, 0x01000193);
	}
	return hash >>> 0;
}

function fmix32(hash: number): number {
	let h = hash;
	h ^= h >>> 16;
	h = Math.imul(h, 0x85ebca6b);
	h ^= h >>> 13;
	h = Math.imul(h, 0xc2b2ae35);
	h ^= h >>> 16;
	return h >>> 0;
}

/** RFC 4122 layout (version 5 bits, variant 10xx), upper case. Same name gives the same UUID. */
function uuidFor(name: string): string {
	const bytes: number[] = [];
	for (const seed of LANE_SEEDS) {
		const lane = fmix32(fnv1a(name, seed));
		bytes.push(lane >>> 24, (lane >>> 16) & 0xff, (lane >>> 8) & 0xff, lane & 0xff);
	}
	bytes[6] = (bytes[6] & 0x0f) | 0x50;
	bytes[8] = (bytes[8] & 0x3f) | 0x80;
	const hex = bytes
		.map((byte) => byte.toString(16).padStart(2, '0'))
		.join('')
		.toUpperCase();
	return [
		hex.slice(0, 8),
		hex.slice(8, 12),
		hex.slice(12, 16),
		hex.slice(16, 20),
		hex.slice(20),
	].join('-');
}

/** Lower-case [a-z0-9-] slug of the label, or the Client ID when the label has no usable characters. */
function fileSlug(label: string, clientId: string): string {
	const slug = label
		.normalize('NFKD')
		.replace(/[̀-ͯ]/g, '')
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, '-')
		.replace(/^-+|-+$/g, '')
		.slice(0, 64)
		.replace(/-+$/, '');
	return slug || clientId;
}

/** Builds an Apple DNS-settings profile (DNSProtocol HTTPS, or TLS for DoT) for one Client ID. */
export function buildMobileConfig(input: MobileConfigInput): MobileConfigResult {
	const domain = checkDomain(input.publicDomain);
	if (!domain.ok) return domain;
	const id = checkClientId(input.clientId);
	if (!id.ok) return id;

	const clientId = id.value;
	const cleanLabel = cleanText(input.label, LABEL_MAX);
	const name = cleanLabel || clientId;
	const ssid = cleanText(input.homeSsid, SSID_MAX);
	const organization = cleanText(input.organization, LABEL_MAX) || ORGANIZATION_DEFAULT;
	const protocol = input.protocol ?? 'https';
	const addresses = (input.serverAddresses ?? [])
		.map((address) => address.trim())
		.filter((address, index, all) => parseIp(address) !== null && all.indexOf(address) === index);
	const serverAddresses =
		addresses.length === 0
			? ''
			: `\t\t\t\t<key>ServerAddresses</key>
\t\t\t\t<array>
${addresses.map((address) => `\t\t\t\t\t<string>${xml(address)}</string>`).join('\n')}
\t\t\t\t</array>
`;

	const payloadIdentifier = `app.dnscraft.dns.${clientId}`;
	const contentIdentifier = `${payloadIdentifier}.payload`;
	const displayName = xml(`DNScraft – ${name}`);
	const description = xml(
		"Sends this device's DNS queries to DNScraft over encrypted DNS. Installing again replaces this profile.",
	);

	const dnsSettings =
		protocol === 'tls'
			? `\t\t\t<key>DNSSettings</key>
\t\t\t<dict>
\t\t\t\t<key>DNSProtocol</key>
\t\t\t\t<string>TLS</string>
${serverAddresses}\t\t\t\t<key>ServerName</key>
\t\t\t\t<string>${xml(`${clientId}.dns.${domain.value}`)}</string>
\t\t\t</dict>`
			: `\t\t\t<key>DNSSettings</key>
\t\t\t<dict>
\t\t\t\t<key>DNSProtocol</key>
\t\t\t\t<string>HTTPS</string>
${serverAddresses}\t\t\t\t<key>ServerURL</key>
\t\t\t\t<string>${xml(`https://${dohHost(domain.value)}/dns-query/${encodeURIComponent(clientId)}`)}</string>
\t\t\t</dict>`;

	const onDemandRules = ssid
		? `\t\t\t<key>OnDemandRules</key>
\t\t\t<array>
\t\t\t\t<dict>
\t\t\t\t\t<key>Action</key>
\t\t\t\t\t<string>Disconnect</string>
\t\t\t\t\t<key>SSIDMatch</key>
\t\t\t\t\t<array>
\t\t\t\t\t\t<string>${xml(ssid)}</string>
\t\t\t\t\t</array>
\t\t\t\t</dict>
\t\t\t\t<dict>
\t\t\t\t\t<key>Action</key>
\t\t\t\t\t<string>Connect</string>
\t\t\t\t</dict>
\t\t\t</array>
`
		: '';

	const xmlText = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>PayloadContent</key>
\t<array>
\t\t<dict>
\t\t\t<key>PayloadType</key>
\t\t\t<string>com.apple.dnsSettings.managed</string>
\t\t\t<key>PayloadVersion</key>
\t\t\t<integer>1</integer>
\t\t\t<key>PayloadIdentifier</key>
\t\t\t<string>${xml(contentIdentifier)}</string>
\t\t\t<key>PayloadUUID</key>
\t\t\t<string>${uuidFor(contentIdentifier)}</string>
\t\t\t<key>PayloadDisplayName</key>
\t\t\t<string>${displayName}</string>
${dnsSettings}
${onDemandRules}\t\t</dict>
\t</array>
\t<key>PayloadDescription</key>
\t<string>${description}</string>
\t<key>PayloadDisplayName</key>
\t<string>${displayName}</string>
\t<key>PayloadIdentifier</key>
\t<string>${xml(payloadIdentifier)}</string>
\t<key>PayloadOrganization</key>
\t<string>${xml(organization)}</string>
\t<key>PayloadType</key>
\t<string>Configuration</string>
\t<key>PayloadUUID</key>
\t<string>${uuidFor(payloadIdentifier)}</string>
\t<key>PayloadVersion</key>
\t<integer>1</integer>
</dict>
</plist>
`;

	return {
		ok: true,
		xml: xmlText,
		fileName: `dnscraft-${fileSlug(cleanLabel, clientId)}.mobileconfig`,
	};
}
