// Deterministic query-log fixtures for the local mock control-api (web/mock/server.mjs).
// Shapes follow crates/dnscraft-api/src/query_log.rs (record JSON). Nothing here is random: the same
// build always serves the same rows, so screenshots and tests stay stable.

export const RECORD_COUNT = 200;

/** The newest record. Records step back in time by 47 seconds each. */
const NEWEST_MS = Date.parse('2026-10-27T12:00:00Z');
const STEP_MS = 47_000;

export const PROTOCOLS = ['udp53', 'tcp53', 'dot', 'doh', 'doq'];
export const VIEWS = ['lan', 'guest'];
export const PROFILES = ['default', 'kids'];

/** Clients from the device directory; `id: null` is a query from an unknown address. */
const CLIENTS = [
	{
		id: 'iphone-k7q2x9',
		name: 'iPhone',
		ip: '192.0.2.11',
		macs: ['aa:bb:cc:00:00:11'],
		vlan: [40, 'IoT'],
	},
	{
		id: 'macbook-r4t8vn',
		name: 'MacBook',
		ip: '192.0.2.4',
		macs: ['aa:bb:cc:00:00:04'],
		vlan: null,
	},
	{ id: 'tv-8d2f1a', name: 'Wohnzimmer-TV', ip: '192.0.2.18', macs: [], vlan: [40, 'IoT'] },
	{ id: 'tablet-x9q2m', name: 'Tablet', ip: '192.0.2.22', macs: [], vlan: null },
	{ id: null, name: null, ip: '198.51.100.7', macs: [], vlan: null },
	{
		id: 'long-client-0001',
		name: `Gerät ${'x'.repeat(180)}`,
		ip: '192.0.2.30',
		macs: [],
		vlan: null,
	},
	{ id: 'bidi-client-0002', name: 'Drucker‮gnp', ip: '192.0.2.31', macs: [], vlan: null },
];

/**
 * Owner names as the API stores them: ASCII (punycode for IDN). The last entries are hostile on
 * purpose: markup, quote breaking, NUL, newline and a bidi override.
 */
const DOMAINS = [
	'www.example.com',
	'cdn.example.net',
	'api.example.org',
	'tracker.example',
	'ads.tracker.example',
	'stats.example.org',
	'xn--bcher-kva.example',
	'xn--mnchen-3ya.de',
	'<script>alert(1)</script>',
	'"><img src=x onerror=alert(1)>',
	'bad\u0000name.example',
	'line\nbreak.example',
	'evil‮gnp.example',
	[1, 2, 3, 4].map((n) => `${String.fromCharCode(96 + n).repeat(63)}`).join('.') + '.example',
];

const LIST_IDS = ['adguard-dns-filter', 'stevenblack-hosts'];

function isoMicros(ms) {
	return new Date(ms).toISOString().replace('Z', '000Z');
}

/** Source address as stored: the last octet is cut for every second record (privacy setting). */
function storedIp(ip, index) {
	if (index % 2 === 0) return { ip: ip.replace(/\.\d+$/, '.0'), truncated: true };
	return { ip, truncated: false };
}

function stepsFor(outcome, index) {
	const steps = [
		{
			stage: 'select',
			verdict: 'selected',
			selection:
				index % 3 === 0 ? { cause: 'default' } : { cause: 'subnet', prefix: '192.0.2.0/24' },
		},
	];
	if (outcome === 'blocked') {
		if (index % 5 === 0) steps.push({ stage: 'local_view', verdict: 'answered' });
		steps.push({ stage: 'filter_qname', verdict: 'blocked' });
		return steps;
	}
	if (index % 7 === 0) steps.push({ stage: 'rebind', verdict: 'stripped', count: 2 });
	if (index % 17 === 0) {
		steps.push({
			stage: 'safesearch',
			verdict: 'rewritten',
			provider: 'search.example',
			target: 'safe.search.example',
		});
	}
	if (outcome === 'servfail') {
		steps.push({ stage: 'resolve', verdict: 'failed', cause_code: 'resolver.timeout' });
		return steps;
	}
	steps.push({
		stage: 'resolve',
		verdict: 'resolved',
		source: index % 3 === 0 ? 'cache' : 'recursion',
		dnssec: outcome === 'dnssec_bogus' ? 'bogus' : 'secure',
	});
	return steps;
}

/** Builds the fixture rows, newest first. */
export function buildRecords() {
	const records = [];
	for (let index = 0; index < RECORD_COUNT; index++) {
		const client = CLIENTS[index % CLIENTS.length];
		const domain = DOMAINS[(index * 7) % DOMAINS.length];
		const blocked = index % 4 === 0;
		const servfail = !blocked && index % 29 === 0;
		const bogus = !blocked && !servfail && index % 11 === 0;
		const outcome = blocked
			? 'blocked'
			: servfail
				? 'servfail'
				: bogus
					? 'dnssec_bogus'
					: 'allowed';
		const { ip, truncated } = storedIp(client.ip, index);
		const filter = blocked
			? {
					reason: index % 12 === 0 ? 'custom' : 'list',
					block_mode: index % 8 === 0 ? 'refused' : 'nxdomain',
					rule_text: index % 37 === 0 ? `||${'z'.repeat(300)}^` : `||${domain}^`,
					list_id: index % 12 === 0 ? null : LIST_IDS[index % LIST_IDS.length],
					important: index % 16 === 0,
				}
			: index % 9 === 0
				? {
						reason: 'temporary_allow',
						block_mode: null,
						rule_text: null,
						list_id: null,
						important: false,
					}
				: null;
		const [vlanId, vlanName] = client.vlan ?? [null, null];
		records.push({
			id: `rec-${String(index).padStart(4, '0')}`,
			node_id: index % 3 === 0 ? 'node2' : 'node1',
			listener_id: index % 2 === 0 ? 'lan-udp' : 'doh-main',
			protocol: PROTOCOLS[index % PROTOCOLS.length],
			source_ip: ip,
			source_ip_truncated: truncated,
			client_id: client.id,
			client:
				client.id === null
					? null
					: {
							id: `dir-${client.id}`,
							display_name: client.name,
							source: 'unifi',
							macs: client.macs,
							vlan_id: vlanId,
							vlan_name: vlanName,
							local_domain: null,
						},
			query: { name: domain, type: index % 4 === 1 ? 'AAAA' : 'A', class: 'IN' },
			view_id: VIEWS[index % VIEWS.length],
			profile_id: PROFILES[index % PROFILES.length],
			filter_set: 'default',
			selection:
				index % 3 === 0 ? { cause: 'default' } : { cause: 'subnet', prefix: '192.0.2.0/24' },
			steps: stepsFor(outcome, index),
			answer_source: blocked ? 'filter_block' : index % 3 === 0 ? 'cache' : 'resolver',
			filter,
			dnssec: blocked ? null : bogus ? 'bogus' : 'secure',
			forward_zone: index % 9 === 0 ? 'corp.example' : null,
			rcode: blocked
				? filter?.block_mode === 'refused'
					? 'REFUSED'
					: 'NXDOMAIN'
				: servfail
					? 'SERVFAIL'
					: 'NOERROR',
			answer_size: blocked ? 0 : 60 + (index % 5) * 32,
			timings: {
				select_us: 2 + (index % 4),
				filter_us: 8 + (index % 11),
				resolve_us: blocked ? 0 : 300 + ((index * 37) % 900),
				total_us: 320 + ((index * 37) % 900),
			},
			time: isoMicros(NEWEST_MS - index * STEP_MS),
		});
	}
	return records;
}

/**
 * A complete configuration snapshot as `GET /api/v1/config` returns it (secrets are never part of it).
 * The shape is the one config_apply.rs stores; the mock does not validate every module field.
 * The MCP rule domain is hostile on purpose: the UI must show it as inert text.
 */
export function initialConfig() {
	return {
		filtering: {
			sets: [
				{
					id: 'default',
					name: 'Standard',
					lists: ['ads-main', 'trackers-main'],
					custom_rules: '',
					services: [],
					block_mode: 'refused',
					mcp_rules: [
						{
							id: 'mcp-rule-0001',
							domain: 'example.com',
							include_subdomains: true,
							created_at: '2026-10-26T08:00:00Z',
							expires_at: null,
							token_id: null,
						},
						{
							id: 'mcp-rule-0002',
							domain: '<img src=x onerror=alert(1)>.example.test',
							include_subdomains: false,
							created_at: '2026-10-26T09:30:00Z',
							expires_at: '2026-11-26T09:30:00Z',
							token_id: 'tok-0001',
						},
					],
				},
				{
					id: 'kids',
					name: 'Kinder',
					lists: ['ads-main'],
					custom_rules: '',
					services: ['social-video'],
					block_mode: 'nxdomain',
					mcp_rules: [],
				},
			],
			lists: [
				{
					id: 'ads-main',
					name: 'AdGuard DNS',
					source: { url: 'https://adguard-dns.io/dns-filter.txt' },
					enabled: true,
				},
				{
					id: 'trackers-main',
					name: 'Tracking protection',
					source: { url: 'https://example.com/lists/trackers.txt' },
					enabled: true,
				},
			],
		},
		clients: {
			manual: [
				{
					name: 'Wohnzimmer-TV',
					ip: '192.0.2.18',
					cidr: null,
					domain: 'tv.lan',
					identity: '192.0.2.18',
				},
			],
		},
		resolver: {
			forward_zones: [
				{
					id: 'site-a',
					zone: 'site-a.example.com.',
					targets: ['10.9.0.53:53'],
					validate: false,
				},
			],
		},
		policy: {
			records: [
				{
					name: 'nas.lan.',
					type: 'A',
					ttl: 60,
					rdata: '192.0.2.50',
					overrides: { guest: '192.0.2.51' },
				},
				{
					name: '<script>alert(1)</script>.evil.test.',
					type: 'A',
					ttl: 60,
					rdata: '192.0.2.99',
					overrides: {},
				},
			],
			client_ids: ['iphone-k7q2x9', 'guest-j4m2pz'],
			views: [
				{
					id: 'lan',
					is_default: true,
					subnets: ['192.0.2.0/24'],
					nodes: [],
					profile: 'default',
				},
				{
					id: 'guest',
					is_default: false,
					subnets: ['198.51.100.0/24'],
					nodes: [],
					profile: 'kids',
				},
			],
			profiles: [
				{
					id: 'default',
					filter_set: 'default',
					suppress_aaaa: false,
					firefox_canary: false,
					icloud_private_relay: false,
					rebind: null,
					rebind_exceptions: [],
					forward_zones: null,
					safesearch: null,
					schedules: [],
				},
				{
					id: 'kids',
					filter_set: 'kids',
					suppress_aaaa: true,
					firefox_canary: false,
					icloud_private_relay: false,
					rebind: null,
					rebind_exceptions: [],
					forward_zones: null,
					safesearch: 'strict',
					schedules: [],
				},
			],
		},
		listeners: { items: [] },
		tls: { mode: 'self_signed' },
	};
}

/** Directory rows returned by `GET /api/v1/clients` (synced). */
export const MOCK_DIRECTORY_CLIENTS = [
	{
		id: 'dir-iphone-k7q2x9',
		name: 'iPhone',
		dns_label: 'iphone',
		local_domain: 'home.arpa',
		source: 'unifi',
		ips: ['192.0.2.11'],
		macs: ['aa:bb:cc:00:00:11'],
		vlan: 40,
		online: true,
		last_seen: '2026-10-27T11:58:00Z',
	},
	{
		id: 'dir-macbook-r4t8vn',
		name: 'MacBook',
		dns_label: 'macbook',
		local_domain: 'home.arpa',
		source: 'unifi',
		ips: ['192.0.2.4'],
		macs: ['aa:bb:cc:00:00:04'],
		vlan: null,
		online: false,
		last_seen: '2026-10-27T10:12:00Z',
	},
];
