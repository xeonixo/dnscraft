// Deterministic example data for the local mock control-api (web/mock/server.mjs). Shapes follow
// crates/dnscraft-api/src/query_log.rs (record JSON) and the snapshot config_apply.rs stores.
// The generator is seeded, so a build always serves the same rows and config. Only the clock is live:
// records are placed relative to the moment this module loads (the server start), so the 15 min to
// 30 d presets always have data and the newest rows are recent. Nothing here is a real person,
// host or vendor account; IPs are documentation ranges (RFC 5737, RFC 3849).

export const RECORD_COUNT = 2500;
export const PROTOCOLS = ['udp53', 'tcp53', 'dot', 'doh', 'doq'];

const SEED = 0x5eedc0de;
const MINUTE_MS = 60_000;
const HOUR_MS = 60 * MINUTE_MS;
const DAY_MS = 24 * HOUR_MS;
/** Server start: the reference for every relative time in these fixtures. */
const NOW_MS = Date.now();
const LOCAL_DOMAIN = 'home.arpa';

/** [records, from, to) as ages before the server start. Newest first when sorted; sums to RECORD_COUNT. */
const AGE_BUCKETS = [
	[6, 0, 15 * MINUTE_MS],
	[34, 15 * MINUTE_MS, HOUR_MS],
	[360, HOUR_MS, DAY_MS],
	[700, DAY_MS, 7 * DAY_MS],
	[1400, 7 * DAY_MS, 30 * DAY_MS],
];

/** Views: the documentation subnet each selects. Clients are placed in the view of their subnet. */
const VIEW_SUBNET = { lan: '192.0.2.0/24', guest: '198.51.100.0/24', iot: '203.0.113.0/24' };
const LISTENER_FOR = {
	udp53: 'lan-udp',
	tcp53: 'lan-tcp',
	dot: 'dot-public',
	doh: 'doh-local',
	doq: 'doq-public',
};
/** Protocol mix per network group (kids devices use DoH through the local proxy). */
const PROTOCOL_MIX = {
	lan: [
		['udp53', 58],
		['tcp53', 4],
		['dot', 12],
		['doh', 22],
		['doq', 4],
	],
	guest: [
		['udp53', 55],
		['doh', 35],
		['dot', 10],
	],
	kids: [
		['doh', 70],
		['udp53', 25],
		['dot', 5],
	],
	iot: [
		['udp53', 95],
		['tcp53', 4],
		['dot', 1],
	],
};

/**
 * Devices. `id: null` is a query from an address the directory does not know. `weight` is the share
 * of queries; `mix` picks the kinds of name the device asks for (KIND_MIX).
 */
const CLIENTS = [
	{
		id: 'iphone-k7q2x9',
		label: 'iphone-anna',
		name: 'iPhone von Anna',
		ip: '192.0.2.11',
		ip6: '2001:db8:0:1::11',
		macs: ['aa:bb:cc:00:00:11'],
		source: 'unifi',
		vlan: null,
		view: 'lan',
		profile: 'default',
		mix: 'phone',
		weight: 14,
	},
	{
		id: 'macbook-r4t8vn',
		label: 'macbook-pro',
		name: 'MacBook Pro',
		ip: '192.0.2.4',
		ip6: '2001:db8:0:1::4',
		macs: ['aa:bb:cc:00:00:04'],
		source: 'unifi',
		vlan: null,
		view: 'lan',
		profile: 'default',
		mix: 'laptop',
		weight: 12,
	},
	{
		id: 'macbook-air-ben',
		label: 'macbook-air-ben',
		name: 'MacBook Air (Ben)',
		ip: '192.0.2.5',
		macs: ['aa:bb:cc:00:00:05'],
		source: 'unifi',
		vlan: null,
		view: 'lan',
		profile: 'default',
		mix: 'laptop',
		weight: 6,
	},
	{
		id: 'pixel-8-jonas',
		label: 'pixel-8',
		name: 'Pixel 8 Jonas',
		ip: '192.0.2.14',
		ip6: '2001:db8:0:1::14',
		macs: ['aa:bb:cc:00:00:14'],
		source: 'dhcp',
		vlan: null,
		view: 'lan',
		profile: 'default',
		mix: 'phone',
		weight: 6,
	},
	{
		id: 'ipad-lena',
		label: 'ipad-lena',
		name: 'iPad Lena',
		ip: '192.0.2.15',
		macs: ['aa:bb:cc:00:00:15'],
		source: 'unifi',
		vlan: null,
		view: 'lan',
		profile: 'default',
		mix: 'phone',
		weight: 2,
	},
	{
		id: 'nas-d4n7x2',
		label: 'nas',
		name: 'NAS',
		ip: '192.0.2.50',
		macs: ['aa:bb:cc:00:00:50'],
		source: 'manual',
		vlan: null,
		view: 'lan',
		profile: 'default',
		mix: 'nas',
		weight: 2,
	},
	{
		id: 'ha-core-c8v6',
		label: 'home-assistant',
		name: 'Home Assistant',
		ip: '192.0.2.60',
		macs: ['aa:bb:cc:00:00:60'],
		source: 'manual',
		vlan: null,
		view: 'lan',
		profile: 'default',
		mix: 'ha',
		weight: 6,
	},
	{
		id: 'drucker-f2r7',
		label: 'drucker-flur',
		name: 'Drucker Flur',
		ip: '192.0.2.40',
		macs: ['aa:bb:cc:00:00:40'],
		source: 'unifi',
		vlan: null,
		view: 'lan',
		profile: 'default',
		mix: 'printer',
		weight: 1,
	},
	{
		id: 'long-client-0001',
		label: 'long-client',
		name: `Gerät ${'x'.repeat(180)}`,
		ip: '192.0.2.30',
		macs: [],
		source: 'dhcp',
		vlan: null,
		view: 'lan',
		profile: 'default',
		mix: 'laptop',
		weight: 0.5,
	},
	{
		id: 'bidi-client-0002',
		label: 'drucker-bidi',
		name: 'Drucker‮gnp',
		ip: '192.0.2.31',
		macs: [],
		source: 'dhcp',
		vlan: null,
		view: 'lan',
		profile: 'default',
		mix: 'printer',
		weight: 0.5,
	},
	{
		id: 'gaeste-laptop-w6t3',
		label: 'gaeste-laptop',
		name: 'Gäste-Laptop',
		ip: '198.51.100.20',
		macs: ['aa:bb:cc:00:01:20'],
		source: 'unifi',
		vlan: [30, 'Gäste'],
		view: 'guest',
		profile: 'guests',
		mix: 'guest',
		weight: 2,
	},
	{
		id: 'gast-handy-m9z4',
		label: 'gast-handy',
		name: 'Gast-Handy',
		ip: '198.51.100.21',
		ip6: '2001:db8:0:3::21',
		macs: ['aa:bb:cc:00:01:21'],
		source: 'dhcp',
		vlan: [30, 'Gäste'],
		view: 'guest',
		profile: 'guests',
		mix: 'phone',
		weight: 2,
	},
	{
		id: 'kinder-tablet-q8j1',
		label: 'kinder-tablet',
		name: 'Kinder-Tablet',
		ip: '198.51.100.22',
		macs: ['aa:bb:cc:00:02:22'],
		source: 'unifi',
		vlan: [20, 'Kinder'],
		view: 'guest',
		profile: 'kids',
		mix: 'kids',
		weight: 4,
	},
	{
		id: 'tv-8d2f1a',
		label: 'wohnzimmer-tv',
		name: 'Wohnzimmer-TV',
		ip: '203.0.113.18',
		macs: ['aa:bb:cc:00:03:18'],
		source: 'unifi',
		vlan: [40, 'IoT'],
		view: 'iot',
		profile: 'iot',
		mix: 'tv',
		weight: 8,
	},
	{
		id: 'ps5-z3c5b8',
		label: 'playstation-5',
		name: 'PlayStation 5',
		ip: '203.0.113.21',
		macs: ['aa:bb:cc:00:03:21'],
		source: 'unifi',
		vlan: [40, 'IoT'],
		view: 'iot',
		profile: 'iot',
		mix: 'ps5',
		weight: 6,
	},
	{
		id: 'sonos-kueche-y4r2',
		label: 'sonos-kueche',
		name: 'Sonos Küche',
		ip: '203.0.113.24',
		macs: ['aa:bb:cc:00:03:24'],
		source: 'unifi',
		vlan: [40, 'IoT'],
		view: 'iot',
		profile: 'iot',
		mix: 'iot',
		weight: 4,
	},
	{
		id: 'kamera-garage-e1n7',
		label: 'kamera-garage',
		name: 'Kamera Garage',
		ip: '203.0.113.33',
		macs: ['aa:bb:cc:00:03:33'],
		source: 'unifi',
		vlan: [40, 'IoT'],
		view: 'iot',
		profile: 'iot',
		mix: 'iot',
		weight: 4,
	},
	{
		id: 'tado-thermostat-k2p8',
		label: 'thermostat-flur',
		name: 'Thermostat Flur',
		ip: '203.0.113.40',
		macs: ['aa:bb:cc:00:03:40'],
		source: 'unifi',
		vlan: [40, 'IoT'],
		view: 'iot',
		profile: 'iot',
		mix: 'iot',
		weight: 3,
	},
	{
		id: 'saugroboter-u6h3',
		label: 'saugroboter',
		name: 'Saugroboter',
		ip: '203.0.113.41',
		macs: ['aa:bb:cc:00:03:41'],
		source: 'dhcp',
		vlan: [40, 'IoT'],
		view: 'iot',
		profile: 'iot',
		mix: 'iot',
		weight: 2,
	},
	{
		id: 'shelly-plug-b9s4',
		label: 'shelly-steckdose',
		name: 'Shelly Steckdose',
		ip: '203.0.113.50',
		macs: ['aa:bb:cc:00:03:50'],
		source: 'dhcp',
		vlan: [40, 'IoT'],
		view: 'iot',
		profile: 'iot',
		mix: 'iot',
		weight: 3,
	},
	// Queries from addresses with no directory entry (IP only, no client id).
	{
		id: null,
		name: null,
		ip: '198.51.100.7',
		macs: [],
		view: 'guest',
		profile: 'guests',
		mix: 'phone',
		weight: 1.5,
	},
	{
		id: null,
		name: null,
		ip: '192.0.2.99',
		macs: [],
		view: 'lan',
		profile: 'default',
		mix: 'laptop',
		weight: 1,
	},
	{
		id: null,
		name: null,
		ip: '2001:db8:0:9::77',
		macs: [],
		view: 'lan',
		profile: 'default',
		mix: 'phone',
		weight: 0.5,
	},
];

/** Kinds of name each device mix asks for. Kinds are picked, then a name of that kind. */
const KIND_MIX = {
	phone: {
		site: 30,
		social: 4,
		cdn: 15,
		vendor: 12,
		system: 5,
		ntp: 1,
		ad: 12,
		tracker: 8,
		telemetry: 2,
		malware: 0.1,
		phish: 0.1,
		typo: 1.2,
		junk: 1.2,
		local: 0.5,
		idn: 0.4,
		long: 0.1,
		hostile: 0.05,
	},
	laptop: {
		site: 36,
		social: 3,
		cdn: 16,
		vendor: 12,
		system: 4,
		ntp: 1,
		ad: 8,
		tracker: 6,
		telemetry: 2,
		malware: 0.2,
		phish: 0.2,
		typo: 2,
		junk: 1,
		local: 1.5,
		idn: 0.4,
		corp: 3,
		long: 0.1,
		hostile: 0.05,
	},
	kids: {
		site: 34,
		social: 10,
		cdn: 16,
		vendor: 8,
		system: 3,
		ad: 12,
		tracker: 6,
		telemetry: 1,
		typo: 3,
		junk: 1,
		phish: 0.5,
		malware: 0.3,
		local: 0.5,
		idn: 0.3,
	},
	guest: {
		site: 34,
		social: 3,
		cdn: 16,
		vendor: 10,
		system: 4,
		ad: 14,
		tracker: 9,
		telemetry: 2,
		malware: 0.4,
		phish: 0.4,
		typo: 2,
		junk: 2,
		idn: 0.3,
		long: 0.1,
	},
	tv: { telemetry: 24, cdn: 26, site: 14, vendor: 10, ad: 12, tracker: 9, ntp: 3, system: 2 },
	ps5: {
		telemetry: 22,
		cdn: 26,
		vendor: 24,
		site: 10,
		ntp: 4,
		ad: 6,
		tracker: 6,
		system: 2,
		junk: 1,
	},
	iot: {
		telemetry: 30,
		vendor: 26,
		ntp: 12,
		system: 8,
		cdn: 12,
		junk: 5,
		local: 3,
		tracker: 2,
		typo: 1,
	},
	nas: { local: 14, vendor: 26, ntp: 16, system: 10, cdn: 12, site: 14, srv: 6 },
	ha: {
		vendor: 30,
		local: 22,
		cdn: 10,
		telemetry: 12,
		ntp: 5,
		system: 5,
		site: 10,
		srv: 3,
		junk: 1,
		typo: 1,
	},
	printer: { vendor: 36, ntp: 24, system: 20, local: 8, cdn: 6, srv: 6 },
};

/** Query types with their share of the traffic. A, AAAA and HTTPS dominate. */
const TYPE_WEIGHTS = [
	['A', 34],
	['AAAA', 26],
	['HTTPS', 14],
	['PTR', 3],
	['SRV', 1.5],
	['TXT', 1.5],
	['MX', 0.8],
	['CNAME', 7],
	['NS', 0.4],
	['SOA', 0.6],
	['CAA', 0.5],
	['SVCB', 0.8],
	['DS', 0.3],
	['DNSKEY', 0.3],
	['ANY', 0.4],
	['NULL', 0.15],
];
/** Answer sizes in bytes on the wire, per type (a typical answer, not the largest). */
const ANSWER_SIZE = {
	A: [48, 96],
	AAAA: [60, 120],
	HTTPS: [70, 130],
	SVCB: [90, 150],
	CNAME: [60, 110],
	MX: [70, 130],
	TXT: [120, 300],
	NS: [90, 160],
	SOA: [90, 120],
	CAA: [60, 90],
	SRV: [110, 170],
	PTR: [70, 120],
	DS: [110, 150],
	DNSKEY: [260, 420],
	ANY: [300, 520],
	NULL: [30, 60],
};
const WEB_TYPES = new Set(['A', 'AAAA', 'HTTPS', 'SVCB', 'CNAME', 'ANY']);
const APEX_TYPES = new Set(['NS', 'SOA', 'MX', 'TXT', 'CAA', 'DS', 'DNSKEY']);
const NXDOMAIN_KINDS = new Set(['typo', 'junk', 'hostile', 'long']);
const SERVFAIL_KINDS = new Set(['site', 'social', 'cdn', 'vendor', 'system', 'ntp']);
const SIGNED_KINDS = new Set(['site', 'social', 'cdn', 'vendor', 'ntp', 'corp']);
/** Share of blockable queries the filter lists catch, by kind. */
const BLOCK_RATE = { ad: 0.97, tracker: 0.96, telemetry: 0.88, malware: 1, phish: 1 };
/** Which list a kind is blocked by when the filter set carries it. */
const PREFERRED_LIST = {
	ad: 'adguard-dns-filter',
	tracker: 'adguard-dns-filter',
	phish: 'adguard-dns-filter',
	telemetry: 'stevenblack-hosts',
	malware: 'stevenblack-hosts',
};
/** Blocked by a user custom rule (see the custom_rules of the filter sets), not by a list. */
const CUSTOM_BLOCK = [
	'graph.facebook.com',
	'mobile.events.data.microsoft.com',
	'browser.events.data.msn.com',
	'log-ingestion.samsungacr.com',
	'eu-acr.alphonso.tv',
	'stats.tado.com',
];

/** Name pools per kind. Earlier entries are the popular ones (see `popular`). */
const POOL = {
	site: [
		'google.com',
		'apple.com',
		'microsoft.com',
		'netflix.com',
		'spotify.com',
		'github.com',
		'wikipedia.org',
		'de.wikipedia.org',
		'www.example.com',
		'heise.de',
		'www.heise.de',
		'tagesschau.de',
		'spiegel.de',
		'zeit.de',
		'amazon.de',
		'ebay.de',
		'mozilla.org',
		'debian.org',
		'kernel.org',
		'bbc.co.uk',
		'reddit.com',
		'stackoverflow.com',
		'dropbox.com',
		'duckduckgo.com',
		'proton.me',
		'ubuntu.com',
		'otto.de',
		'dw.com',
		'news.ycombinator.com',
		'hetzner.com',
		'npr.org',
		'paypal.com',
	],
	social: [
		'tiktok.com',
		'instagram.com',
		'youtube.com',
		'twitch.tv',
		'snapchat.com',
		'discord.com',
	],
	cdn: [
		'd111abc12xyz.cloudfront.net',
		'd2k7nq5wv3hl1x.cloudfront.net',
		'e4567.dsce9.akamaiedge.net',
		'a1.akamaized.net',
		'static.xx.fbcdn.net',
		'cdn.jsdelivr.net',
		'ajax.googleapis.com',
		'fonts.gstatic.com',
		'j.sni.global.fastly.net',
		'assets.ctfassets.net',
		'images-na.ssl-images-amazon.com',
		'cdn.example.net',
	],
	vendor: [
		'gateway.icloud.com',
		'configuration.apple.com',
		'swcdn.apple.com',
		'settings-win.data.microsoft.com',
		'dl.google.com',
		'play.googleapis.com',
		'api.spotify.com',
		'api.github.com',
		'store-eu.steampowered.com',
		'auth.np.ac.playstation.net',
		'api.netflix.com',
		'api.tado.com',
		'api.sonos.com',
		'device.sonos.com',
		'api.smartthings.com',
		'api.shelly.cloud',
		'api.example.org',
		'update.plex.tv',
	],
	ntp: [
		'pool.ntp.org',
		'0.de.pool.ntp.org',
		'1.de.pool.ntp.org',
		'2.pool.ntp.org',
		'time.apple.com',
		'time.cloudflare.com',
		'time.google.com',
		'ntp.ubuntu.com',
	],
	system: [
		'connectivitycheck.gstatic.com',
		'captive.apple.com',
		'www.msftconnecttest.com',
		'detectportal.firefox.com',
		'nmcheck.gnome.org',
		'network-test.debian.org',
	],
	ad: [
		'doubleclick.net',
		'ad.doubleclick.net',
		'googlesyndication.com',
		'pagead2.googlesyndication.com',
		'adservice.google.com',
		'ads.yahoo.com',
		'adnxs.com',
		'criteo.com',
		'taboola.com',
		'outbrain.com',
		'pubmatic.com',
		'rubiconproject.com',
		'smartadserver.com',
		'adform.net',
		'ads.linkedin.com',
		'ads.twitter.com',
		'ads.tracker.example',
	],
	tracker: [
		'google-analytics.com',
		'www.google-analytics.com',
		'scorecardresearch.com',
		'hotjar.com',
		'mouseflow.com',
		'mixpanel.com',
		'segment.io',
		'branch.io',
		'adjust.com',
		'crazyegg.com',
		'quantserve.com',
		'bat.bing.com',
		'c.clarity.ms',
		'tr.snapchat.com',
		'tracker.example',
	],
	telemetry: [
		'app-measurement.com',
		'graph.facebook.com',
		'metrics.icloud.com',
		'mobile.events.data.microsoft.com',
		'browser.events.data.msn.com',
		'log-ingestion.samsungacr.com',
		'eu-acr.alphonso.tv',
		'stats.tado.com',
		'telemetry.shelly.cloud',
		'firebaselogging-pa.googleapis.com',
		'stats.example.org',
	],
	malware: ['c2-beacon-7f3.test', 'dropper-cdn-77.test', 'crypto-miner-pool.test'],
	phish: [
		'secure-acc0unt-check.test',
		'parcel-redelivery-fee.test',
		'winupdate-driver-pack.test',
		'free-iptv-stream-hd.test',
		'crypto-airdrop-claim.test',
	],
	local: [
		'nas.home.arpa',
		'nas.lan',
		'printer.fritz.box',
		'ha.home.arpa',
		'kamera-garage.home.arpa',
		'wohnzimmer-tv.home.arpa',
		'sonos-kueche.home.arpa',
		'router.home.arpa',
	],
	idn: ['xn--mnchen-3ya.de', 'xn--bcher-kva.example', 'xn--wgv71a119e.jp', 'xn--n3h.example'],
	typo: [
		'gogle.com',
		'wikpedia.org',
		'githb.com',
		'netflx.com',
		'amazn.de',
		'youtub.com',
		'spotfy.com',
		'goolge.de',
		'mircosoft.com',
	],
	corp: ['intranet.corp.example', 'git.corp.example', 'vpn.corp.example', 'wiki.corp.example'],
	// The markup, quote and control-character names are kept on purpose: the UI must show them as inert text.
	hostile: [
		'<script>alert(1)</script>',
		'"><img src=x onerror=alert(1)>',
		'bad\u0000name.example',
		'line\nbreak.example',
		'evil‮gnp.example',
	],
	long: [
		`${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(63)}.example`,
		`telemetry-batch-${'z'.repeat(40)}.metrics.example`,
	],
	srv: [
		'_sip._tcp.example.com',
		'_xmpp-client._tcp.example.org',
		'_submission._tcp.mail.example.com',
		'_imaps._tcp.example.de',
		'_ldap._tcp.dc._msdcs.corp.example',
		'_kerberos._udp.corp.example',
		'_ipp._tcp.home.arpa',
		'_googlecast._tcp.home.arpa',
		'_matrix._tcp.example.org',
	],
};
const JUNK_ZONES = [
	'trk-collect.example',
	'ping-edge.example',
	'beacon-sync.example',
	'cdn-probe.example',
];
/** Names queried as CNAME type; they resolve normally, no chain is modelled. */
const CNAME_NAMES = ['www.example.com', 'www.heise.de'];
/**
 * First-party-looking names whose CNAME target is a tracker. The resolver uncloaks them in the
 * answer chain and blocks the answer (answer_chain blocked); the query name itself is not blocked.
 */
const CLOAKED_TARGETS = {
	'metrics.example-shop.test': 'collect.adtech-hub.example',
	'stats.news-site.test': 'sc.trackerhub.example',
};

function mulberry32(seed) {
	let state = seed >>> 0;
	return () => {
		state = (state + 0x6d2b79f5) >>> 0;
		let t = state;
		t = Math.imul(t ^ (t >>> 15), t | 1);
		t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	};
}

const pickWeighted = (rng, items) => {
	const total = items.reduce((sum, [, weight]) => sum + weight, 0);
	let roll = rng() * total;
	for (const [value, weight] of items) {
		roll -= weight;
		if (roll < 0) return value;
	}
	return items[items.length - 1][0];
};
const pick = (rng, list) => list[Math.floor(rng() * list.length)];
const between = (rng, min, max) => min + Math.floor(rng() * (max - min + 1));
/** Earlier entries are more popular: a Zipf-like preference by position. */
const popular = (rng, list) =>
	pickWeighted(
		rng,
		list.map((name, index) => [name, 1 / (index + 1.5)]),
	);

const rfc3339 = (ms) => new Date(ms).toISOString().replace('.000Z', 'Z');
function isoMicros(ms) {
	return new Date(ms).toISOString().replace('Z', '000Z');
}

const reverseName = (ipv4) => `${ipv4.split('.').reverse().join('.')}.in-addr.arpa`;

/** The stored source address: the last octet (or the last IPv6 group) is cut for privacy. */
function truncateAddress(address) {
	return address.includes(':') ? address.replace(/[0-9a-f]*$/i, '') : address.replace(/\d+$/, '0');
}

function randomLabel(rng) {
	const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
	let label = '';
	for (let i = between(rng, 8, 12); i > 0; i--) label += chars[Math.floor(rng() * chars.length)];
	return label;
}

/** Turns a drawn kind and type into a consistent pair: names of the right shape for each type. */
function shapeQuery(kind, type) {
	if (kind === 'srv' || type === 'SRV') return { kind: 'srv', type: 'SRV' };
	if (type === 'PTR') return { kind: 'ptr', type };
	if (BLOCK_RATE[kind] !== undefined && !WEB_TYPES.has(type)) return { kind, type: 'A' };
	if (APEX_TYPES.has(type) && kind !== 'site' && kind !== 'vendor') return { kind, type: 'A' };
	if (type === 'CNAME' && kind !== 'site') return { kind, type: 'A' };
	if (kind === 'local' && type !== 'AAAA') return { kind, type: 'A' };
	if (NXDOMAIN_KINDS.has(kind) || kind === 'idn' || kind === 'corp') {
		if (
			['ANY', 'NULL', 'SVCB', 'MX', 'TXT', 'NS', 'SOA', 'CAA', 'DS', 'DNSKEY', 'CNAME'].includes(
				type,
			)
		) {
			return { kind, type: 'A' };
		}
	}
	return { kind, type };
}

function nameFor(rng, kind, type, client) {
	if (kind === 'ptr') {
		const own = rng() < 0.6 && client.ip.includes('.');
		const address = own
			? client.ip
			: `${between(rng, 11, 223)}.${between(rng, 0, 255)}.${between(rng, 0, 255)}.${between(rng, 1, 254)}`;
		return reverseName(address);
	}
	if (kind === 'srv') return pick(rng, POOL.srv);
	if (kind === 'junk') return `${randomLabel(rng)}.${pick(rng, JUNK_ZONES)}`;
	if (kind === 'tracker' && (type === 'A' || type === 'AAAA') && rng() < 0.08)
		return pick(rng, Object.keys(CLOAKED_TARGETS));
	if (type === 'CNAME') return pick(rng, CNAME_NAMES);
	if (APEX_TYPES.has(type)) {
		const apex = popular(
			rng,
			POOL[kind].filter((name) => !name.startsWith('www.')),
		);
		return type === 'TXT' && rng() < 0.3 ? `_dmarc.${apex}` : apex;
	}
	return popular(rng, POOL[kind]);
}

function recursionUs(rng, secure, type) {
	let us = between(rng, 8_000, 32_000);
	if (rng() < 0.15) us += between(rng, 15_000, 45_000);
	if (rng() < 0.02) us += between(rng, 60_000, 300_000);
	if (secure) us += between(rng, 4_000, 12_000);
	if (type === 'DS' || type === 'DNSKEY') us += between(rng, 3_000, 9_000);
	return us;
}

/** Returns the filter hit for a blocked query: which rule decided it, and the list it came from. */
function blockHit(rng, kind, name, set, service) {
	const base = { block_mode: set.block_mode, important: false };
	if (service) return { reason: 'service', ...base, rule_text: `||${name}^`, list_id: null };
	if (CUSTOM_BLOCK.includes(name))
		return { reason: 'custom', ...base, rule_text: `||${name}^`, list_id: null };
	const preferred = PREFERRED_LIST[kind];
	const list = set.lists.includes(preferred) ? preferred : set.lists[0];
	if (list === undefined)
		return { reason: 'custom', ...base, rule_text: `||${name}^`, list_id: null };
	if (list === 'stevenblack-hosts')
		return { reason: 'list', ...base, rule_text: `0.0.0.0 ${name}`, list_id: list };
	const important = rng() < 0.05;
	const stress = rng() < 0.01;
	return {
		reason: 'list',
		...base,
		important,
		rule_text: stress ? `||${'z'.repeat(300)}^` : `||${name}^${important ? '$important' : ''}`,
		list_id: list,
	};
}

const BLOCK_RCODE = { refused: 'REFUSED', nxdomain: 'NXDOMAIN', null_ip: 'NOERROR' };

/** One query record. Steps follow the decision order the UI shows: select, filter, answer, resolve. */
function buildRecord(rng, index, timeMs, sets, profiles) {
	const client = pickWeighted(
		rng,
		CLIENTS.map((entry) => [entry, entry.weight]),
	);
	const mix = pickWeighted(rng, Object.entries(KIND_MIX[client.mix]));
	const shaped = shapeQuery(mix, pickWeighted(rng, TYPE_WEIGHTS));
	const { kind, type } = shaped;
	const name = nameFor(rng, kind, type, client);
	const set = sets.get(client.profile);
	const profile = profiles.get(client.profile);
	const ownPtr =
		kind === 'ptr' &&
		client.id !== null &&
		client.ip.includes('.') &&
		name === reverseName(client.ip);

	const v6 = client.ip.includes(':') || (client.ip6 !== undefined && rng() < 0.25);
	const address = v6 && client.ip6 !== undefined ? client.ip6 : client.ip;
	const truncated = rng() < 0.5;
	const group = client.profile === 'kids' ? 'kids' : client.view;
	const protocol = pickWeighted(rng, PROTOCOL_MIX[group]);
	const selection =
		rng() < 0.66 ? { cause: 'subnet', prefix: VIEW_SUBNET[client.view] } : { cause: 'default' };
	const socialBlock = set.id === 'kids' && kind === 'social' && WEB_TYPES.has(type);
	const cloaked = CLOAKED_TARGETS[name] !== undefined;
	const blocked =
		socialBlock ||
		cloaked ||
		(BLOCK_RATE[kind] !== undefined && WEB_TYPES.has(type) && rng() < BLOCK_RATE[kind]);
	const tempAllow = !blocked && (kind === 'ad' || kind === 'tracker') && rng() < 0.04;

	const steps = [{ stage: 'select', verdict: 'selected', selection }];
	let filter = null;
	let rcode = 'NOERROR';
	let answerSource = 'resolver';
	let answerSize = 0;
	let dnssec = null;
	let forwardZone = null;
	let resolveUs = 0;

	if (blocked) {
		if (cloaked) {
			filter = {
				reason: 'list',
				block_mode: set.block_mode,
				important: false,
				rule_text: `||${CLOAKED_TARGETS[name]}^`,
				list_id: PREFERRED_LIST.tracker,
			};
			steps.push({ stage: 'resolve', verdict: 'resolved', source: 'recursion' });
			steps.push({ stage: 'answer_chain', verdict: 'blocked' });
			resolveUs = recursionUs(rng, false, type);
		} else {
			filter = blockHit(rng, kind, name, set, socialBlock);
			steps.push({ stage: 'filter_qname', verdict: 'blocked', reason: filter.reason });
		}
		rcode = BLOCK_RCODE[set.block_mode];
		answerSource = 'filter_block';
		answerSize = set.block_mode === 'null_ip' ? 45 : 0;
	} else if (tempAllow) {
		filter = {
			reason: 'temporary_allow',
			block_mode: null,
			rule_text: null,
			list_id: null,
			important: false,
		};
		steps.push({ stage: 'filter_qname', verdict: 'skipped', reason: 'temporary_allow' });
	}

	if (blocked) {
		// A blocked query never reaches the answer stages below.
	} else if (kind === 'local' || ownPtr) {
		steps.push({ stage: ownPtr ? 'local_client' : 'local_view', verdict: 'answered' });
		answerSource = ownPtr ? 'local_client' : 'local_view';
		answerSize = between(rng, 60, 110);
	} else if (type === 'ANY') {
		steps.push({ stage: 'any_synth', verdict: 'synth' });
		answerSource = 'synth_any';
		answerSize = 40;
	} else if (type === 'AAAA' && profile.suppress_aaaa) {
		steps.push({ stage: 'aaaa_suppressed', verdict: 'suppressed' });
		answerSource = 'resolver';
	} else {
		const nxdomain = NXDOMAIN_KINDS.has(kind) || (kind === 'ptr' && rng() < 0.7);
		const cacheRate = nxdomain ? 0 : SERVFAIL_KINDS.has(kind) ? 0.55 : 0.3;
		if (profile.safesearch === 'strict' && name === 'google.com') {
			steps.push({
				stage: 'safesearch',
				verdict: 'rewritten',
				provider: 'google',
				target: 'forcesafesearch.google.com',
			});
		}
		if (kind === 'corp') {
			forwardZone = 'corp.example';
			resolveUs = between(rng, 1_500, 6_000);
			steps.push({ stage: 'resolve', verdict: 'resolved', source: 'recursion' });
			answerSize = between(rng, ...ANSWER_SIZE[type]);
		} else if (SERVFAIL_KINDS.has(kind) && rng() < 0.004) {
			rcode = 'SERVFAIL';
			answerSource = 'resolve_error';
			resolveUs = 2_000_000;
			steps.push({
				stage: 'resolve',
				verdict: 'failed',
				cause_code: rng() < 0.5 ? 'resolver.timeout' : 'resolver.unreachable',
			});
		} else {
			const cached = rng() < cacheRate;
			const bogus =
				!nxdomain &&
				SIGNED_KINDS.has(kind) &&
				rng() < 0.006 &&
				['A', 'AAAA', 'HTTPS', 'DS', 'DNSKEY'].includes(type);
			dnssec = bogus ? 'bogus' : rng() < 0.85 ? 'secure' : null;
			const resolveSource = cached ? (rng() < 0.01 ? 'stale' : 'cache') : 'recursion';
			if (nxdomain) rcode = 'NXDOMAIN';
			answerSize = nxdomain ? between(rng, 110, 160) : between(rng, ...ANSWER_SIZE[type]);
			resolveUs = cached ? between(rng, 120, 820) : recursionUs(rng, dnssec === 'secure', type);
			if (!cached && !nxdomain && (type === 'A' || type === 'AAAA') && rng() < 0.006) {
				steps.push({ stage: 'rebind', verdict: 'stripped', count: between(rng, 1, 3) });
			}
			if (rng() < 0.01) {
				answerSource = 'bypass';
				steps.push({ stage: 'bypass', verdict: 'answered' });
			}
			const resolve = { stage: 'resolve', verdict: 'resolved', source: resolveSource };
			if (dnssec !== null) resolve.dnssec = dnssec;
			steps.push(resolve);
		}
	}

	const selectUs = between(rng, 40, 260);
	const filterUs = blocked ? between(rng, 600, 2_600) : between(rng, 150, 2_400);
	const sourceIp = truncated ? truncateAddress(address) : address;
	const [vlanId, vlanName] = client.vlan ?? [null, null];
	return {
		id: `rec-${String(index).padStart(4, '0')}`,
		node_id: rng() < 0.7 ? 'node1' : 'node2',
		listener_id: LISTENER_FOR[protocol],
		protocol,
		source_ip: sourceIp,
		source_ip_truncated: truncated,
		client_id: client.id,
		client:
			client.id === null
				? null
				: {
						id: `dir-${client.id}`,
						display_name: client.name,
						source: client.source,
						macs: client.macs,
						vlan_id: vlanId,
						vlan_name: vlanName,
						local_domain: LOCAL_DOMAIN,
					},
		query: { name, type, class: 'IN' },
		view_id: client.view,
		profile_id: client.profile,
		filter_set: set.id,
		selection,
		steps,
		answer_source: answerSource,
		filter,
		dnssec,
		forward_zone: forwardZone,
		rcode,
		answer_size: answerSize,
		timings: {
			select_us: selectUs,
			filter_us: filterUs,
			resolve_us: resolveUs,
			total_us: selectUs + filterUs + resolveUs,
		},
		time: isoMicros(timeMs),
	};
}

/** Client IDs pinned to `unterwegs` in the initial config; their newest queries come in roaming. */
const ROAMING_IDS = ['iphone-k7q2x9', 'pixel-8-jonas'];
const ROAMING_COUNT = 10;

/**
 * Rewrites the newest queries of the pinned Client IDs as roaming ones: the address matches no range,
 * so the Client-ID pin selects `unterwegs`. Done after generation, so the seeded stream is unchanged.
 */
function markRoaming(records, clientIds) {
	const labels = new Map(clientIds.map((entry) => [entry.id, entry.label]));
	let marked = 0;
	for (const record of records) {
		if (marked >= ROAMING_COUNT) break;
		if (!ROAMING_IDS.includes(record.client_id)) continue;
		marked++;
		const selection = { cause: 'client_id' };
		record.selection = selection;
		record.steps[0] = { ...record.steps[0], selection };
		record.view_id = 'unterwegs';
		record.protocol = 'doh';
		record.listener_id = LISTENER_FOR.doh;
		record.source_ip = '198.18.77.0';
		record.source_ip_truncated = true;
		record.client = {
			id: record.client_id,
			display_name: labels.get(record.client_id) ?? record.client_id,
			source: 'client_id',
			macs: [],
			vlan_id: null,
			vlan_name: null,
			local_domain: null,
		};
	}
}

/** The generated rows, newest first, built once per process. */
function generateRecords(config) {
	const rng = mulberry32(SEED);
	const sets = new Map(config.filtering.sets.map((set) => [set.id, set]));
	const profiles = new Map(config.policy.profiles.map((profile) => [profile.id, profile]));
	const ages = [];
	for (const [count, from, to] of AGE_BUCKETS) {
		for (let i = 0; i < count; i++) ages.push(Math.floor(from + rng() * (to - from)));
	}
	ages.sort((a, b) => a - b);
	const records = ages.map((age, index) => buildRecord(rng, index, NOW_MS - age, sets, profiles));
	markRoaming(records, config.policy.client_ids);
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
					lists: ['adguard-dns-filter', 'stevenblack-hosts'],
					custom_rules:
						'||graph.facebook.com^\n||mobile.events.data.microsoft.com^\n||browser.events.data.msn.com^\n@@||api.github.com^\n|exact.example.org^\n||ads.example.net^$important',
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
					lists: ['adguard-dns-filter', 'stevenblack-hosts'],
					custom_rules:
						'@@||de.wikipedia.org^\n! Schulmaterial freigegeben\n@@|lernplattform.example.de^',
					services: ['social-video', 'social-chat'],
					block_mode: 'nxdomain',
					mcp_rules: [],
				},
				{
					id: 'guests',
					name: 'Gäste',
					lists: ['adguard-dns-filter'],
					custom_rules: '',
					services: ['adult-content'],
					block_mode: 'refused',
					mcp_rules: [],
				},
				{
					id: 'iot',
					name: 'Smart Home',
					lists: ['stevenblack-hosts'],
					custom_rules: '||log-ingestion.samsungacr.com^\n||eu-acr.alphonso.tv^\n||stats.tado.com^',
					services: [],
					block_mode: 'null_ip',
					mcp_rules: [
						{
							id: 'mcp-rule-0003',
							domain: 'telemetry.example.net',
							include_subdomains: false,
							created_at: '2026-10-27T16:00:00Z',
							expires_at: '2026-10-29T18:00:00Z',
							token_id: 'tok-0002',
						},
					],
				},
			],
			lists: [
				{
					id: 'adguard-dns-filter',
					name: 'AdGuard DNS',
					source: { url: 'https://adguard-dns.io/dns-filter.txt' },
					enabled: true,
				},
				{
					id: 'stevenblack-hosts',
					name: 'StevenBlack Hosts',
					source: { url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts' },
					enabled: true,
				},
				{
					id: 'trackers-main',
					name: 'Tracking protection',
					source: { url: 'https://example.com/lists/trackers.txt' },
					enabled: true,
				},
				{
					id: 'legacy-hosts',
					name: 'Legacy hosts',
					source: { url: 'https://example.com/lists/hosts.txt' },
					enabled: false,
				},
			],
		},
		clients: {
			local_domain: 'home.arpa',
			local_domain_mode: 'unifi_then_config',
			unifi_profiles: [
				{
					id: 'home',
					sync_owner: 'local',
					enabled: true,
					base_url: 'https://192.0.2.1',
					site_id: null,
					poll_interval: '60s',
					classic_clients: true,
					tls_pin_sha256: `sha256:${'ab'.repeat(32)}`,
					ca_file: null,
					insecure_skip_verify: false,
				},
			],
			unifi_bindings: {
				local: 'home',
			},
			unifi: {
				enabled: true,
				base_url: 'https://192.0.2.1',
				site_id: null,
				poll_interval: '60s',
				classic_clients: true,
				tls_pin_sha256: `sha256:${'ab'.repeat(32)}`,
				ca_file: null,
				insecure_skip_verify: false,
			},
			manual: [
				{
					name: 'Wohnzimmer-TV',
					ip: '203.0.113.18',
					cidr: null,
					domain: 'tv.lan',
					identity: '203.0.113.18',
				},
				{
					name: 'Home Assistant',
					ip: '192.0.2.60',
					cidr: null,
					domain: 'ha.home.arpa',
					identity: '192.0.2.60',
				},
				{
					name: 'Gäste-WLAN',
					ip: null,
					cidr: '198.51.100.0/24',
					domain: 'gaeste.home.arpa',
					identity: '198.51.100.0/24',
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
				{
					id: 'corp',
					zone: 'corp.example.',
					targets: ['10.9.0.53:53', '10.9.1.53:53'],
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
					overrides: { guest: '192.0.2.51', unterwegs: '198.18.0.50' },
				},
				{
					name: 'nas.lan.',
					type: 'AAAA',
					ttl: 60,
					rdata: '2001:db8:0:1::50',
					overrides: {},
				},
				{
					name: 'ha.home.arpa.',
					type: 'A',
					ttl: 300,
					rdata: '192.0.2.60',
					overrides: {},
				},
				{
					name: 'ha.home.arpa.',
					type: 'AAAA',
					ttl: 300,
					rdata: '2001:db8:0:1::60',
					overrides: {},
				},
				{
					name: 'wohnzimmer-tv.home.arpa.',
					type: 'A',
					ttl: 300,
					rdata: '203.0.113.18',
					overrides: {},
				},
				{
					name: 'kamera-garage.home.arpa.',
					type: 'A',
					ttl: 300,
					rdata: '203.0.113.33',
					overrides: {},
				},
				{
					name: 'files.lan.',
					type: 'CNAME',
					ttl: 300,
					rdata: 'nas.lan.',
					overrides: {},
				},
				{
					name: '50.2.0.192.in-addr.arpa.',
					type: 'PTR',
					ttl: 3600,
					rdata: 'nas.lan.',
					overrides: {},
				},
				{
					name: '_ipp._tcp.lan.',
					type: 'SRV',
					ttl: 3600,
					rdata: '0 0 631 drucker-flur.home.arpa.',
					overrides: {},
				},
				{
					name: 'info.lan.',
					type: 'TXT',
					ttl: 3600,
					rdata: '"Heimnetz: DNScraft Demo"',
					overrides: {},
				},
				{
					name: '<script>alert(1)</script>.evil.test.',
					type: 'A',
					ttl: 60,
					rdata: '192.0.2.99',
					overrides: {},
				},
			],
			client_ids: [
				{
					id: 'iphone-k7q2x9',
					label: 'iPhone von Anna',
					device: 'dir-iphone-k7q2x9',
					view: 'unterwegs',
				},
				{ id: 'macbook-r4t8vn', label: 'MacBook Pro', device: 'dir-macbook-r4t8vn' },
				{
					id: 'pixel-8-jonas',
					label: 'Pixel 8 Jonas',
					device: 'dir-pixel-8-jonas',
					view: 'unterwegs',
				},
				{ id: 'kinder-tablet-q8j1', label: 'Kinder-Tablet', device: 'dir-kinder-tablet-q8j1' },
				{ id: 'tv-8d2f1a', label: 'Wohnzimmer-TV', device: null },
				{ id: 'sonos-kueche-y4r2', label: 'Sonos Küche', device: null },
				{ id: 'reserve-tablet-p7k2', label: 'Ersatz-Tablet', device: null },
			],
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
					profile: 'guests',
				},
				{
					id: 'iot',
					is_default: false,
					subnets: ['203.0.113.0/24'],
					nodes: [],
					profile: 'iot',
				},
				{
					id: 'office',
					is_default: false,
					subnets: ['10.10.0.0/16', '10.20.0.0/24', '2001:db8:10::/64'],
					nodes: [],
					profile: 'kids',
				},
				{
					id: 'lab',
					is_default: false,
					subnets: ['192.0.2.128/25'],
					nodes: [],
					profile: 'iot',
				},
				{
					id: 'cabin',
					is_default: false,
					subnets: ['198.18.0.0/24'],
					nodes: ['node2'],
					profile: 'guests',
				},
				{
					id: 'unterwegs',
					is_default: false,
					subnets: [],
					nodes: [],
					profile: 'default',
				},
			],
			profiles: [
				{
					id: 'default',
					filter_set: 'default',
					suppress_aaaa: false,
					firefox_canary: true,
					icloud_private_relay: true,
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
				{
					id: 'guests',
					filter_set: 'guests',
					suppress_aaaa: false,
					firefox_canary: false,
					icloud_private_relay: true,
					rebind: null,
					rebind_exceptions: [],
					forward_zones: null,
					safesearch: null,
					schedules: [],
				},
				{
					id: 'iot',
					filter_set: 'iot',
					suppress_aaaa: true,
					firefox_canary: false,
					icloud_private_relay: false,
					rebind: null,
					rebind_exceptions: [],
					forward_zones: null,
					safesearch: null,
					schedules: [],
				},
			],
		},
		listeners: {
			listeners: [
				{
					id: 'lan-udp',
					protocol: 'udp53',
					address: '192.0.2.1:53',
					exposure: 'local',
					h3: false,
					nodes: ['node1'],
				},
				{
					id: 'lan-tcp',
					protocol: 'tcp53',
					address: '192.0.2.1:53',
					exposure: 'local',
					h3: false,
					nodes: ['node1'],
				},
				{
					id: 'doh-local',
					protocol: 'doh',
					address: '127.0.0.1:443',
					exposure: 'local',
					h3: false,
					nodes: [],
				},
				{
					id: 'dot-public',
					protocol: 'dot',
					address: '0.0.0.0:853',
					exposure: 'public',
					h3: false,
					nodes: ['node1', 'node2'],
				},
				{
					id: 'dot-public-v6',
					protocol: 'dot',
					address: '[::]:853',
					exposure: 'public',
					h3: false,
					nodes: ['node1', 'node2'],
				},
				{
					id: 'doq-public',
					protocol: 'doq',
					address: '0.0.0.0:853',
					exposure: 'public',
					h3: false,
					nodes: [],
				},
				{
					id: 'lan-udp-v6',
					protocol: 'udp53',
					address: '[::1]:53',
					exposure: 'local',
					h3: false,
					nodes: ['node1'],
				},
			],
		},
		tls: {
			mode: 'self_signed',
			public_domain: 'example.test',
			extra_sans: [],
			key_type: 'ecdsa_p256',
			dns_provider: {
				kind: 'cloudflare',
				cloudflare: { zone_id: 'zone-example-test' },
				zones: [],
				manual_txt: [],
			},
			dyndns: {
				enabled: true,
				hostname: 'ns1.dns.example.test',
				proxied: false,
				public_entry: true,
				ipv4: true,
				ipv6: true,
				reserved_labels: ['ns1', 'ns2', 'ns3'],
				interval: '5m',
				ipv6_identifier: { mode: 'eui64' },
				interfaces: [],
				nodes: [
					{
						node_id: 'node1',
						hostname: 'ns1.dns.example.test',
						enabled: true,
						ipv4: true,
						ipv6: true,
						public_entry: true,
						ipv6_identifier: { mode: 'eui64' },
						interfaces: ['eth0'],
					},
					{
						node_id: 'node2',
						hostname: 'ns2.dns.example.test',
						enabled: true,
						ipv4: true,
						ipv6: true,
						public_entry: false,
						ipv6_identifier: { mode: 'stable_privacy' },
						interfaces: ['enp1s0'],
					},
					{
						node_id: 'node3',
						hostname: 'ns3.dns.example.test',
						enabled: false,
						ipv4: true,
						ipv6: false,
						public_entry: false,
						ipv6_identifier: { mode: 'eui64' },
						interfaces: [],
					},
				],
			},
			acme: {
				enabled: false,
				email: 'ops@example.test',
				directory: 'production',
			},
		},
		control_api_settings: {
			update_check: true,
			query_log: { retention_days: 30, ip_truncate: 'none' },
		},
		mcp: {
			enabled: true,
			write_tools_enabled: false,
			max_custom_rules_per_set: 100,
		},
	};
}

/** Initial cluster nodes for the mock master: node1 is the master, the others are sub-nodes. */
export const MOCK_CLUSTER_NODES = [
	{
		node_id: 'node1',
		role: 'master',
		fingerprint: '11'.repeat(32),
		joined_at: rfc3339(NOW_MS - 40 * DAY_MS),
		last_seen: rfc3339(NOW_MS - 2_000),
		applied_config_version: 12,
		revoked: false,
		local: true,
		connected: true,
		remote_addr: null,
		transport: null,
	},
	{
		node_id: 'node2',
		role: 'sub_node',
		fingerprint: 'ab'.repeat(32),
		joined_at: rfc3339(NOW_MS - 9 * DAY_MS),
		last_seen: rfc3339(NOW_MS - 40_000),
		applied_config_version: 12,
		revoked: false,
		local: false,
		connected: true,
		remote_addr: '192.0.2.91:8443',
		transport: 'mtls',
	},
	{
		node_id: 'node3',
		role: 'sub_node',
		fingerprint: 'cd'.repeat(32),
		joined_at: rfc3339(NOW_MS - 3 * DAY_MS),
		last_seen: rfc3339(NOW_MS - 2 * HOUR_MS),
		applied_config_version: 10,
		revoked: false,
		local: false,
		connected: false,
		remote_addr: '192.0.2.92:8443',
		transport: 'mtls',
	},
];
/** Config versions, as `minutes ago` (newest first in the API). */
const auditEvent = (ago, actor, actorType, action, objectType, objectId, rest = {}) => ({
	ago,
	actor,
	actorType,
	action,
	objectType,
	objectId,
	node: 'node1',
	version: null,
	result: 'ok',
	error: null,
	after: null,
	...rest,
});

const AUDIT_EVENTS = [
	auditEvent(3, 'admin', 'user', 'auth.token.create', 'token', 'tok-0004', {
		after: { name: 'mcp-reader', scope: 'mcp:read' },
	}),
	auditEvent(9, 'tok-0002', 'token', 'mcp.allow_temporarily', 'domain', 'allowed.example.test', {
		after: { duration: 'PT15M', include_subdomains: false },
	}),
	auditEvent(14, 'admin', 'user', 'resolver.cache.flush', 'cache', 'all', {
		after: { scope: 'all', evicted: 412 },
	}),
	auditEvent(21, 'tok-0002', 'token', 'mcp.pause_filter_set', 'filter_set', 'default', {
		after: { duration: 'PT5M' },
	}),
	auditEvent(26, 'tok-0002', 'token', 'mcp.resume_filter_set', 'filter_set', 'default'),
	auditEvent(41, 'admin', 'user', 'config.write', 'config', '13', { version: 13 }),
	auditEvent(55, 'service', 'service', 'clients.sync', 'clients', 'directory', {
		after: { generation: 2, client_count: 20 },
	}),
	auditEvent(63, 'ops@example.test', 'user', 'config.write', 'config', '12', {
		result: 'error',
		error: 'policy.config.unknown_filter_set',
	}),
	auditEvent(88, 'admin', 'user', 'config.write', 'config', '11', { version: 11 }),
	auditEvent(95, 'admin', 'user', 'tls.acme.order', 'tls', 'dns.example.test', {
		result: 'error',
		error: 'tls.acme.rate_limited',
	}),
	auditEvent(120, 'admin', 'user', 'mcp.add_rule', 'filter_set', 'default', {
		after: { domain: 'example.com', include_subdomains: true, expires_at: null },
	}),
	auditEvent(131, 'admin', 'user', 'mcp.remove_rule', 'filter_set', 'default', {
		after: { domain: 'old-test.example.test' },
	}),
	auditEvent(160, 'admin', 'user', 'cluster.join.token', 'node', 'node3', {
		after: { ttl_seconds: 900 },
	}),
	auditEvent(190, 'admin', 'user', 'cluster.node.revoked', 'node', 'node4'),
	auditEvent(232, 'admin', 'user', 'config.rollback', 'config', '9', {
		version: 11,
		after: { restored_from: 9 },
	}),
	auditEvent(260, 'ops@example.test', 'user', 'config.write', 'config', '10', { version: 10 }),
	auditEvent(300, 'tok-0003', 'token', 'cluster.config.apply', 'node', 'node2', {
		result: 'error',
		error: 'cluster.node.unknown',
	}),
	auditEvent(340, 'admin', 'user', 'auth.token.revoke', 'token', 'tok-0005'),
	auditEvent(420, 'tok-0002', 'token', 'mcp.add_rule', 'filter_set', 'default', {
		result: 'error',
		error: 'mcp.domain_too_broad',
	}),
	auditEvent(510, 'admin', 'user', 'mcp.add_rule', 'filter_set', 'default', {
		result: 'error',
		error: 'mcp.rule_limit_exceeded',
	}),
	auditEvent(600, 'admin', 'user', 'config.write', 'config', '9', { version: 9 }),
	auditEvent(780, 'admin', 'user', 'auth.token.create', 'token', 'tok-0003', {
		after: { name: 'kiosk-dashboard', scope: 'viewer' },
	}),
	auditEvent(900, 'tok-0002', 'token', 'mcp.pause_filter_set', 'filter_set', 'kids', {
		after: { duration: 'PT1H' },
	}),
	auditEvent(1200, '<script>alert(1)</script>', 'user', 'config.write', 'config', '8', {
		version: 8,
	}),
	auditEvent(1500, 'admin', 'user', 'config.write', 'config', '7', { version: 7 }),
	auditEvent(1900, 'service', 'service', 'clients.sync', 'clients', 'directory', {
		after: { generation: 1, client_count: 20 },
	}),
	auditEvent(2400, 'admin', 'user', 'auth.token.create', 'token', 'tok-0002', {
		after: { name: 'mcp-assistant', scope: 'mcp:write' },
	}),
	auditEvent(3000, 'admin', 'user', 'auth.token.create', 'token', 'tok-0001', {
		after: { name: 'ci-token', scope: 'admin' },
	}),
	auditEvent(3600, 'admin', 'user', 'config.write', 'config', '6', { version: 6 }),
	auditEvent(4320, 'admin', 'user', 'tls.acme.order', 'tls', 'dns.example.test'),
	auditEvent(5000, 'admin', 'user', 'cluster.join.token', 'node', 'node2'),
	auditEvent(5800, 'admin', 'user', 'config.write', 'config', '5', { version: 5 }),
	auditEvent(7200, 'admin', 'user', 'mcp.resume_filter_set', 'filter_set', 'default'),
	auditEvent(8000, 'service', 'service', 'clients.sync', 'clients', 'directory', {
		after: { generation: 1, client_count: 20 },
	}),
	auditEvent(9000, 'admin', 'user', 'config.write', 'config', '4', { version: 4 }),
	auditEvent(11000, 'admin', 'user', 'config.write', 'config', '3', { version: 3 }),
	auditEvent(12000, 'admin', 'user', 'config.write', 'config', '2', { version: 2 }),
	auditEvent(13000, 'admin', 'user', 'config.write', 'config', '1', { version: 1 }),
];

/** Audit rows, newest first; ids count down from the newest. Secrets never appear here. */
export const MOCK_AUDIT = AUDIT_EVENTS.map((event, index) => {
	const digest = (version) => (version * 0x9e3779b1).toString(16).padStart(64, '0').slice(-64);
	const version = event.version;
	return {
		id: AUDIT_EVENTS.length - index,
		time: rfc3339(NOW_MS - event.ago * MINUTE_MS),
		node_id: event.node,
		actor_id: event.actor,
		actor_type: event.actorType,
		action: event.action,
		object_type: event.objectType,
		object_id: event.objectId,
		config_version: version,
		before_digest: version === null ? null : digest(version - 1),
		after_digest: version === null ? null : digest(version),
		before: version === null ? null : { redacted: true },
		after:
			event.result === 'ok'
				? (event.after ?? (version === null ? null : { redacted: true }))
				: null,
		result: event.result,
		error_code: event.error,
	};
});

/** Token rows the admin Tokens panel lists (plaintext is never stored, so none is shown). */
export const MOCK_TOKENS = [
	{
		id: 'tok-0001',
		name: 'ci-token',
		scope: 'admin',
		actor_id: 'admin',
		created_at: rfc3339(NOW_MS - 3000 * MINUTE_MS),
		expires_at: null,
	},
	{
		id: 'tok-0002',
		name: 'mcp-assistant',
		scope: 'mcp:write',
		actor_id: 'admin',
		created_at: rfc3339(NOW_MS - 2400 * MINUTE_MS),
		expires_at: rfc3339(NOW_MS + 30 * DAY_MS),
	},
	{
		id: 'tok-0003',
		name: 'kiosk-dashboard',
		scope: 'viewer',
		actor_id: 'admin',
		created_at: rfc3339(NOW_MS - 780 * MINUTE_MS),
		expires_at: null,
	},
	{
		id: 'tok-0004',
		name: 'mcp-reader',
		scope: 'mcp:read',
		actor_id: 'admin',
		created_at: rfc3339(NOW_MS - 3 * MINUTE_MS),
		expires_at: rfc3339(NOW_MS + 7 * DAY_MS),
	},
];

const GENERATED_RECORDS = generateRecords(initialConfig());

/** Newest first. The same array for every call: the server builds it once per process. */
export function buildRecords() {
	return GENERATED_RECORDS;
}

/** Directory rows (`GET /api/v1/clients`), derived from the same device table as the records. */
export const MOCK_DIRECTORY_CLIENTS = directoryFrom(GENERATED_RECORDS);

function directoryFrom(records) {
	const newest = new Map();
	for (const record of records) {
		if (record.client_id !== null && !newest.has(record.client_id)) {
			newest.set(record.client_id, Date.parse(record.time));
		}
	}
	return CLIENTS.filter((client) => client.id !== null).map((client) => {
		const seen = newest.get(client.id) ?? NOW_MS - 3 * DAY_MS;
		return {
			id: `dir-${client.id}`,
			name: client.name,
			dns_label: client.label,
			local_domain: LOCAL_DOMAIN,
			source: client.source,
			ips: [client.ip, client.ip6].filter((ip) => ip !== undefined),
			macs: client.macs,
			vlan: client.vlan?.[0] ?? null,
			online: seen >= NOW_MS - 30 * MINUTE_MS,
			last_seen: rfc3339(seen),
		};
	});
}
