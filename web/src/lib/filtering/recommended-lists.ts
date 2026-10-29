/**
 * Curated starting point for `/filter-lists`: names and download URLs of lists from the AdGuard
 * HostlistsRegistry (https://github.com/AdguardTeam/HostlistsRegistry). Only references, never list content.
 * Ids are valid backend list ids (`[a-z0-9-]{1,64}`).
 */
export type RecommendedGroup = 'base' | 'stronger' | 'security' | 'devices' | 'content' | 'careful';

export interface RecommendedList {
	id: string;
	name: string;
	url: string;
	group: RecommendedGroup;
	/** Ticked when the dialog opens; one general base list plus the threat feed. */
	preselected?: true;
}

export const RECOMMENDED_GROUPS: readonly RecommendedGroup[] = [
	'base',
	'stronger',
	'security',
	'devices',
	'content',
	'careful',
];

const registry = (filterId: number): string =>
	`https://adguardteam.github.io/HostlistsRegistry/assets/filter_${filterId}.txt`;

export const RECOMMENDED_LISTS: readonly RecommendedList[] = [
	{
		id: 'hagezi-pro',
		name: "HaGeZi's Pro Blocklist",
		url: registry(48),
		group: 'base',
		preselected: true,
	},
	{
		id: 'hagezi-tif',
		name: "HaGeZi's Threat Intelligence Feeds",
		url: registry(44),
		group: 'base',
		preselected: true,
	},

	{ id: 'hagezi-pro-plus', name: "HaGeZi's Pro++ Blocklist", url: registry(51), group: 'stronger' },
	{
		id: 'hagezi-ultimate',
		name: "HaGeZi's Ultimate Blocklist",
		url: registry(49),
		group: 'stronger',
	},

	{ id: 'stalkerware', name: 'Stalkerware Indicators List', url: registry(31), group: 'security' },
	{
		id: 'hagezi-badware-hoster',
		name: "HaGeZi's Badware Hoster Blocklist",
		url: registry(55),
		group: 'security',
	},
	{
		id: 'phishtank-openphish',
		name: 'Phishing URL Blocklist (PhishTank and OpenPhish)',
		url: registry(30),
		group: 'security',
	},
	{
		id: 'durablenapkin-scam',
		name: 'Scam Blocklist by DurableNapkin',
		url: registry(10),
		group: 'security',
	},

	{
		id: 'smart-tv',
		name: "Perflyst and Dandelion Sprout's Smart-TV Blocklist",
		url: registry(7),
		group: 'devices',
	},
	{
		id: 'hagezi-windows-office',
		name: "HaGeZi's Windows/Office Tracker Blocklist",
		url: registry(63),
		group: 'devices',
	},
	{
		id: 'hagezi-apple',
		name: "HaGeZi's Apple Tracker Blocklist",
		url: registry(67),
		group: 'devices',
	},
	{
		id: 'hagezi-samsung',
		name: "HaGeZi's Samsung Tracker Blocklist",
		url: registry(61),
		group: 'devices',
	},
	{
		id: 'hagezi-lg-webos',
		name: "HaGeZi's LG webOS Tracker Blocklist",
		url: registry(72),
		group: 'devices',
	},

	{
		id: 'hagezi-gambling',
		name: "HaGeZi's Gambling Blocklist",
		url: registry(47),
		group: 'content',
	},
	{
		id: 'hagezi-anti-piracy',
		name: "HaGeZi's Anti-Piracy Blocklist",
		url: registry(46),
		group: 'content',
	},
	{ id: 'dating', name: "ShadowWhisperer's Dating List", url: registry(57), group: 'content' },
	{
		id: 'anti-push-notifications',
		name: "Dandelion Sprout's Anti Push Notifications",
		url: registry(39),
		group: 'content',
	},
	{
		id: 'hagezi-url-shortener',
		name: "HaGeZi's URL Shortener Blocklist",
		url: registry(68),
		group: 'content',
	},

	{
		id: 'hagezi-encrypted-dns-bypass',
		name: "HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass",
		url: registry(52),
		group: 'careful',
	},
	{
		id: 'hagezi-abused-tlds',
		name: "HaGeZi's The World's Most Abused TLDs",
		url: registry(56),
		group: 'careful',
	},
	{ id: 'hagezi-dyndns', name: "HaGeZi's DynDNS Blocklist", url: registry(54), group: 'careful' },
];
