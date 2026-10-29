import { describe, expect, it } from 'vitest';
import { buildMobileConfig, dohUrl, dotHostname, type MobileConfigInput } from './mobileconfig';

const base: MobileConfigInput = {
	publicDomain: 'example.com',
	clientId: 'iphone-anna',
	label: 'Anna iPhone',
};

const UUID_PATTERN = /^[0-9A-F]{8}-[0-9A-F]{4}-5[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$/;

function payloadUuids(xml: string): string[] {
	return [...xml.matchAll(/<key>PayloadUUID<\/key>\s*<string>([^<]*)<\/string>/g)].map((m) => m[1]);
}

// Tiny well-formedness check: tags balance, every & is an entity, no control characters.
function assertWellFormed(xml: string): void {
	const stack: string[] = [];
	let cursor = 0;
	for (const match of xml.matchAll(/<[^>]*>/g)) {
		const text = xml.slice(cursor, match.index);
		expect(text).not.toMatch(/&(?!(amp|lt|gt|quot|apos);)/);
		cursor = (match.index ?? 0) + match[0].length;
		const tag = match[0];
		if (tag.startsWith('<?') || tag.startsWith('<!')) continue;
		const name = /^<\/?([A-Za-z][\w-]*)/.exec(tag)?.[1];
		expect(name, tag).toBeDefined();
		if (tag.startsWith('</')) {
			expect(stack.pop(), tag).toBe(name);
		} else {
			stack.push(name as string);
		}
	}
	expect(stack).toEqual([]);
	expect(xml.slice(cursor)).not.toMatch(/&(?!(amp|lt|gt|quot|apos);)/);
	expect(xml).not.toMatch(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F￾￿]/);
	expect(xml).not.toMatch(/[‪-‮⁦-⁩]/);
}

describe('dohUrl and dotHostname', () => {
	it('builds the DoH URL and the DoT hostname', () => {
		expect(dohUrl('example.com', 'iphone-anna')).toEqual({
			ok: true,
			value: 'https://dns.example.com/dns-query/iphone-anna',
		});
		expect(dotHostname('example.com', 'iphone-anna')).toEqual({
			ok: true,
			value: 'iphone-anna.dns.example.com',
		});
	});

	it('trims and lower-cases the public domain', () => {
		expect(dohUrl('  DNS.Example.COM ', 'a')).toEqual({
			ok: true,
			value: 'https://dns.example.com/dns-query/a',
		});
	});

	it('rejects domains with a scheme, path, port, space or missing dot', () => {
		for (const domain of [
			'https://x',
			'x/y',
			'dns example.com',
			'dns.example.com:443',
			'user@example.com',
			'x',
			'a..b.com',
			'-a.example.com',
			`${'a'.repeat(64)}.com`,
		]) {
			expect(dohUrl(domain, 'iphone-anna'), domain).toEqual({ ok: false, error: 'invalid_domain' });
			expect(buildMobileConfig({ ...base, publicDomain: domain }), domain).toEqual({
				ok: false,
				error: 'invalid_domain',
			});
		}
	});

	it('reports an empty or blank public domain as missing', () => {
		for (const domain of ['', '   ']) {
			expect(dohUrl(domain, 'a')).toEqual({ ok: false, error: 'no_public_domain' });
			expect(dotHostname(domain, 'a')).toEqual({ ok: false, error: 'no_public_domain' });
			expect(buildMobileConfig({ ...base, publicDomain: domain })).toEqual({
				ok: false,
				error: 'no_public_domain',
			});
		}
	});

	it('rejects invalid Client IDs', () => {
		const ids = ['', 'Upper', '-lead', 'a/b', 'a b', 'a&b', 'a'.repeat(64), 'ünï', 'a.b'];
		for (const id of ids) {
			expect(dohUrl('example.com', id), id).toEqual({ ok: false, error: 'invalid_client_id' });
			expect(dotHostname('example.com', id), id).toEqual({
				ok: false,
				error: 'invalid_client_id',
			});
			expect(buildMobileConfig({ ...base, clientId: id }), id).toEqual({
				ok: false,
				error: 'invalid_client_id',
			});
		}
	});

	it('accepts the longest valid Client ID', () => {
		expect(dohUrl('example.com', 'a'.repeat(63))).toEqual({
			ok: true,
			value: `https://dns.example.com/dns-query/${'a'.repeat(63)}`,
		});
	});
});

describe('buildMobileConfig', () => {
	it('matches the golden profile for an HTTPS Client ID', () => {
		const result = buildMobileConfig(base);
		expect(result).toEqual({
			ok: true,
			xml: GOLDEN_HTTPS,
			fileName: 'dnscraft-anna-iphone.mobileconfig',
		});
	});

	it('uses DNS over TLS with a ServerName for protocol tls', () => {
		const result = buildMobileConfig({ ...base, protocol: 'tls' });
		if (!result.ok) throw new Error(result.error);
		expect(result.xml).toContain(
			'<key>DNSProtocol</key>\n\t\t\t\t<string>TLS</string>\n\t\t\t\t<key>ServerName</key>\n\t\t\t\t<string>iphone-anna.dns.example.com</string>',
		);
		expect(result.xml).not.toContain('ServerURL');
		expect(result.xml).not.toContain('HTTPS');
		assertWellFormed(result.xml);
	});

	it('adds an on-demand rule only when a home SSID is set', () => {
		const withSsid = buildMobileConfig({ ...base, protocol: 'tls', homeSsid: 'Home WLAN' });
		if (!withSsid.ok) throw new Error(withSsid.error);
		expect(withSsid.xml).toContain(
			[
				'\t\t\t<key>OnDemandRules</key>',
				'\t\t\t<array>',
				'\t\t\t\t<dict>',
				'\t\t\t\t\t<key>Action</key>',
				'\t\t\t\t\t<string>Disconnect</string>',
				'\t\t\t\t\t<key>SSIDMatch</key>',
				'\t\t\t\t\t<array>',
				'\t\t\t\t\t\t<string>Home WLAN</string>',
				'\t\t\t\t\t</array>',
				'\t\t\t\t</dict>',
				'\t\t\t\t<dict>',
				'\t\t\t\t\t<key>Action</key>',
				'\t\t\t\t\t<string>Connect</string>',
				'\t\t\t\t</dict>',
				'\t\t\t</array>',
				'\t\t</dict>',
			].join('\n'),
		);
		assertWellFormed(withSsid.xml);

		for (const homeSsid of [undefined, null, '', '   ', '‮\u0000']) {
			const result = buildMobileConfig({ ...base, homeSsid });
			if (!result.ok) throw new Error(result.error);
			expect(result.xml, String(homeSsid)).not.toContain('OnDemandRules');
		}
	});

	it('is deterministic: same input, same XML and UUIDs', () => {
		const first = buildMobileConfig(base);
		const second = buildMobileConfig({ ...base });
		expect(second).toEqual(first);
	});

	it('keeps UUIDs stable across a relabel, so reinstalling replaces the profile', () => {
		const before = buildMobileConfig(base);
		const after = buildMobileConfig({ ...base, label: 'Anna phone' });
		if (!before.ok || !after.ok) throw new Error('unexpected');
		expect(payloadUuids(after.xml)).toEqual(payloadUuids(before.xml));
	});

	it('gives distinct Client IDs distinct UUIDs', () => {
		const ids = ['a', 'b', 'iphone-anna', 'iphone-anna-2', 'x1'];
		const uuids = ids.flatMap((clientId) => {
			const result = buildMobileConfig({ ...base, clientId });
			if (!result.ok) throw new Error(result.error);
			return payloadUuids(result.xml);
		});
		expect(new Set(uuids).size).toBe(ids.length * 2);
	});

	it('formats payload UUIDs as RFC 4122 version 5 with the variant bits set', () => {
		const result = buildMobileConfig(base);
		if (!result.ok) throw new Error(result.error);
		const uuids = payloadUuids(result.xml);
		expect(uuids).toHaveLength(2);
		for (const uuid of uuids) expect(uuid).toMatch(UUID_PATTERN);
	});

	it('uses the custom organization and falls back to DNScraft', () => {
		const custom = buildMobileConfig({ ...base, organization: 'Acme' });
		if (!custom.ok) throw new Error(custom.error);
		expect(custom.xml).toContain('<key>PayloadOrganization</key>\n\t<string>Acme</string>');
		const fallback = buildMobileConfig({ ...base, organization: '  ' });
		if (!fallback.ok) throw new Error(fallback.error);
		expect(fallback.xml).toContain('<key>PayloadOrganization</key>\n\t<string>DNScraft</string>');
	});

	it('escapes hostile labels and keeps the XML well-formed', () => {
		const hostile = [
			'<img src=x onerror=alert(1)>',
			'Tom & "Jerry" \'s',
			'evil‮gnp.exe',
			'a\u0000b\u0007c\u007Fd\u0085e',
			'\uD800lone',
			'x'.repeat(150),
			'😀'.repeat(70),
		];
		for (const label of hostile) {
			const result = buildMobileConfig({ ...base, label, homeSsid: '<evil & "x">' });
			if (!result.ok) throw new Error(result.error);
			assertWellFormed(result.xml);
		}

		const img = buildMobileConfig({ ...base, label: '<img src=x onerror=alert(1)>' });
		if (!img.ok) throw new Error(img.error);
		expect(img.xml).toContain('DNScraft – &lt;img src=x onerror=alert(1)&gt;');
		expect(img.xml).not.toContain('<img');

		const quotes = buildMobileConfig({ ...base, label: 'Tom & "Jerry" \'s' });
		if (!quotes.ok) throw new Error(quotes.error);
		expect(quotes.xml).toContain('DNScraft – Tom &amp; &quot;Jerry&quot; &apos;s');

		const bidi = buildMobileConfig({ ...base, label: 'evil‮gnp.exe' });
		if (!bidi.ok) throw new Error(bidi.error);
		expect(bidi.xml).toContain('DNScraft – evilgnp.exe');

		const controls = buildMobileConfig({ ...base, label: 'a\u0000b\u0007c\u007Fd\u0085e' });
		if (!controls.ok) throw new Error(controls.error);
		expect(controls.xml).toContain('DNScraft – abcde');

		const ssid = buildMobileConfig({ ...base, homeSsid: '<evil & "x">' });
		if (!ssid.ok) throw new Error(ssid.error);
		expect(ssid.xml).toContain('<string>&lt;evil &amp; &quot;x&quot;&gt;</string>');
	});

	it('caps the label at 64 code points and the SSID at 32', () => {
		const long = buildMobileConfig({ ...base, label: 'x'.repeat(150) });
		if (!long.ok) throw new Error(long.error);
		expect(long.xml).toContain(`<string>DNScraft – ${'x'.repeat(64)}</string>`);
		expect(long.xml).not.toContain('x'.repeat(65));
		expect(long.fileName).toBe(`dnscraft-${'x'.repeat(64)}.mobileconfig`);

		const emoji = buildMobileConfig({ ...base, label: '😀'.repeat(70) });
		if (!emoji.ok) throw new Error(emoji.error);
		expect(emoji.xml).toContain(`<string>DNScraft – ${'😀'.repeat(64)}</string>`);

		const ssid = buildMobileConfig({ ...base, homeSsid: 'S'.repeat(40) });
		if (!ssid.ok) throw new Error(ssid.error);
		expect(ssid.xml).toContain(`<string>${'S'.repeat(32)}</string>`);
		expect(ssid.xml).not.toContain('S'.repeat(33));
	});

	it('uses the Client ID as display name and file name when the label is blank or unusable', () => {
		for (const label of [null, undefined, '', '   ', '‮']) {
			const result = buildMobileConfig({ ...base, label });
			if (!result.ok) throw new Error(result.error);
			expect(result.xml, String(label)).toContain('<string>DNScraft – iphone-anna</string>');
			expect(result.fileName, String(label)).toBe('dnscraft-iphone-anna.mobileconfig');
		}
	});

	it('falls back to the Client ID in the file name when the label has no Latin letters or digits', () => {
		const result = buildMobileConfig({ ...base, label: 'Телефон' });
		if (!result.ok) throw new Error(result.error);
		expect(result.xml).toContain('<string>DNScraft – Телефон</string>');
		expect(result.fileName).toBe('dnscraft-iphone-anna.mobileconfig');
	});

	it('derives the file name slug from the label', () => {
		const cases: [string, string][] = [
			['Anna iPhone', 'dnscraft-anna-iphone.mobileconfig'],
			['Anna’s iPhone (Küche)', 'dnscraft-anna-s-iphone-kuche.mobileconfig'],
			['../../etc/passwd', 'dnscraft-etc-passwd.mobileconfig'],
			['  --Kids!!  ', 'dnscraft-kids.mobileconfig'],
		];
		for (const [label, fileName] of cases) {
			const result = buildMobileConfig({ ...base, label });
			if (!result.ok) throw new Error(result.error);
			expect(result.fileName, label).toBe(fileName);
		}
	});

	it('never produces a file name with path separators or an empty slug', () => {
		for (const label of ['a/b\\c', '..', '////', '  ', '😀']) {
			const result = buildMobileConfig({ ...base, label });
			if (!result.ok) throw new Error(result.error);
			expect(result.fileName).toMatch(/^dnscraft-[a-z0-9-]+\.mobileconfig$/);
		}
	});

	it('produces well-formed XML for the golden cases', () => {
		assertWellFormed(GOLDEN_HTTPS);
		const tls = buildMobileConfig({ ...base, protocol: 'tls', homeSsid: 'Home WLAN' });
		if (!tls.ok) throw new Error(tls.error);
		assertWellFormed(tls.xml);
	});
});

const GOLDEN_HTTPS = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadType</key>
			<string>com.apple.dnsSettings.managed</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
			<key>PayloadIdentifier</key>
			<string>app.dnscraft.dns.iphone-anna.payload</string>
			<key>PayloadUUID</key>
			<string>1F778150-8D77-58CB-9D07-63B3BC66A9ED</string>
			<key>PayloadDisplayName</key>
			<string>DNScraft – Anna iPhone</string>
			<key>DNSSettings</key>
			<dict>
				<key>DNSProtocol</key>
				<string>HTTPS</string>
				<key>ServerURL</key>
				<string>https://dns.example.com/dns-query/iphone-anna</string>
			</dict>
		</dict>
	</array>
	<key>PayloadDescription</key>
	<string>Sends this device&apos;s DNS queries to DNScraft over encrypted DNS. Installing again replaces this profile.</string>
	<key>PayloadDisplayName</key>
	<string>DNScraft – Anna iPhone</string>
	<key>PayloadIdentifier</key>
	<string>app.dnscraft.dns.iphone-anna</string>
	<key>PayloadOrganization</key>
	<string>DNScraft</string>
	<key>PayloadScope</key>
	<string>System</string>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>88F0CE37-EFE0-5C97-8000-C16E82499079</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
`;

describe('serverAddresses', () => {
	const base = { publicDomain: 'example.com', clientId: 'iphone-anna' };

	it('adds a ServerAddresses array for valid, de-duplicated IPs only', () => {
		const result = buildMobileConfig({
			...base,
			serverAddresses: ['203.0.113.7', ' 203.0.113.7 ', '2001:db8::1', 'not-an-ip', '<x>'],
		});
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.xml).toContain('<key>ServerAddresses</key>');
		expect(result.xml.match(/<string>203\.0\.113\.7<\/string>/g)).toHaveLength(1);
		expect(result.xml).toContain('<string>2001:db8::1</string>');
		expect(result.xml).not.toContain('not-an-ip');
		expect(result.xml.indexOf('ServerAddresses')).toBeLessThan(result.xml.indexOf('ServerURL'));
	});

	it('omits the key without addresses and works for tls', () => {
		const none = buildMobileConfig({ ...base, serverAddresses: [] });
		expect(none.ok && none.xml.includes('ServerAddresses')).toBe(false);
		const tls = buildMobileConfig({ ...base, protocol: 'tls', serverAddresses: ['203.0.113.7'] });
		expect(tls.ok && tls.xml.includes('<string>203.0.113.7</string>')).toBe(true);
	});
});

describe('node hosts', () => {
	const base = { publicDomain: 'example.com', clientId: 'abc' };

	it('emits one DoH payload per node host', () => {
		const r = buildMobileConfig({ ...base, hosts: ['ns1.dns.example.com', 'NS2.dns.example.com'] });
		if (!r.ok) throw new Error('expected ok');
		expect(r.xml).toContain('https://ns1.dns.example.com/dns-query/abc');
		expect(r.xml).toContain('https://ns2.dns.example.com/dns-query/abc');
		expect(r.xml).not.toContain('https://dns.example.com/');
	});

	it('rejects an invalid host', () => {
		expect(buildMobileConfig({ ...base, hosts: ['bad host'] })).toEqual({
			ok: false,
			error: 'invalid_domain',
		});
	});
});

describe('scope', () => {
	it('is system scoped, which macOS requires for DNS settings', () => {
		const r = buildMobileConfig({ publicDomain: 'example.com', clientId: 'abc' });
		if (!r.ok) throw new Error('expected ok');
		expect(r.xml).toContain('<key>PayloadScope</key>\n\t<string>System</string>');
	});
});
