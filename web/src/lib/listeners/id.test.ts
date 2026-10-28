import { describe, expect, it } from 'vitest';
import { suggestListenerId } from './id';

describe('suggestListenerId', () => {
	it('builds a lowercase slug from protocol, family and exposure', () => {
		expect(suggestListenerId('doh', 'ipv4', true, [])).toBe('public-doh');
		expect(suggestListenerId('doh', 'ipv6', true, [])).toBe('public-doh-v6');
		expect(suggestListenerId('udp53', 'ipv4', true, [])).toBe('local-udp53');
		expect(suggestListenerId('dot', 'ipv4', false, [])).toBe('local-dot');
	});

	it('avoids collisions with existing ids', () => {
		expect(suggestListenerId('doh', 'ipv4', true, ['public-doh'])).toBe('public-doh-2');
		expect(suggestListenerId('doh', 'ipv4', true, ['public-doh', 'public-doh-2'])).toBe(
			'public-doh-3',
		);
	});
});
