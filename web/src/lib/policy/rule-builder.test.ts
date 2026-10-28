import { describe, expect, it } from 'vitest';
import { buildRuleText } from '$lib/api/filtering';

describe('guided rule builder', () => {
	it('builds block and allow rules without user-typed modifiers', () => {
		expect(
			buildRuleText({ action: 'block', domain: 'ads.example.com', include_subdomains: true }),
		).toBe('||ads.example.com^');
		expect(
			buildRuleText({ action: 'allow', domain: 'cdn.example.com', include_subdomains: false }),
		).toBe('@@|cdn.example.com^');
	});
});
