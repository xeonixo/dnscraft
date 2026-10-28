import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { listListeners, nodesFromWire } from './listeners';
import { endSession, setPrincipal } from '$lib/auth/state.svelte';

describe('nodesFromWire', () => {
	it('treats missing nodes as every node', () => {
		expect(nodesFromWire(undefined)).toEqual([]);
		expect(nodesFromWire(null)).toEqual([]);
	});

	it('dedupes and trims node ids', () => {
		expect(nodesFromWire([' garage ', 'garage', 'office', ''])).toEqual(['garage', 'office']);
	});
});

describe('listListeners', () => {
	beforeEach(() => {
		vi.stubGlobal('fetch', vi.fn());
		endSession();
		setPrincipal({ role: 'admin', actorId: 'alice', actorType: 'user', csrfToken: 'tok-1' });
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('accepts legacy PascalCase protocol and exposure from the wire', async () => {
		vi.mocked(fetch).mockResolvedValueOnce(
			new Response(
				JSON.stringify({
					data: {
						listeners: [
							{
								id: 'lan-udp',
								protocol: 'Udp53',
								address: '0.0.0.0:53',
								exposure: 'Local',
								h3: false,
								nodes: [],
							},
						],
					},
				}),
				{ status: 200, headers: { 'content-type': 'application/json' } },
			),
		);
		await expect(listListeners()).resolves.toEqual([
			{
				id: 'lan-udp',
				protocol: 'udp53',
				address: '0.0.0.0:53',
				exposure: 'local',
				h3: false,
				nodes: [],
			},
		]);
	});
});
