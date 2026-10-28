import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createClientId, listClientIds, revokeClientId, updateClientId } from './policy';
import { endSession, setPrincipal } from '$lib/auth/state.svelte';

const json = (status: number, body: unknown): Response =>
	new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});

let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;

function answerWith(body: unknown): void {
	fetchMock = vi.fn(async () => json(200, { data: body }));
	vi.stubGlobal('fetch', fetchMock);
}

function lastCall(): { url: string; method: string; body: unknown } {
	const [url, init] = fetchMock.mock.calls.at(-1) as [string, RequestInit];
	return {
		url,
		method: init.method ?? 'GET',
		body: init.body === undefined ? undefined : JSON.parse(String(init.body)),
	};
}

beforeEach(() => {
	endSession();
	setPrincipal({ role: 'admin', actorId: 'admin', actorType: 'user', csrfToken: 'tok' });
});

afterEach(() => {
	vi.unstubAllGlobals();
});

describe('policy client ids API', () => {
	it('reads objects and maps old string entries to { id }', async () => {
		answerWith({
			client_ids: [
				{ id: 'iphone-k7q2x9', label: 'iPhone von Anna', device: 'dir-iphone-k7q2x9' },
				'legacy-id',
				{ id: 'tv-8d2f1a' },
				{ label: 'no id, dropped' },
			],
		});
		expect(await listClientIds()).toEqual([
			{ id: 'iphone-k7q2x9', label: 'iPhone von Anna', device: 'dir-iphone-k7q2x9', view: null },
			{ id: 'legacy-id', label: null, device: null, view: null },
			{ id: 'tv-8d2f1a', label: null, device: null, view: null },
		]);
	});

	it('reads the pinned Netzbereich and maps a missing or non-string view to null', async () => {
		answerWith({
			client_ids: [
				{ id: 'pixel-8-jonas', label: 'Pixel 8 Jonas', device: null, view: 'unterwegs' },
				{ id: 'odd', label: null, device: null, view: 7 },
			],
		});
		expect(await listClientIds()).toEqual([
			{ id: 'pixel-8-jonas', label: 'Pixel 8 Jonas', device: null, view: 'unterwegs' },
			{ id: 'odd', label: null, device: null, view: null },
		]);
	});

	it('returns an empty list for a malformed payload', async () => {
		answerWith({ client_ids: 'nope' });
		expect(await listClientIds()).toEqual([]);
	});

	it('sends label, device and view only when given on create', async () => {
		answerWith({ version: 4, client_id: 'x' });
		await createClientId('x');
		expect(lastCall()).toMatchObject({ method: 'POST', body: { id: 'x' } });
		await createClientId('y', { label: 'Pixel', device: null });
		expect(lastCall().body).toEqual({ id: 'y', label: 'Pixel', device: null });
		await createClientId('z', { view: 'unterwegs' });
		expect(lastCall().body).toEqual({ id: 'z', view: 'unterwegs' });
	});

	it('PUTs label and device to the id path and keeps null as a clear', async () => {
		answerWith({ version: 5, client_id: 'a/b' });
		await updateClientId('a/b', { label: null, device: 'dir-x' });
		const call = lastCall();
		expect(call.method).toBe('PUT');
		expect(call.url).toContain('/api/v1/policy/client-ids/a%2Fb');
		expect(call.body).toEqual({ label: null, device: 'dir-x' });
	});

	it('PUTs view and sends null to clear the pin', async () => {
		answerWith({ version: 7, client_id: 'a' });
		await updateClientId('a', { view: 'unterwegs' });
		expect(lastCall().body).toEqual({ view: 'unterwegs' });
		await updateClientId('a', { view: null });
		expect(lastCall().body).toEqual({ view: null });
	});

	it('still deletes by id', async () => {
		answerWith({ version: 6 });
		await revokeClientId('iphone-k7q2x9');
		expect(lastCall()).toMatchObject({ method: 'DELETE' });
	});
});
