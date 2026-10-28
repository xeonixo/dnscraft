import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createPoller, type PollDocument } from './poll';

const INTERVAL = 30_000;
const MAX = 300_000;

interface FakeDocument extends PollDocument {
	fire(): void;
}

function fakeDocument(): FakeDocument {
	const listeners = new Set<() => void>();
	return {
		hidden: false,
		addEventListener: (_type, listener) => listeners.add(listener),
		removeEventListener: (_type, listener) => listeners.delete(listener),
		fire() {
			for (const listener of listeners) listener();
		},
	};
}

function setup(results: boolean[] = []) {
	const doc = fakeDocument();
	const task = vi.fn(async () => results.shift() ?? true);
	const poller = createPoller(task, { intervalMs: INTERVAL, maxBackoffMs: MAX, doc });
	return { doc, task, poller };
}

beforeEach(() => {
	vi.useFakeTimers();
});

afterEach(() => {
	vi.useRealTimers();
});

describe('createPoller', () => {
	it('runs at once on start and then on the interval', async () => {
		const { task, poller } = setup();
		poller.start();
		await vi.advanceTimersByTimeAsync(0);
		expect(task).toHaveBeenCalledTimes(1);

		await vi.advanceTimersByTimeAsync(INTERVAL);
		expect(task).toHaveBeenCalledTimes(2);
		poller.stop();
	});

	it('stops scheduling while hidden and runs at once when visible again', async () => {
		const { doc, task, poller } = setup();
		poller.start();
		await vi.advanceTimersByTimeAsync(0);

		doc.hidden = true;
		doc.fire();
		await vi.advanceTimersByTimeAsync(5 * INTERVAL);
		expect(task).toHaveBeenCalledTimes(1);

		doc.hidden = false;
		doc.fire();
		await vi.advanceTimersByTimeAsync(0);
		expect(task).toHaveBeenCalledTimes(2);
		poller.stop();
	});

	it('backs off after failures and resets after a success', async () => {
		const { task, poller } = setup([false, false, true]);
		poller.start();
		await vi.advanceTimersByTimeAsync(0);
		expect(task).toHaveBeenCalledTimes(1);

		// First failure: 60s until the next run.
		await vi.advanceTimersByTimeAsync(2 * INTERVAL - 1);
		expect(task).toHaveBeenCalledTimes(1);
		await vi.advanceTimersByTimeAsync(1);
		expect(task).toHaveBeenCalledTimes(2);

		// Second failure: 120s.
		await vi.advanceTimersByTimeAsync(4 * INTERVAL - 1);
		expect(task).toHaveBeenCalledTimes(2);
		await vi.advanceTimersByTimeAsync(1);
		expect(task).toHaveBeenCalledTimes(3);

		// Success resets to the normal interval.
		await vi.advanceTimersByTimeAsync(INTERVAL);
		expect(task).toHaveBeenCalledTimes(4);
		poller.stop();
	});

	it('caps the backoff delay', async () => {
		const task = vi.fn(async () => false);
		const poller = createPoller(task, { intervalMs: INTERVAL, maxBackoffMs: MAX });
		poller.start();
		// Delays after each failure: 60s, 120s, 240s, then the 300s cap.
		await vi.advanceTimersByTimeAsync(60_000 + 120_000 + 240_000);
		expect(task).toHaveBeenCalledTimes(4);
		await vi.advanceTimersByTimeAsync(MAX - 1);
		expect(task).toHaveBeenCalledTimes(4);
		await vi.advanceTimersByTimeAsync(1);
		expect(task).toHaveBeenCalledTimes(5);
		await vi.advanceTimersByTimeAsync(MAX);
		expect(task).toHaveBeenCalledTimes(6);
		poller.stop();
	});

	it('treats a thrown task as a failed run', async () => {
		const task = vi.fn(async () => {
			throw new Error('boom');
		});
		const poller = createPoller(task, { intervalMs: INTERVAL, maxBackoffMs: MAX });
		poller.start();
		await vi.advanceTimersByTimeAsync(0);
		await vi.advanceTimersByTimeAsync(2 * INTERVAL - 1);
		expect(task).toHaveBeenCalledTimes(1);
		poller.stop();
	});

	it('refresh runs now and queues one rerun when a run is already in flight', async () => {
		let release: (() => void) | undefined;
		const task = vi.fn(
			() =>
				new Promise<boolean>((resolve) => {
					release = () => resolve(true);
				}),
		);
		const poller = createPoller(task, { intervalMs: INTERVAL, maxBackoffMs: MAX });
		poller.start();
		poller.refresh();
		poller.refresh();
		expect(task).toHaveBeenCalledTimes(1);

		release?.();
		await vi.advanceTimersByTimeAsync(0);
		expect(task).toHaveBeenCalledTimes(2);
		poller.stop();
	});

	it('stop cancels the timer, detaches the listener and ignores late results', async () => {
		let release: (() => void) | undefined;
		const doc = fakeDocument();
		const task = vi.fn(
			() =>
				new Promise<boolean>((resolve) => {
					release = () => resolve(true);
				}),
		);
		const poller = createPoller(task, { intervalMs: INTERVAL, maxBackoffMs: MAX, doc });
		poller.start();
		poller.stop();
		release?.();
		await vi.advanceTimersByTimeAsync(5 * INTERVAL);
		expect(task).toHaveBeenCalledTimes(1);

		doc.fire();
		poller.refresh();
		expect(task).toHaveBeenCalledTimes(1);
	});
});
