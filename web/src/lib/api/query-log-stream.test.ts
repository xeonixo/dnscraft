import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { PollDocument } from '$lib/poll';
import { openQueryLogStream, parseLagged, parseStreamRow } from './query-log-stream';

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

type Listener = (event: MessageEvent<string>) => void;

class FakeEventSource {
	static instances: FakeEventSource[] = [];
	readonly url: string;
	onerror: ((ev: Event) => void) | null = null;
	onopen: ((ev: Event) => void) | null = null;
	closed = false;
	private readonly listeners = new Map<string, Set<Listener>>();

	constructor(url: string) {
		this.url = url;
		FakeEventSource.instances.push(this);
	}

	addEventListener(type: string, listener: EventListenerOrEventListenerObject): void {
		const set = this.listeners.get(type) ?? new Set();
		set.add(listener as Listener);
		this.listeners.set(type, set);
	}

	close(): void {
		this.closed = true;
	}

	emit(type: string, data: string): void {
		const event = { data } as MessageEvent<string>;
		for (const listener of this.listeners.get(type) ?? []) listener(event);
	}

	fail(): void {
		this.onerror?.(new Event('error'));
	}

	opened(): void {
		this.onopen?.(new Event('open'));
	}
}

describe('parseStreamRow / parseLagged', () => {
	it('accepts a record with an id', () => {
		expect(parseStreamRow('{"id":"q1","query":{"name":"a.example"}}')?.id).toBe('q1');
	});

	it('rejects garbage', () => {
		expect(parseStreamRow('not-json')).toBeNull();
		expect(parseStreamRow('{"id":""}')).toBeNull();
		expect(parseLagged('{"dropped":"x"}')).toBeNull();
		expect(parseLagged('{"dropped":3}')).toBe(3);
	});
});

describe('openQueryLogStream', () => {
	beforeEach(() => {
		vi.useFakeTimers();
		FakeEventSource.instances = [];
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	it('delivers row and lagged events', () => {
		const onRow = vi.fn();
		const onLagged = vi.fn();
		const stream = openQueryLogStream(
			'/api/v1/query-log/stream',
			{ onRow, onLagged },
			{
				EventSourceImpl: FakeEventSource as unknown as typeof EventSource,
			},
		);
		const es = FakeEventSource.instances[0]!;
		es.emit('row', '{"id":"live-1"}');
		es.emit('lagged', '{"dropped":4}');
		expect(onRow).toHaveBeenCalledWith(expect.objectContaining({ id: 'live-1' }));
		expect(onLagged).toHaveBeenCalledWith(4);
		stream.stop();
		expect(es.closed).toBe(true);
	});

	it('reconnects after error with backoff', async () => {
		const stream = openQueryLogStream(
			'/api/v1/query-log/stream',
			{
				onRow: () => undefined,
				onLagged: () => undefined,
			},
			{
				EventSourceImpl: FakeEventSource as unknown as typeof EventSource,
				baseBackoffMs: 1000,
				maxBackoffMs: 8000,
			},
		);
		FakeEventSource.instances[0]!.fail();
		expect(FakeEventSource.instances).toHaveLength(1);
		await vi.advanceTimersByTimeAsync(999);
		expect(FakeEventSource.instances).toHaveLength(1);
		await vi.advanceTimersByTimeAsync(1);
		expect(FakeEventSource.instances).toHaveLength(2);
		stream.stop();
	});

	it('closes after staying hidden and reconnects when visible', async () => {
		const doc = fakeDocument();
		const stream = openQueryLogStream(
			'/api/v1/query-log/stream',
			{
				onRow: () => undefined,
				onLagged: () => undefined,
			},
			{
				EventSourceImpl: FakeEventSource as unknown as typeof EventSource,
				doc,
				hiddenCloseMs: 60_000,
			},
		);
		expect(FakeEventSource.instances).toHaveLength(1);

		doc.hidden = true;
		doc.fire();
		await vi.advanceTimersByTimeAsync(59_999);
		expect(FakeEventSource.instances[0]!.closed).toBe(false);
		await vi.advanceTimersByTimeAsync(1);
		expect(FakeEventSource.instances[0]!.closed).toBe(true);

		doc.hidden = false;
		doc.fire();
		expect(FakeEventSource.instances).toHaveLength(2);
		stream.stop();
	});
});
