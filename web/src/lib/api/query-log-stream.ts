import type { QueryRecord } from './query-log';
import { isRecord } from './client';
import type { PollDocument } from '$lib/poll';
import { HIDDEN_CLOSE_MS } from '$lib/querylog/live';

export interface LiveStreamHandlers {
	onRow(row: QueryRecord): void;
	onLagged(dropped: number): void;
}

export interface LiveStreamOptions {
	/** Injected for tests; defaults to the global constructor. */
	EventSourceImpl?: typeof EventSource;
	doc?: PollDocument | null;
	hiddenCloseMs?: number;
	baseBackoffMs?: number;
	maxBackoffMs?: number;
}

export interface LiveStream {
	/** Closes the connection and cancels reconnect / hidden timers. */
	stop(): void;
}

/** Minimal shape check; the control-api owns the full record contract. */
export function parseStreamRow(data: string): QueryRecord | null {
	try {
		const value: unknown = JSON.parse(data);
		if (!isRecord(value) || typeof value.id !== 'string' || value.id === '') return null;
		return value as QueryRecord;
	} catch {
		return null;
	}
}

export function parseLagged(data: string): number | null {
	try {
		const value: unknown = JSON.parse(data);
		if (!isRecord(value) || typeof value.dropped !== 'number' || !Number.isFinite(value.dropped)) {
			return null;
		}
		return Math.max(0, Math.floor(value.dropped));
	} catch {
		return null;
	}
}

/**
 * Always-on SSE subscription to `GET /api/v1/query-log/stream`.
 * Reconnects with exponential backoff on error; closes after `hiddenCloseMs` while the tab is
 * hidden and opens again when it becomes visible.
 */
export function openQueryLogStream(
	href: string,
	handlers: LiveStreamHandlers,
	options: LiveStreamOptions = {},
): LiveStream {
	const EventSourceImpl = options.EventSourceImpl ?? globalThis.EventSource;
	const doc = options.doc ?? null;
	const hiddenCloseMs = options.hiddenCloseMs ?? HIDDEN_CLOSE_MS;
	const baseBackoffMs = options.baseBackoffMs ?? 1_000;
	const maxBackoffMs = options.maxBackoffMs ?? 30_000;

	let stopped = false;
	let source: EventSource | null = null;
	let reconnectTimer: ReturnType<typeof setTimeout> | undefined;
	let hiddenTimer: ReturnType<typeof setTimeout> | undefined;
	let failures = 0;

	function clearReconnect(): void {
		if (reconnectTimer !== undefined) {
			clearTimeout(reconnectTimer);
			reconnectTimer = undefined;
		}
	}

	function clearHidden(): void {
		if (hiddenTimer !== undefined) {
			clearTimeout(hiddenTimer);
			hiddenTimer = undefined;
		}
	}

	function closeSource(): void {
		if (source) {
			source.close();
			source = null;
		}
	}

	function attach(es: EventSource): void {
		es.addEventListener('row', (event) => {
			if (stopped) return;
			const message = event as MessageEvent<string>;
			const row = parseStreamRow(message.data);
			if (row) handlers.onRow(row);
		});
		es.addEventListener('lagged', (event) => {
			if (stopped) return;
			const message = event as MessageEvent<string>;
			const dropped = parseLagged(message.data);
			if (dropped !== null && dropped > 0) handlers.onLagged(dropped);
		});
		es.onerror = () => {
			if (stopped) return;
			closeSource();
			scheduleReconnect();
		};
		es.onopen = () => {
			if (stopped) return;
			failures = 0;
		};
	}

	function connect(): void {
		if (stopped || source || !EventSourceImpl) return;
		if (doc?.hidden === true) return;
		clearReconnect();
		try {
			source = new EventSourceImpl(href);
		} catch {
			scheduleReconnect();
			return;
		}
		attach(source);
	}

	function scheduleReconnect(): void {
		clearReconnect();
		if (stopped || doc?.hidden === true) return;
		const delay = Math.min(baseBackoffMs * 2 ** failures, maxBackoffMs);
		failures += 1;
		reconnectTimer = setTimeout(() => {
			reconnectTimer = undefined;
			connect();
		}, delay);
	}

	function onVisibilityChange(): void {
		if (stopped) return;
		if (doc?.hidden === true) {
			clearReconnect();
			clearHidden();
			hiddenTimer = setTimeout(() => {
				hiddenTimer = undefined;
				if (stopped || doc?.hidden !== true) return;
				closeSource();
			}, hiddenCloseMs);
			return;
		}
		clearHidden();
		if (!source) connect();
	}

	doc?.addEventListener('visibilitychange', onVisibilityChange);
	connect();

	return {
		stop(): void {
			stopped = true;
			clearReconnect();
			clearHidden();
			closeSource();
			doc?.removeEventListener('visibilitychange', onVisibilityChange);
		},
	};
}
