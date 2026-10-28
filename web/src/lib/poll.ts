/** The slice of `document` the poller needs; tests pass a stub. */
export interface PollDocument {
	hidden: boolean;
	addEventListener(type: 'visibilitychange', listener: () => void): void;
	removeEventListener(type: 'visibilitychange', listener: () => void): void;
}

export interface PollerOptions {
	intervalMs: number;
	/** Upper bound for the delay after repeated failures. */
	maxBackoffMs: number;
	/** Omit (or pass null) when there is no document, which disables the visibility pause. */
	doc?: PollDocument | null;
}

export interface Poller {
	/** Runs the task now and then on the interval. Idempotent. */
	start(): void;
	/** Runs the task now; a call during a run schedules one more run after it. */
	refresh(): void;
	/** Cancels the timer, detaches the listener and ignores any result still in flight. */
	stop(): void;
}

/**
 * A recursive timeout (no setInterval): the next run is scheduled only after the last one ends.
 * While the document is hidden nothing is scheduled; becoming visible runs the task at once.
 * Each failed run doubles the delay up to `maxBackoffMs`; a successful run resets it.
 * The task resolves to true on success and must not throw.
 */
export function createPoller(task: () => Promise<boolean>, options: PollerOptions): Poller {
	const { intervalMs, maxBackoffMs, doc = null } = options;
	let timer: ReturnType<typeof setTimeout> | undefined;
	let running = false;
	let rerun = false;
	let started = false;
	let stopped = false;
	let failures = 0;

	const hidden = (): boolean => doc?.hidden === true;

	function clear(): void {
		if (timer !== undefined) {
			clearTimeout(timer);
			timer = undefined;
		}
	}

	function delayAfterRun(): number {
		if (failures === 0) return intervalMs;
		return Math.min(intervalMs * 2 ** failures, maxBackoffMs);
	}

	function schedule(): void {
		clear();
		if (stopped || hidden()) return;
		timer = setTimeout(() => {
			timer = undefined;
			void run();
		}, delayAfterRun());
	}

	async function run(): Promise<void> {
		if (stopped) return;
		if (running) {
			rerun = true;
			return;
		}
		running = true;
		clear();
		let ok = false;
		try {
			ok = await task();
		} catch {
			ok = false;
		}
		running = false;
		if (stopped) return;
		failures = ok ? 0 : failures + 1;
		if (rerun) {
			rerun = false;
			void run();
			return;
		}
		schedule();
	}

	function onVisibilityChange(): void {
		if (stopped) return;
		if (hidden()) {
			clear();
		} else {
			void run();
		}
	}

	return {
		start(): void {
			if (started || stopped) return;
			started = true;
			doc?.addEventListener('visibilitychange', onVisibilityChange);
			void run();
		},
		refresh(): void {
			if (!started || stopped) return;
			void run();
		},
		stop(): void {
			stopped = true;
			clear();
			doc?.removeEventListener('visibilitychange', onVisibilityChange);
		},
	};
}
