// Shared polite announcement channel (SPEC-web-ui: async results go to an aria-live="polite" region).
// Only the latest message is kept; it clears itself so a stale toast does not stay on screen.

const CLEAR_AFTER_MS = 6_000;

export const live = $state({ message: '' });

let clearTimer: ReturnType<typeof setTimeout> | undefined;

export function announce(message: string): void {
	live.message = message;
	if (clearTimer !== undefined) clearTimeout(clearTimer);
	clearTimer = setTimeout(() => {
		live.message = '';
		clearTimer = undefined;
	}, CLEAR_AFTER_MS);
}
