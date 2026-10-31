const THRESHOLD = 90;

/** A home-screen app has no browser chrome, so a pull-down at the top of the page reloads it. */
export function enablePullToRefresh(): () => void {
	const standalone =
		globalThis.matchMedia?.('(display-mode: standalone)').matches ||
		(globalThis.navigator as { standalone?: boolean }).standalone === true;
	if (!standalone) return () => {};

	let startY: number | null = null;
	const start = (event: TouchEvent) => {
		startY = window.scrollY <= 0 && event.touches.length === 1 ? event.touches[0].clientY : null;
	};
	const end = (event: TouchEvent) => {
		if (
			startY !== null &&
			event.changedTouches[0].clientY - startY > THRESHOLD &&
			window.scrollY <= 0
		) {
			location.reload();
		}
		startY = null;
	};
	window.addEventListener('touchstart', start, { passive: true });
	window.addEventListener('touchend', end, { passive: true });
	return () => {
		window.removeEventListener('touchstart', start);
		window.removeEventListener('touchend', end);
	};
}
