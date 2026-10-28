/** Registers the root service worker when the page is a secure context. */
export function registerServiceWorker(): void {
	if (typeof globalThis.window === 'undefined') return;
	if (!globalThis.isSecureContext) return;
	if (!('serviceWorker' in globalThis.navigator)) return;

	void globalThis.navigator.serviceWorker.register('/sw.js', { scope: '/' }).catch(() => {
		// Self-signed bootstrap or blocked SW: the app still runs; offline shell is unavailable.
	});
}
