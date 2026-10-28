// Node 26 defines a global localStorage getter that returns undefined without --localstorage-file,
// and vitest's jsdom environment keeps it. Point the globals at the jsdom window's storage instead.
interface JsdomGlobal {
	jsdom?: { window: { localStorage: Storage; Storage: typeof Storage } };
}

const jsdomWindow = (globalThis as JsdomGlobal).jsdom?.window;
if (jsdomWindow && globalThis.localStorage === undefined) {
	Object.defineProperty(globalThis, 'localStorage', {
		configurable: true,
		value: jsdomWindow.localStorage,
	});
	Object.defineProperty(globalThis, 'Storage', { configurable: true, value: jsdomWindow.Storage });
}

export {};
