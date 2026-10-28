// Table density is a per-viewer convenience: it lives in localStorage and is never required. Every
// access is guarded because storage can be blocked, full or missing (private windows).

export type Density = 'comfortable' | 'compact';

export const DENSITY_KEY = 'dnscraft_querylog_density';

export function readDensity(): Density {
	try {
		return globalThis.localStorage?.getItem(DENSITY_KEY) === 'compact' ? 'compact' : 'comfortable';
	} catch {
		return 'comfortable';
	}
}

export function writeDensity(density: Density): void {
	try {
		globalThis.localStorage?.setItem(DENSITY_KEY, density);
	} catch {
		// Not persisted: the choice lasts until the next load.
	}
}
