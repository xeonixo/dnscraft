// Table display preferences are per-viewer conveniences: they live in localStorage and are never
// required. Every access is guarded because storage can be blocked, full or missing (private windows).

export type Density = 'comfortable' | 'compact';

export const DENSITY_KEY = 'dnscraft_querylog_density';
export const TECHNICAL_KEY = 'dnscraft_querylog_technical';

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

/** Protocol, answer code and latency columns: off unless this viewer switched them on. */
export function readTechnical(): boolean {
	try {
		return globalThis.localStorage?.getItem(TECHNICAL_KEY) === 'on';
	} catch {
		return false;
	}
}

export function writeTechnical(on: boolean): void {
	try {
		globalThis.localStorage?.setItem(TECHNICAL_KEY, on ? 'on' : 'off');
	} catch {
		// Not persisted: the choice lasts until the next load.
	}
}
