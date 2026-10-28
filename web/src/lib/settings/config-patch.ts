import { getConfig, saveConfig, ifMatchFor, type ConfigSnapshot } from '$lib/api/config';

/** Reads the versioned snapshot or throws when config is unavailable. */
export async function loadConfigSnapshot(): Promise<ConfigSnapshot> {
	return getConfig();
}

/** Merges `patch` into one top-level section and saves with If-Match. */
export async function patchConfigSection(
	section: string,
	patch: Record<string, unknown>,
): Promise<number> {
	const snapshot = await getConfig();
	const base = snapshot.config ?? {};
	const current = (base[section] as Record<string, unknown> | undefined) ?? {};
	const next = {
		...base,
		[section]: { ...current, ...patch },
	};
	const result = await saveConfig(next, snapshot.version);
	return result.version;
}

export { ifMatchFor };
