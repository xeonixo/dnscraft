import { get, post, put, type RequestOptions } from './client';

// Typed reads and writes for the full configuration (Einstellungen > Konfiguration). Shapes follow
// crates/dnscraft-api/src/api/config_routes.rs and config_apply.rs. Only the fields the UI renders
// are declared. The snapshot is opaque to the UI except for the filter sets (mcp_rules).

/** `GET /api/v1/config`: `version` is null on a fresh install; secrets are never part of it. */
export interface ConfigSnapshot {
	version: number | null;
	config: Record<string, unknown> | null;
}

/** One `{ code, path, params }` entry from a dry run. `path` is null when the module gives none. */
export interface ConfigFinding {
	code: string;
	path: string | null;
	params: Record<string, unknown> | null;
}

/** Section-level diff of the candidate against the stored snapshot. Names only, never values. */
export interface ConfigDiff {
	changed_sections: string[];
	added: string[];
	removed: string[];
	changed: string[];
}

/** `POST /api/v1/config/validate`: HTTP 200 even when invalid; nothing is stored, applied or audited. */
export interface ValidateResult {
	valid: boolean;
	config_version: number | null;
	errors: ConfigFinding[];
	warnings: ConfigFinding[];
	diff: ConfigDiff;
}

/** One row of `GET /api/v1/config/versions`. The API does not expose who saved a version. */
export interface ConfigVersion {
	version: number;
	/** RFC 3339 instant. */
	created_at: string;
}

export interface VersionPage {
	current_version: number | null;
	versions: ConfigVersion[];
	has_more: boolean;
	next_offset: number | null;
}

export interface SaveResult {
	version: number;
}

export interface RollbackResult {
	version: number;
	restored_from: number;
}

/** Version conflict or invalid If-Match (HTTP 409). */
export const CONFIG_VERSION_CODE = 'control_api.config.version';

/** `If-Match` for the version the screen last loaded; no precondition when no version exists yet. */
export function ifMatchFor(version: number | null): RequestOptions['ifMatch'] {
	return version === null ? undefined : String(version);
}

export const getConfig = (): Promise<ConfigSnapshot> => get<ConfigSnapshot>('/config');

export const validateConfig = (body: unknown, version: number | null): Promise<ValidateResult> =>
	post<ValidateResult>('/config/validate', { body, ifMatch: ifMatchFor(version) });

export const saveConfig = (body: unknown, version: number | null): Promise<SaveResult> =>
	put<SaveResult>('/config', { body, ifMatch: ifMatchFor(version) });

export const getVersions = (limit: number, offset: number): Promise<VersionPage> =>
	get<VersionPage>(`/config/versions?limit=${limit}&offset=${offset}`);

export const rollbackConfig = (target: number, version: number | null): Promise<RollbackResult> =>
	post<RollbackResult>(`/config/versions/${target}/rollback`, { ifMatch: ifMatchFor(version) });
