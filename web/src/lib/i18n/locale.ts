import { m } from '$lib/paraglide/messages';
import {
	getLocale as getParaglideLocale,
	setLocale as setParaglideLocale,
	type Locale,
} from '$lib/paraglide/runtime';

/** Key shared with the Paraglide localStorage strategy (see vite.config.ts). */
export const LOCALE_STORAGE_KEY = 'dnscraft_locale';

type MessageFn = (params?: Record<string, unknown>) => string;
const catalog = m as unknown as Record<string, MessageFn | undefined>;

export function getLocale(): Locale {
	return getParaglideLocale();
}

/**
 * Stores the explicit choice, then switches the locale (Paraglide reloads the document).
 * Storage can be unavailable (private window, blocked site data); the switch still happens.
 */
export function setLocale(locale: Locale): void {
	try {
		globalThis.localStorage.setItem(LOCALE_STORAGE_KEY, locale);
	} catch {
		// Not persisted: the choice lasts only until the next load.
	}
	setParaglideLocale(locale);
}

/**
 * Maps a control-api error code to its message ID:
 * `control_api.auth.locked` -> `error_control_api_auth_locked`.
 * Codes without a message in the catalog fall back to `error_unknown`.
 */
export function errorMessageKey(code: string): string {
	const key = `error_${code.replace(/[^a-zA-Z0-9]/g, '_')}`;
	return typeof catalog[key] === 'function' ? key : 'error_unknown';
}

/** Placeholders a message needs even when the API omits the param (only the required role has one). */
const PARAM_DEFAULTS: Record<string, Record<string, string>> = {
	error_control_api_auth_insufficient_scope: { required: 'admin' },
	// API usually sends `reason`; this is only the empty-param fallback.
	error_policy_config_invalid: { reason: 'invalid' },
	error_listeners_config_invalid: { reason: 'invalid' },
};

/** Params are API data: only scalars are passed on, and they reach the message as plain text. */
function textParams(params: Record<string, unknown>): Record<string, string> {
	const out: Record<string, string> = {};
	for (const [name, value] of Object.entries(params)) {
		if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
			out[name] = String(value);
		}
	}
	return out;
}

/** Translated text for an error code; the raw code stays with the caller for a copyable line. */
export function errorMessage(code: string, params: Record<string, unknown> = {}): string {
	const key = errorMessageKey(code);
	const fn = catalog[key];
	return fn ? fn({ ...PARAM_DEFAULTS[key], ...textParams(params) }) : m.error_unknown();
}

/** Native display name of a locale, read from its `locale_name_<code>` message. */
export function localeName(locale: string): string {
	const fn = catalog[`locale_name_${locale}`];
	return fn ? fn() : locale;
}
