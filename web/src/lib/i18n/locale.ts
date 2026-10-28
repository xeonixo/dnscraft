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

/** Translated text for an error code; the raw code stays with the caller for a copyable line. */
export function errorMessage(code: string, params?: Record<string, unknown>): string {
	const fn = catalog[errorMessageKey(code)];
	return fn ? fn(params) : m.error_unknown();
}

/** Native display name of a locale, read from its `locale_name_<code>` message. */
export function localeName(locale: string): string {
	const fn = catalog[`locale_name_${locale}`];
	return fn ? fn() : locale;
}
