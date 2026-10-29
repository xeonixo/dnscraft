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
 * Switches the locale. Paraglide stores the choice under `LOCALE_STORAGE_KEY` and reloads the document;
 * the store must not happen before this call, or Paraglide sees the locale as unchanged and skips the reload.
 * Storage can be unavailable (private window, blocked site data): the choice then is not persisted.
 */
export function setLocale(locale: Locale): void {
	try {
		setParaglideLocale(locale);
	} catch {
		// Not persisted: the choice lasts only until the next load.
	}
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
	error_tls_config_invalid: { reason: 'invalid' },
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

/**
 * Known English `reason` texts of the Rust validators, mapped to message keys. The server sends the
 * reason as free text; anything not listed here is shown as sent.
 */
const REASONS: { pattern: RegExp; key: string; param?: string }[] = [
	{ pattern: /\bid must match \[a-z0-9-\]/i, key: 'error_reason_id_pattern' },
	{ pattern: /\bmust match \[a-z0-9-\]/i, key: 'error_reason_id_pattern' },
	{
		pattern: /subnet (.+?) is listed on more than one view/i,
		key: 'error_reason_subnet_overlap',
		param: 'subnet',
	},
	{ pattern: /invalid IPv4 address/i, key: 'error_reason_invalid_ipv4' },
	{ pattern: /invalid IPv6 address/i, key: 'error_reason_invalid_ipv6' },
	{ pattern: /empty label in domain name/i, key: 'error_reason_empty_label' },
];

/** Translated form of a server reason text, or the text itself when it is not a known one. */
export function reasonMessage(reason: string): string {
	for (const { pattern, key, param } of REASONS) {
		const match = pattern.exec(reason);
		const fn = catalog[key];
		if (match && fn) return fn(param ? { [param]: match[1] } : {});
	}
	return reason;
}

/** Translated text for an error code; the raw code stays with the caller for a copyable line. */
export function errorMessage(code: string, params: Record<string, unknown> = {}): string {
	const key = errorMessageKey(code);
	const fn = catalog[key];
	if (!fn) return m.error_unknown();
	const text = { ...PARAM_DEFAULTS[key], ...textParams(params) };
	if (typeof text.reason === 'string') text.reason = reasonMessage(text.reason);
	return fn(text);
}

/** Native display name of a locale, read from its `locale_name_<code>` message. */
export function localeName(locale: string): string {
	const fn = catalog[`locale_name_${locale}`];
	return fn ? fn() : locale;
}
