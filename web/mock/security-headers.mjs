/** CSP and related headers for HTML served by the local mock (matches SPEC-web-ui intent). */

import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

/** sha256 of the inline theme bootstrap in src/app.html (stable across builds). */
export const THEME_BOOTSTRAP_HASH = 'sha256-+/UWW+kFTQfRcLtOTJw4BrviiPaL5UMxrjQpU8Pu7Mk=';

const DEFAULT_BUILD = join(dirname(fileURLToPath(import.meta.url)), '..', 'build');

/**
 * Inline script hashes for script-src. Prefers build/csp-script-hashes.json (written by
 * scripts/gen-csp-hashes.mjs after vite build) so the SvelteKit starter script is included;
 * falls back to the theme bootstrap hash alone when the file is missing (unit tests).
 */
export function scriptSrcHashes(buildDir = DEFAULT_BUILD) {
	const file = join(buildDir, 'csp-script-hashes.json');
	if (existsSync(file)) {
		const parsed = JSON.parse(readFileSync(file, 'utf8'));
		if (Array.isArray(parsed) && parsed.length > 0) return parsed;
	}
	return [THEME_BOOTSTRAP_HASH];
}

export function buildCsp(hashes = scriptSrcHashes()) {
	const scriptSrc = ['script-src', "'self'", ...hashes.map((h) => `'${h}'`)].join(' ');
	return [
		"default-src 'self'",
		scriptSrc,
		"style-src 'self' 'unsafe-inline'",
		"img-src 'self' data:",
		"connect-src 'self'",
		"font-src 'self'",
		"object-src 'none'",
		"base-uri 'self'",
		"frame-ancestors 'none'",
		"form-action 'self'",
	].join('; ');
}

/** Snapshot used by unit tests that do not point at a real build/ tree. */
export const CSP = buildCsp([THEME_BOOTSTRAP_HASH]);

export const BASE_SECURITY_HEADERS = {
	'X-Content-Type-Options': 'nosniff',
	'Referrer-Policy': 'no-referrer',
};

export function cacheControlForPath(pathname) {
	if (pathname.startsWith('/_app/immutable/')) {
		return 'public, max-age=31536000, immutable';
	}
	if (pathname === '/' || pathname.endsWith('.html') || pathname === '/index.html') {
		return 'no-cache';
	}
	if (pathname === '/manifest.webmanifest' || pathname === '/sw.js') {
		return 'no-cache';
	}
	return 'public, max-age=3600';
}

export function htmlSecurityHeaders(buildDir = DEFAULT_BUILD) {
	return {
		...BASE_SECURITY_HEADERS,
		'Content-Security-Policy': buildCsp(scriptSrcHashes(buildDir)),
	};
}
