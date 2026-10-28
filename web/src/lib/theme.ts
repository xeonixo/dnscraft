import { writable } from 'svelte/store';

export type ThemeChoice = 'light' | 'dark' | 'system';

/** localStorage key; the inline bootstrap script in app.html reads the same key. */
export const THEME_STORAGE_KEY = 'dnscraft_theme';

function isChoice(value: unknown): value is ThemeChoice {
	return value === 'light' || value === 'dark' || value === 'system';
}

function readStored(): ThemeChoice {
	try {
		const value: unknown = globalThis.localStorage.getItem(THEME_STORAGE_KEY);
		return isChoice(value) ? value : 'system';
	} catch {
		// Storage unavailable (private window, blocked site data): follow the system.
		return 'system';
	}
}

/** Sets data-theme on <html>; "system" removes the attribute so the media query decides. */
function applyToDocument(choice: ThemeChoice): void {
	const root = globalThis.document?.documentElement;
	if (!root) return;
	if (choice === 'system') {
		root.removeAttribute('data-theme');
	} else {
		root.setAttribute('data-theme', choice);
	}
}

export const theme = writable<ThemeChoice>('system');

/** Loads the stored choice and applies it. Called once from the root layout. */
export function initTheme(): void {
	const choice = readStored();
	theme.set(choice);
	applyToDocument(choice);
}

/** Stores the choice (best effort) and applies it immediately. */
export function setTheme(choice: ThemeChoice): void {
	try {
		globalThis.localStorage.setItem(THEME_STORAGE_KEY, choice);
	} catch {
		// Not persisted: the choice lasts until the next load.
	}
	theme.set(choice);
	applyToDocument(choice);
}

/** The palette actually shown for a choice; "system" asks the OS preference. */
export function resolveTheme(choice: ThemeChoice): 'light' | 'dark' {
	if (choice !== 'system') return choice;
	return globalThis.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}
