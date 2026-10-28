// Neutralises control and bidi-override characters in untrusted text (domains, client names, rule
// text). Output is still plain text: Svelte escapes it, and nothing here builds markup.

/** Shown in place of every neutralised character. */
export const REPLACEMENT = '�';

/** Code points shown before a value is cut and the rest is offered behind an expansion. */
export const DISPLAY_LIMIT = 120;

/** Upper bound for the expanded value, so a hostile record cannot flood the DOM. */
export const FULL_LIMIT = 4096;

// C0 controls (NUL, TAB, LF, CR included), DEL, C1 controls, and the bidi embedding, override and
// isolate controls U+202A-U+202E and U+2066-U+2069 (Trojan-source style reordering).
const UNSAFE = /[\u0000-\u001F\u007F-\u009F‪-‮⁦-⁩]/gu;

export function neutralize(value: string): string {
	return value.replace(UNSAFE, REPLACEMENT);
}

export interface DisplayText {
	/** What the page shows first: neutralised and cut to `limit` code points. */
	text: string;
	/** The neutralised value, capped at FULL_LIMIT code points. */
	full: string;
	truncated: boolean;
}

/** Neutralises and cuts an untrusted value for display. Code points are never split. */
export function displayText(value: string | null | undefined, limit = DISPLAY_LIMIT): DisplayText {
	const clean = neutralize(value ?? '');
	const points = Array.from(clean);
	const full = points.slice(0, FULL_LIMIT).join('');
	const truncated = points.length > limit;
	const text = truncated ? `${points.slice(0, limit).join('')}…` : clean;
	return { text, full, truncated: truncated || points.length > FULL_LIMIT };
}
