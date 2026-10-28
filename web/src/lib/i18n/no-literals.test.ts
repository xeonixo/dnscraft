import { describe, expect, it } from 'vitest';

// Fails when a component shows text that did not come from the message catalog.
// Heuristic, not a Svelte parser: it covers text nodes and the literal attribute values
// aria-label, title, placeholder and alt. Expressions `{...}` are dropped before checking.

const LETTER = /\p{L}/u;
const LITERAL_ATTRIBUTE =
	/\b(aria-label|title|placeholder|alt)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/g;

/** Returns one entry per user-facing literal found in a .svelte source. */
export function findLiterals(source: string): string[] {
	const markup = source
		.replace(/<!--[\s\S]*?-->/g, '')
		.replace(/<(script|style)\b[\s\S]*?<\/\1\s*>/g, '');
	const found: string[] = [];
	let text = '';
	let tag = '';
	let inTag = false;
	let quote: string | null = null;
	let depth = 0;

	const flushText = (): void => {
		if (LETTER.test(text)) found.push(`text: ${text.trim()}`);
		text = '';
	};
	const flushTag = (): void => {
		for (const match of tag.matchAll(LITERAL_ATTRIBUTE)) {
			const value = match[2] ?? match[3] ?? match[4] ?? '';
			if (LETTER.test(value)) found.push(`${match[1]}="${value}"`);
		}
		tag = '';
	};

	for (let i = 0; i < markup.length; i++) {
		const ch = markup[i];

		if (ch === '{') {
			// Entering an expression: keep a placeholder in tags so attribute values stay parseable.
			if (depth === 0 && inTag) tag += '{}';
			depth++;
			continue;
		}
		if (ch === '}' && depth > 0) {
			depth--;
			continue;
		}
		if (depth > 0) continue;

		if (inTag) {
			if (quote) {
				if (ch === quote) quote = null;
				tag += ch;
			} else if (ch === '"' || ch === "'") {
				quote = ch;
				tag += ch;
			} else if (ch === '>') {
				tag += ch;
				flushTag();
				inTag = false;
			} else {
				tag += ch;
			}
		} else if (ch === '<' && /[A-Za-z/!]/.test(markup[i + 1] ?? '')) {
			flushText();
			inTag = true;
			tag = '<';
			quote = null;
		} else {
			text += ch;
		}
	}
	flushText();
	return found;
}

describe('literal scanner (self-test)', () => {
	it.each([
		['bare text node', '<h1>Welcome</h1>'],
		['text mixed with an expression', '<p>Hello {name}, you have 3 items</p>'],
		['literal aria-label', '<button aria-label="Close">{icon}</button>'],
		['literal title', '<span title="Help">x</span>'],
		['literal placeholder', '<input placeholder="Search domains" />'],
		['literal alt', '<img alt="Logo" src="logo.svg" />'],
		['literal inside a quoted expression mix', '<b title="Edit {id}">{id}</b>'],
	])('flags %s', (_name, fixture) => {
		expect(findLiterals(fixture)).not.toEqual([]);
	});

	it.each([
		['message calls', '<h1>{m.app_name()}</h1>'],
		[
			'expression attributes',
			"<button aria-label={m.action_cancel()} title={m.action_cancel()}>{'×'}</button>",
		],
		['empty alt', '<img alt="" src="logo.svg" />'],
		[
			'script and style content',
			'<script lang="ts">let label = \'Hello\';</script><style>p { color: red; }</style><p>{label}</p>',
		],
		[
			'comments',
			'<!-- Welcome comment --><div class="card" data-testid="x">{m.state_empty()}</div>',
		],
		[
			'">" inside an expression',
			'<button onclick={() => (n > 1 ? a() : b())}>{m.action_save()}</button>',
		],
	])('accepts %s', (_name, fixture) => {
		expect(findLiterals(fixture)).toEqual([]);
	});
});

describe('components under src', () => {
	const components = import.meta.glob('/src/**/*.svelte', {
		query: '?raw',
		import: 'default',
		eager: true,
	}) as Record<string, string>;

	it('finds at least one component to scan', () => {
		expect(Object.keys(components).length).toBeGreaterThan(0);
	});

	it.each(Object.entries(components))('%s has no raw user-facing literals', (_path, source) => {
		expect(findLiterals(source)).toEqual([]);
	});
});
