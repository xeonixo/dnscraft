import { describe, expect, it } from 'vitest';
import tokensCss from './tokens.css?raw';

// Every component file under src (except the token file itself) is scanned for literal colors.
const componentFiles = import.meta.glob('/src/**/*.{svelte,css}', {
	query: '?raw',
	import: 'default',
	eager: true,
}) as Record<string, string>;

const REQUIRED_TOKENS = [
	'--canvas',
	'--surface',
	'--surface-2',
	'--label',
	'--label-2',
	'--label-3',
	'--separator',
	'--track-off',
	'--accent',
	'--accent-fill',
	'--ok',
	'--danger',
	'--danger-fill',
	'--warn',
	'--warn-fill',
	'--font-ui',
	'--font-mono',
	'--r-card',
	'--r-ctl',
	'--shadow',
	'--space-1',
	'--space-2',
	'--space-3',
	'--space-4',
	'--space-5',
	'--space-6',
	'--space-7',
	'--duration-fast',
	'--duration-normal',
	'--duration-slow',
	'--ease',
];

interface Frame {
	selector: string;
	ancestors: string[];
	decls: Map<string, string>;
}

/** Minimal CSS block parser: returns every rule with its ancestor at-rules and declarations. */
function parseCss(css: string): Frame[] {
	const text = css.replace(/\/\*[\s\S]*?\*\//g, '');
	const frames: Frame[] = [];
	const stack: Frame[] = [];
	let buf = '';

	const flushDecl = (): void => {
		const top = stack[stack.length - 1];
		const idx = buf.indexOf(':');
		if (top && idx > 0) {
			top.decls.set(buf.slice(0, idx).trim(), buf.slice(idx + 1).trim());
		}
		buf = '';
	};

	for (const ch of text) {
		if (ch === '{') {
			stack.push({
				selector: buf.trim(),
				ancestors: stack.map((f) => f.selector),
				decls: new Map(),
			});
			buf = '';
		} else if (ch === ';') {
			flushDecl();
		} else if (ch === '}') {
			flushDecl();
			const frame = stack.pop();
			if (frame) frames.push(frame);
		} else {
			buf += ch;
		}
	}
	return frames;
}

const frames = parseCss(tokensCss);

const isDarkFrame = (f: Frame): boolean =>
	f.ancestors.some((a) => a.includes('prefers-color-scheme: dark')) ||
	f.selector === ":root[data-theme='dark']";
const isContrastFrame = (f: Frame): boolean =>
	f.ancestors.some((a) => a.includes('prefers-contrast: more'));
const isBase = (f: Frame): boolean => f.ancestors.length === 0 && f.selector === ':root';

/** Resolves the token map for one mode by applying matching frames in source order. */
function resolveMode(mode: 'light' | 'dark' | 'contrast' | 'dark-contrast'): Map<string, string> {
	const resolved = new Map<string, string>();
	for (const f of frames) {
		const dark = isDarkFrame(f);
		const contrast = isContrastFrame(f);
		const applies =
			isBase(f) ||
			(mode === 'dark' && dark && !contrast) ||
			(mode === 'contrast' && contrast && !dark) ||
			(mode === 'dark-contrast' && dark && contrast);
		if (applies) {
			for (const [prop, value] of f.decls) resolved.set(prop, value);
		}
	}
	// Frames with a base :root selector only, so light mode excludes the variant blocks.
	if (mode === 'light') {
		return new Map(frames.filter(isBase).flatMap((f) => [...f.decls]));
	}
	return resolved;
}

function hexToRgb(hex: string): [number, number, number] {
	const m = /^#([0-9a-fA-F]{6})$/.exec(hex);
	if (!m) throw new Error(`not a 6-digit hex color: ${hex}`);
	const n = parseInt(m[1], 16);
	return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}

function luminance(hex: string): number {
	const [r, g, b] = hexToRgb(hex).map((c) => {
		const s = c / 255;
		return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
	});
	return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrastRatio(a: string, b: string): number {
	const la = luminance(a);
	const lb = luminance(b);
	return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
}

function value(map: Map<string, string>, token: string): string {
	const v = map.get(token);
	if (v === undefined) throw new Error(`token ${token} is not defined`);
	return v;
}

describe('design tokens', () => {
	it('parses the token file', () => {
		expect(frames.length).toBeGreaterThan(0);
	});

	it.each(['light', 'dark', 'contrast', 'dark-contrast'] as const)(
		'defines every required token in the %s mode',
		(mode) => {
			const map = resolveMode(mode);
			for (const token of REQUIRED_TOKENS) {
				expect(map.has(token), `${token} missing in ${mode}`).toBe(true);
			}
		},
	);

	it('redefines the dark palette in the dark modes', () => {
		expect(value(resolveMode('dark'), '--canvas')).not.toBe(
			value(resolveMode('light'), '--canvas'),
		);
	});

	it('defines an increased-contrast label set that is stronger than the default', () => {
		expect(value(resolveMode('contrast'), '--label-2')).not.toBe(
			value(resolveMode('light'), '--label-2'),
		);
	});

	const pairs: [string, string, string][] = [
		['light', '--label', '--canvas'],
		['light', '--label', '--surface'],
		['light', '--accent', '--surface'],
		['dark', '--label', '--canvas'],
		['dark', '--label', '--surface'],
		['dark', '--accent', '--surface'],
	];

	it.each(pairs)('meets 4.5:1 for %s %s on %s', (mode, fg, bg) => {
		const map = resolveMode(mode as 'light' | 'dark');
		const ratio = contrastRatio(value(map, fg), value(map, bg));
		expect(ratio).toBeGreaterThanOrEqual(4.5);
	});

	it('uses no literal colors in components (only tokens.css may hold them)', () => {
		const literal = /#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(/;
		const scanned = Object.entries(componentFiles).filter(
			([path]) => !path.endsWith('/tokens.css'),
		);
		expect(scanned.length).toBeGreaterThan(0);
		const offenders = scanned.filter(([, source]) => literal.test(source)).map(([path]) => path);
		expect(offenders).toEqual([]);
	});
});
