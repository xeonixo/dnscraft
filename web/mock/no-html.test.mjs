// Scans src/ for forbidden `{@html}` bindings (SPEC XSS rule).
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

const SRC = join(fileURLToPath(new URL('.', import.meta.url)), '..', 'src');

function walk(dir, out = []) {
	for (const name of readdirSync(dir)) {
		const path = join(dir, name);
		if (statSync(path).isDirectory()) {
			if (name === 'paraglide') continue;
			walk(path, out);
		} else if (/\.(svelte|ts)$/.test(name) && !name.endsWith('.test.ts')) {
			out.push(path);
		}
	}
	return out;
}

describe('no {@html} in src', () => {
	it('finds no raw HTML binding in application source', () => {
		for (const file of walk(SRC)) {
			const text = readFileSync(file, 'utf8');
			assert.equal(text.includes('{@html}'), false, file);
		}
	});
});
