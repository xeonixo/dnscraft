// After `vite build`, writes build/csp-script-hashes.json with sha256 hashes of every
// inline <script> in build/index.html (theme bootstrap + SvelteKit starter). The mock
// (and later rust-embed) put these into script-src so CSP stays hash-based without
// 'unsafe-inline' for scripts.
import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const WEB = join(dirname(fileURLToPath(import.meta.url)), '..');
const INDEX = join(WEB, 'build', 'index.html');
const OUT = join(WEB, 'build', 'csp-script-hashes.json');

const html = await readFile(INDEX, 'utf8');
const hashes = [];
for (const match of html.matchAll(/<script(\s[^>]*)?>([\s\S]*?)<\/script>/gi)) {
	const attrs = match[1] ?? '';
	if (/\bsrc\s*=/.test(attrs)) continue;
	const body = match[2];
	if (!body) continue;
	hashes.push(`sha256-${createHash('sha256').update(body, 'utf8').digest('base64')}`);
}

if (hashes.length === 0) {
	throw new Error('gen-csp-hashes: no inline scripts found in build/index.html');
}

await writeFile(OUT, `${JSON.stringify(hashes, null, '\t')}\n`, 'utf8');
console.log(`Wrote build/csp-script-hashes.json (${hashes.length} inline script hashes).`);
