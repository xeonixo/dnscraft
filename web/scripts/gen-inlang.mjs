// Writes .generated/project.inlang/settings.json for the Paraglide compiler.
//
// The inlang SDK treats a non-http `modules` entry as a file path relative to the project root
// (the directory that contains project.inlang, i.e. .generated/). The pinned message-format
// plugin is read from node_modules, so nothing is fetched from the network at build time.
// Plain Node, no dependencies.

import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const generatedRoot = join(root, '.generated');
const projectDir = join(generatedRoot, 'project.inlang');
const pluginPath = join(root, 'node_modules/@inlang/plugin-message-format/dist/index.js');
const outPath = join(projectDir, 'settings.json');

if (!existsSync(pluginPath)) {
	console.error(
		`gen-inlang: message-format plugin missing at ${pluginPath}. Run pnpm install first.`,
	);
	process.exit(1);
}

// Paths in settings are relative to the project root, which is .generated/.
const toProjectPath = (absolute) => relative(generatedRoot, absolute).split('\\').join('/');

const settings = {
	$schema: 'https://inlang.com/schema/project-settings',
	baseLocale: 'en',
	locales: ['en', 'de'],
	modules: [toProjectPath(pluginPath)],
	'plugin.inlang.messageFormat': {
		pathPattern: toProjectPath(join(root, 'messages/{locale}.json')),
	},
};

mkdirSync(projectDir, { recursive: true });
writeFileSync(outPath, JSON.stringify(settings, null, '\t') + '\n');
console.log(`gen-inlang: wrote ${outPath}`);
