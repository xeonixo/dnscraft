// Writes solid-color PNG icons for the PWA manifest (no external deps).
import { createHash } from 'node:crypto';
import { deflateSync } from 'node:zlib';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', 'static');

/** Accent token (--accent, light mode). */
const RGB = [0x00, 0x60, 0xdf];

const CRC_TABLE = (() => {
	const table = new Uint32Array(256);
	for (let n = 0; n < 256; n++) {
		let c = n;
		for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
		table[n] = c >>> 0;
	}
	return table;
})();

function crc32(data) {
	let crc = 0xffffffff;
	for (let i = 0; i < data.length; i++) crc = CRC_TABLE[(crc ^ data[i]) & 0xff] ^ (crc >>> 8);
	return (crc ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
	const len = Buffer.alloc(4);
	len.writeUInt32BE(data.length);
	const body = Buffer.concat([Buffer.from(type), data]);
	const crc = Buffer.alloc(4);
	crc.writeUInt32BE(crc32(body));
	return Buffer.concat([len, body, crc]);
}

function solidPng(size, [r, g, b]) {
	const row = Buffer.alloc(1 + size * 3);
	row[0] = 0;
	for (let x = 0; x < size; x++) {
		const o = 1 + x * 3;
		row[o] = r;
		row[o + 1] = g;
		row[o + 2] = b;
	}
	const raw = Buffer.concat(Array.from({ length: size }, () => row));
	const ihdr = Buffer.alloc(13);
	ihdr.writeUInt32BE(size, 0);
	ihdr.writeUInt32BE(size, 4);
	ihdr[8] = 8;
	ihdr[9] = 2;
	ihdr[10] = 0;
	ihdr[11] = 0;
	ihdr[12] = 0;
	return Buffer.concat([
		Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
		chunk('IHDR', ihdr),
		chunk('IDAT', deflateSync(raw)),
		chunk('IEND', Buffer.alloc(0)),
	]);
}

async function writeIcon(relativePath, size) {
	const path = join(ROOT, relativePath);
	await mkdir(dirname(path), { recursive: true });
	await writeFile(path, solidPng(size, RGB));
}

await writeIcon('icons/icon-192.png', 192);
await writeIcon('icons/icon-512.png', 512);
await writeIcon('icons/icon-512-maskable.png', 512);
await writeIcon('apple-touch-icon.png', 180);

const digest = createHash('sha256').update(solidPng(192, RGB)).digest('hex').slice(0, 12);
console.log(`Wrote PWA icons under static/ (accent #0060df, digest ${digest}).`);
