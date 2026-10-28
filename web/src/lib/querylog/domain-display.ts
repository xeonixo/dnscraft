// Unicode view of an ASCII (punycode) owner name, for display only. The API stores and filters on
// the ASCII form; the Unicode form is a reading aid and is always shown next to the ASCII form.

const BASE = 36;
const T_MIN = 1;
const T_MAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 0x80;
const MAX_CODE_POINT = 0x10ffff;
/** RFC 1035 labels are at most 63 octets; anything longer is not decoded. */
const MAX_LABEL = 63;

function digitValue(code: number): number {
	if (code >= 0x30 && code <= 0x39) return code - 22; // '0'..'9' -> 26..35
	if (code >= 0x41 && code <= 0x5a) return code - 0x41; // 'A'..'Z'
	if (code >= 0x61 && code <= 0x7a) return code - 0x61; // 'a'..'z'
	return -1;
}

function adapt(delta: number, points: number, first: boolean): number {
	let d = first ? Math.floor(delta / DAMP) : Math.floor(delta / 2);
	d += Math.floor(d / points);
	let k = 0;
	while (d > Math.floor(((BASE - T_MIN) * T_MAX) / 2)) {
		d = Math.floor(d / (BASE - T_MIN));
		k += BASE;
	}
	return k + Math.floor(((BASE - T_MIN + 1) * d) / (d + SKEW));
}

/** RFC 3492 decoding of one label without its `xn--` prefix. Throws on malformed input. */
export function decodePunycode(input: string): string {
	const output: number[] = [];
	const basic = input.lastIndexOf('-');
	for (let j = 0; j < Math.max(basic, 0); j++) {
		const code = input.charCodeAt(j);
		if (code >= 0x80) throw new RangeError('non-basic code point');
		output.push(code);
	}

	let n = INITIAL_N;
	let i = 0;
	let bias = INITIAL_BIAS;
	for (let pos = basic > 0 ? basic + 1 : 0; pos < input.length;) {
		const previous = i;
		let weight = 1;
		for (let k = BASE; ; k += BASE) {
			if (pos >= input.length) throw new RangeError('truncated');
			const digit = digitValue(input.charCodeAt(pos++));
			if (digit < 0) throw new RangeError('bad digit');
			i += digit * weight;
			const t = k <= bias ? T_MIN : k >= bias + T_MAX ? T_MAX : k - bias;
			if (digit < t) break;
			weight *= BASE - t;
		}
		bias = adapt(i - previous, output.length + 1, previous === 0);
		n += Math.floor(i / (output.length + 1));
		if (n > MAX_CODE_POINT) throw new RangeError('overflow');
		i %= output.length + 1;
		output.splice(i++, 0, n);
	}
	return String.fromCodePoint(...output);
}

/** The Unicode form of an owner name; labels that do not decode stay as they are. */
export function unicodeName(name: string): string {
	return name
		.split('.')
		.map((label) => {
			if (!/^xn--/i.test(label) || label.length > MAX_LABEL) return label;
			try {
				return decodePunycode(label.slice(4));
			} catch {
				return label;
			}
		})
		.join('.');
}
