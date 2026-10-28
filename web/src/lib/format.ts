// Locale-aware formatting through Intl only (no date library). Every function takes the locale
// explicitly so the callers (and tests) decide it; the app passes getLocale().

export function formatNumber(value: number, locale: string): string {
	return new Intl.NumberFormat(locale).format(value);
}

/** A ratio in 0..1 as a percentage with `digits` fraction digits (`0.918` -> `91.8 %` in de). */
export function formatPercent(ratio: number, locale: string, digits = 1): string {
	return new Intl.NumberFormat(locale, {
		style: 'percent',
		maximumFractionDigits: digits,
	}).format(ratio);
}

export function formatMilliseconds(ms: number, locale: string): string {
	return new Intl.NumberFormat(locale, {
		style: 'unit',
		unit: 'millisecond',
		maximumFractionDigits: ms < 10 ? 1 : 0,
	}).format(ms);
}

/** Decimal (SI) byte units, which is what storage and transfer figures use. */
export function formatBytes(bytes: number, locale: string): string {
	const units = ['byte', 'kilobyte', 'megabyte', 'gigabyte', 'terabyte'] as const;
	let value = bytes;
	let index = 0;
	while (value >= 1000 && index < units.length - 1) {
		value /= 1000;
		index++;
	}
	return new Intl.NumberFormat(locale, {
		style: 'unit',
		unit: units[index],
		maximumFractionDigits: index === 0 ? 0 : 1,
	}).format(value);
}

/** A duration in seconds in the largest whole-ish unit: seconds, minutes, hours or days. */
export function formatDuration(seconds: number, locale: string): string {
	const steps: [unit: 'second' | 'minute' | 'hour' | 'day', size: number][] = [
		['day', 86_400],
		['hour', 3_600],
		['minute', 60],
		['second', 1],
	];
	const [unit, size] = steps.find(([, step]) => seconds >= step) ?? ['second', 1];
	return new Intl.NumberFormat(locale, {
		style: 'unit',
		unit,
		unitDisplay: 'short',
		maximumFractionDigits: 1,
	}).format(seconds / size);
}

/** "5 minutes ago" style text for a past or future instant relative to `now`. */
export function formatRelativeTime(target: Date, now: Date, locale: string): string {
	const deltaSeconds = Math.round((target.getTime() - now.getTime()) / 1000);
	const absolute = Math.abs(deltaSeconds);
	const units: [unit: Intl.RelativeTimeFormatUnit, size: number][] = [
		['day', 86_400],
		['hour', 3_600],
		['minute', 60],
		['second', 1],
	];
	const [unit, size] = units.find(([, step]) => absolute >= step) ?? ['second', 1];
	return new Intl.RelativeTimeFormat(locale, { numeric: 'auto' }).format(
		Math.round(deltaSeconds / size),
		unit,
	);
}

export function formatDateTime(date: Date, locale: string): string {
	return new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(date);
}

/** A SHA-256 hex digest as colon-separated upper-case pairs, the form owners compare and pin. */
export function formatFingerprint(hex: string): string {
	return hex
		.replace(/[^0-9a-fA-F]/g, '')
		.toUpperCase()
		.replace(/(.{2})(?=.)/g, '$1:');
}
