import { describe, expect, it } from 'vitest';
import {
	formatBytes,
	formatDuration,
	formatFingerprint,
	formatMilliseconds,
	formatNumber,
	formatPercent,
	formatRelativeTime,
} from './format';
import { toDomainName } from './domain-name';

// Intl output uses no-break spaces in some locales; tests compare with plain spaces.
const plain = (text: string): string => text.replace(/ | /g, ' ');

describe('number and percentage formatting per locale', () => {
	it.each([
		['en', '1,234,567'],
		['de', '1.234.567'],
	])('groups thousands for %s', (locale, expected) => {
		expect(formatNumber(1_234_567, locale)).toBe(expected);
	});

	it('formats ratios as percentages with a locale decimal separator', () => {
		expect(plain(formatPercent(0.918, 'en'))).toBe('91.8%');
		expect(plain(formatPercent(0.918, 'de'))).toBe('91,8 %');
	});

	it('honours the requested fraction digits', () => {
		expect(plain(formatPercent(0.5, 'de', 0))).toBe('50 %');
	});
});

describe('unit formatting', () => {
	it('formats milliseconds with fewer decimals above 10 ms', () => {
		expect(plain(formatMilliseconds(7.25, 'en'))).toBe('7.3 ms');
		expect(plain(formatMilliseconds(42.4, 'de'))).toBe('42 ms');
	});

	it('scales bytes with decimal units', () => {
		expect(plain(formatBytes(1_500_000, 'en'))).toBe('1.5 MB');
		expect(plain(formatBytes(1_500_000, 'de'))).toBe('1,5 MB');
		expect(plain(formatBytes(512, 'en'))).toBe('512 byte');
	});

	it('picks the largest fitting duration unit', () => {
		expect(plain(formatDuration(300, 'en'))).toBe('5 min');
		expect(plain(formatDuration(3_600, 'de'))).toBe('1 Std.');
		expect(plain(formatDuration(45, 'en'))).toBe('45 sec');
	});
});

describe('relative time', () => {
	const now = new Date('2026-10-28T12:00:00Z');

	it('expresses past instants in the locale', () => {
		const fourteenMinutesAgo = new Date(now.getTime() - 14 * 60_000);
		expect(formatRelativeTime(fourteenMinutesAgo, now, 'en')).toBe('14 minutes ago');
		expect(formatRelativeTime(fourteenMinutesAgo, now, 'de')).toBe('vor 14 Minuten');
	});

	it('uses the named word for yesterday under numeric auto', () => {
		const yesterday = new Date(now.getTime() - 86_400_000);
		expect(formatRelativeTime(yesterday, now, 'en')).toBe('yesterday');
	});
});

describe('fingerprint formatting', () => {
	it('renders lowercase hex as upper-case colon pairs', () => {
		expect(formatFingerprint('3a9c7f11de42')).toBe('3A:9C:7F:11:DE:42');
	});
});

describe('domain name normalisation', () => {
	it.each([
		['Example.COM', 'example.com'],
		['  www.example.com. ', 'www.example.com'],
		['a-b.test', 'a-b.test'],
	])('accepts %j as %j', (input, expected) => {
		expect(toDomainName(input)).toBe(expected);
	});

	it.each([
		'',
		'*.example.com',
		'a..b',
		'-lead.example.com',
		'trail-.example.com',
		'café.test',
		'<script>alert(1)</script>',
		`${'a'.repeat(64)}.test`,
	])('rejects %j', (input) => {
		expect(toDomainName(input)).toBeNull();
	});
});
