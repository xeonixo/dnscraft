import { afterEach, describe, expect, it, vi } from 'vitest';
import { DENSITY_KEY, readDensity, writeDensity } from './density';

afterEach(() => {
	vi.unstubAllGlobals();
});

function stubStorage(storage: Partial<Storage> | undefined): void {
	vi.stubGlobal('localStorage', storage);
}

describe('density preference', () => {
	it('defaults to comfortable and reads a stored compact choice', () => {
		const values = new Map<string, string>();
		stubStorage({
			getItem: (key: string) => values.get(key) ?? null,
			setItem: (key: string, value: string) => void values.set(key, value),
		});
		expect(readDensity()).toBe('comfortable');
		writeDensity('compact');
		expect(values.get(DENSITY_KEY)).toBe('compact');
		expect(readDensity()).toBe('compact');
	});

	it('keeps working when storage throws (blocked site data)', () => {
		stubStorage({
			getItem: () => {
				throw new DOMException('blocked', 'SecurityError');
			},
			setItem: () => {
				throw new DOMException('full', 'QuotaExceededError');
			},
		});
		expect(readDensity()).toBe('comfortable');
		expect(() => writeDensity('compact')).not.toThrow();
	});

	it('keeps working when no storage exists at all', () => {
		stubStorage(undefined);
		expect(readDensity()).toBe('comfortable');
		expect(() => writeDensity('compact')).not.toThrow();
	});
});
