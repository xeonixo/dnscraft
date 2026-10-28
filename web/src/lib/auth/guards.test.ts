import { describe, expect, it, vi } from 'vitest';
import { canAccess, routeDecision } from './guards';

// A route that needs admin does not exist in the nav yet; stand one in for the decision table.
vi.mock('$lib/nav', async (importOriginal) => {
	const actual = await importOriginal<typeof import('$lib/nav')>();
	return {
		...actual,
		navItemForPath: (path: string) =>
			path === '/admin-only' ? { minRole: 'admin' } : actual.navItemForPath(path),
	};
});

describe('canAccess', () => {
	it.each([
		['viewer', 'viewer', true],
		['viewer', 'admin', false],
		['admin', 'viewer', true],
		['admin', 'admin', true],
	] as const)('role %s with minimum %s is allowed: %s', (role, minRole, expected) => {
		expect(canAccess(role, minRole)).toBe(expected);
	});
});

describe('routeDecision', () => {
	it.each([
		[
			'unknown status asks for login (fails closed)',
			{ status: 'unknown', path: '/dashboard', role: 'admin' },
			'login',
		],
		[
			'anonymous user is sent to login',
			{ status: 'anonymous', path: '/dashboard', role: 'admin' },
			'login',
		],
		[
			'viewer may open a viewer route',
			{ status: 'authenticated', path: '/dashboard', role: 'viewer' },
			'allow',
		],
		[
			'viewer is refused an admin route',
			{ status: 'authenticated', path: '/admin-only', role: 'viewer' },
			'forbidden',
		],
		[
			'admin may open an admin route',
			{ status: 'authenticated', path: '/admin-only', role: 'admin' },
			'allow',
		],
		[
			'a route without a nav entry needs only a viewer',
			{ status: 'authenticated', path: '/no-such-screen', role: 'viewer' },
			'allow',
		],
		[
			'login is public for anonymous users',
			{ status: 'anonymous', path: '/login', role: 'viewer' },
			'allow',
		],
		[
			'setup is public while unknown',
			{ status: 'unknown', path: '/setup', role: 'viewer' },
			'allow',
		],
	] as const)('%s', (_name, input, expected) => {
		expect(routeDecision(input)).toBe(expected);
	});
});
