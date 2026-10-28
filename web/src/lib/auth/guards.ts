import { navItemForPath, type Role } from '$lib/nav';
import { m } from '$lib/paraglide/messages';
import type { AuthStatus } from './state.svelte';
import { isPublicPath } from './public-routes';

const RANK: Record<Role, number> = { viewer: 0, admin: 1 };

/** Whether a role meets the minimum role of a route (admin satisfies viewer). */
export function canAccess(role: Role, minRole: Role): boolean {
	return RANK[role] >= RANK[minRole];
}

export type RouteDecision = 'allow' | 'login' | 'forbidden';

export interface RouteInput {
	status: AuthStatus;
	path: string;
	role: Role;
}

/**
 * What the layout does for a route. Fails closed: an unknown status asks for the login route.
 * The minimum role comes from the route's nav entry; routes without one need a viewer.
 */
export function routeDecision({ status, path, role }: RouteInput): RouteDecision {
	if (isPublicPath(path)) return 'allow';
	if (status !== 'authenticated') return 'login';
	const minRole = navItemForPath(path)?.minRole ?? 'viewer';
	return canAccess(role, minRole) ? 'allow' : 'forbidden';
}

export function roleLabel(role: Role): string {
	return role === 'admin' ? m.role_admin() : m.role_viewer();
}
