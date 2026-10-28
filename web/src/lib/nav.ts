import type { RouteId } from '$app/types';
import type { IconName } from '$lib/components/icons';
import { m } from '$lib/paraglide/messages';

/** Roles from SPEC-web-ui.md § Role gating. A viewer never sees an item that needs admin. */
export type Role = 'viewer' | 'admin';

/**
 * Routes that take no parameters. Navigation lists only these; a dynamic route (such as
 * /query-log/[id]) is linked with resolve(route, params) at the call site instead.
 */
export type StaticRouteId = Exclude<RouteId, '/query-log/[id]'>;

export interface NavItem {
	/** SvelteKit route path, also the key for the page title and the active item. */
	path: StaticRouteId;
	label: () => string;
	icon: IconName;
	minRole: Role;
}

export interface NavSection {
	heading: () => string;
	items: NavItem[];
}

const item = (
	path: StaticRouteId,
	label: () => string,
	icon: IconName,
	minRole: Role = 'viewer',
): NavItem => ({
	path,
	label,
	icon,
	minRole,
});

/** Sidebar sections in SPEC order (SPEC-web-ui.md § Navigation). */
export const navSections: NavSection[] = [
	{
		heading: () => m.nav_section_overview(),
		items: [
			item('/dashboard', () => m.nav_dashboard(), 'grid'),
			item('/query-log', () => m.nav_queries(), 'download'),
			item('/alerts', () => m.nav_alerts(), 'bell'),
		],
	},
	{
		heading: () => m.nav_section_filtering(),
		items: [
			item('/filter-sets', () => m.nav_filter_sets(), 'layers'),
			item('/filter-lists', () => m.nav_filter_lists(), 'list'),
			item('/mcp-rules', () => m.nav_rules_exceptions(), 'zap'),
			item('/blocked-services', () => m.nav_blocked_services(), 'ban'),
		],
	},
	{
		heading: () => m.nav_section_dns_rules(),
		items: [
			item('/zones', () => m.nav_zones(), 'target'),
			item('/names', () => m.nav_names(), 'text'),
			item('/forward-zones', () => m.nav_forward_zones(), 'arrow-right'),
			item('/profiles', () => m.nav_profiles(), 'sliders'),
			item('/test-query', () => m.nav_test_query(), 'play-circle'),
		],
	},
	{
		heading: () => m.nav_section_network(),
		items: [
			item('/clients', () => m.nav_clients(), 'user'),
			item('/doh-clients', () => m.nav_doh_clients(), 'user-check'),
			item('/listeners', () => m.nav_listeners(), 'network'),
			item('/tls', () => m.nav_tls(), 'lock'),
			item('/cluster', () => m.nav_nodes(), 'server'),
		],
	},
];

/** Einstellungen is one item set apart below the sections (tabs live on the screen). */
export const navSettings = item('/settings', () => m.nav_settings(), 'settings');

/** Hilfe & Feedback is a link in the sidebar foot, not a section item. */
export const navFeedback = item('/feedback', () => m.nav_help_feedback(), 'message-square');

const routed: NavItem[] = [
	...navSections.flatMap((section) => section.items),
	navSettings,
	navFeedback,
];

/** The nav entry for a route, used for the toolbar title, document title and placeholder icon. */
export function navItemForPath(pathname: string): NavItem | undefined {
	return (
		routed.find((entry) => entry.path === pathname) ??
		// Detail routes (for example /query-log/:id) belong to the section they open from.
		routed.find((entry) => pathname.startsWith(`${entry.path}/`))
	);
}

export function isVisible(entry: NavItem, role: Role): boolean {
	return entry.minRole === 'viewer' || role === 'admin';
}
