/** Routes that render without the app shell and do not need a session. */
export const PUBLIC_ROUTES: readonly string[] = ['/login', '/setup'];

export function isPublicPath(pathname: string): boolean {
	return PUBLIC_ROUTES.includes(pathname);
}
