import { redirect } from '@sveltejs/kit';

// The root has no screen of its own: it opens the dashboard.
export const load = () => redirect(307, '/dashboard');
