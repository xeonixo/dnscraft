import { redirect } from '@sveltejs/kit';

// The page moved to /rules (Regeln). Old links keep working.
export const load = () => redirect(307, '/rules');
