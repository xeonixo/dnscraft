import { get } from './client';

/** `GET /api/v1/update/check` (system_routes.rs). */
export interface UpdateCheck {
	enabled: boolean;
	current: string;
	latest: string | null;
	update_available: boolean;
	release_url: string | null;
	checked_at: string | null;
	error?: { code: string };
}

export const getUpdateCheck = (): Promise<UpdateCheck> => get('/update/check');
