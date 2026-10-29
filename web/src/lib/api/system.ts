import { del, get, put } from './client';

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

/** `GET/PUT /api/v1/web-access` (system_routes.rs): public sources may reach the web UI. */
export interface WebAccess {
	public_enabled: boolean;
}

export const getWebAccess = (): Promise<WebAccess> => get('/web-access');
export const putWebAccess = (publicEnabled: boolean): Promise<WebAccess> =>
	put('/web-access', { body: { public_enabled: publicEnabled } });

/** `GET /api/v1/web-bans`: sources currently banned by the shared strike table. */
export interface WebBan {
	ip: string;
	until: string;
}

export const getWebBans = (): Promise<{ items: WebBan[] }> => get('/web-bans');
export const deleteWebBan = (ip: string): Promise<{ ip: string }> =>
	del(`/web-bans/${encodeURIComponent(ip)}`);

export const getUpdateCheck = (): Promise<UpdateCheck> => get('/update/check');
