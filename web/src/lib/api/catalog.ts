/** Hand-maintained control-api paths for the settings API explorer (v1). */
export interface ApiCatalogEntry {
	method: 'GET' | 'POST' | 'PUT' | 'DELETE';
	path: string;
	role: 'viewer' | 'admin';
	summaryKey:
		| 'api_cat_auth_me'
		| 'api_cat_status'
		| 'api_cat_config'
		| 'api_cat_listeners'
		| 'api_cat_tls_status'
		| 'api_cat_query_log'
		| 'api_cat_audit'
		| 'api_cat_tokens';
	/** When set, the explorer may offer a safe GET try. */
	tryPath?: string;
}

export const API_CATALOG: ApiCatalogEntry[] = [
	{
		method: 'GET',
		path: '/api/v1/auth/me',
		role: 'viewer',
		summaryKey: 'api_cat_auth_me',
		tryPath: '/auth/me',
	},
	{
		method: 'GET',
		path: '/api/v1/status',
		role: 'viewer',
		summaryKey: 'api_cat_status',
		tryPath: '/status',
	},
	{
		method: 'GET',
		path: '/api/v1/config',
		role: 'admin',
		summaryKey: 'api_cat_config',
	},
	{
		method: 'GET',
		path: '/api/v1/listeners',
		role: 'admin',
		summaryKey: 'api_cat_listeners',
		tryPath: '/listeners',
	},
	{
		method: 'GET',
		path: '/api/v1/tls/status',
		role: 'viewer',
		summaryKey: 'api_cat_tls_status',
		tryPath: '/tls/status',
	},
	{
		method: 'GET',
		path: '/api/v1/query-log',
		role: 'viewer',
		summaryKey: 'api_cat_query_log',
		tryPath: '/query-log?limit=1',
	},
	{
		method: 'GET',
		path: '/api/v1/audit',
		role: 'admin',
		summaryKey: 'api_cat_audit',
	},
	{
		method: 'GET',
		path: '/api/v1/auth/tokens',
		role: 'admin',
		summaryKey: 'api_cat_tokens',
	},
];
