import { del, get, post } from './client';

export type TokenScope = 'viewer' | 'admin' | 'mcp:read' | 'mcp:write';

export interface ApiToken {
	id: string;
	name: string;
	scope: TokenScope;
	actor_id: string;
	created_at: string;
	expires_at: string | null;
}

export interface CreateTokenBody {
	name: string;
	scope: TokenScope;
	ttl_seconds?: number;
}

export interface CreatedToken extends ApiToken {
	token: string;
	warnings: string[];
}

function parseToken(value: unknown): ApiToken | null {
	if (typeof value !== 'object' || value === null) return null;
	const row = value as ApiToken;
	if (typeof row.id !== 'string' || typeof row.name !== 'string') return null;
	return row;
}

export const listTokens = (): Promise<ApiToken[]> =>
	get<{ tokens: unknown }>('/auth/tokens').then((data) =>
		Array.isArray(data.tokens)
			? data.tokens.map(parseToken).filter((t): t is ApiToken => t !== null)
			: [],
	);

export const createToken = (body: CreateTokenBody): Promise<CreatedToken> =>
	post('/auth/tokens', { body });

export const revokeToken = (id: string): Promise<{ id: string; revoked: boolean }> =>
	del(`/auth/tokens/${encodeURIComponent(id)}`);
