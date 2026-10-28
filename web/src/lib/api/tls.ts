import { get, post, put, type RequestOptions } from './client';
import type { TlsMode } from './stats';

/** Subset of `GET /api/v1/tls/status` (typed TLS DTO from SPEC-tls). */
export interface TlsStatus {
	mode?: TlsMode;
	fingerprint_sha256?: string;
	not_before?: string | null;
	not_after?: string | null;
	days_to_expiry?: number | null;
	identifiers?: string[];
	issuer?: string | null;
	subject?: string | null;
	key_type?: string | null;
	last_issue?: string | null;
	last_renew_attempt?: string | null;
	last_error?: string | null;
	self_signed?: boolean;
	/** Last discovered addresses from a DynDNS pass (SPEC: `dyndns_ipv4` / `dyndns_ipv6`). */
	dyndns_ipv4?: string | null;
	dyndns_ipv6?: string | null;
	/** @deprecated Mock/older clients; prefer `dyndns_ipv4`. */
	dyndns_last_ipv4?: string | null;
	/** @deprecated Mock/older clients; prefer `dyndns_ipv6`. */
	dyndns_last_ipv6?: string | null;
	last_dyndns_success?: string | null;
	[key: string]: unknown;
}

/** Prefer canonical status fields; fall back to older mock names. */
export function dyndnsDiscoveredIpv4(status: TlsStatus | null | undefined): string | null {
	const value = status?.dyndns_ipv4 ?? status?.dyndns_last_ipv4;
	return value == null || value === '' ? null : value;
}

export function dyndnsDiscoveredIpv6(status: TlsStatus | null | undefined): string | null {
	const value = status?.dyndns_ipv6 ?? status?.dyndns_last_ipv6;
	return value == null || value === '' ? null : value;
}

export interface TlsConfigResponse {
	tls: Record<string, unknown>;
	/** Write-only Cloudflare token is set (never returned in plaintext). */
	has_cloudflare_token?: boolean;
}

export const getTlsConfig = (): Promise<TlsConfigResponse> => get('/tls');

export const saveTlsConfig = (
	tls: Record<string, unknown>,
	options?: RequestOptions,
): Promise<{ version: number; tls: Record<string, unknown> }> =>
	put('/tls', { body: tls, ...options });

/** Write-only Cloudflare API token. Pass `null` to clear. */
export const putCloudflareToken = (
	api_token: string | null,
): Promise<{ updated: boolean; has_cloudflare_token?: boolean }> =>
	put('/tls/cloudflare-token', { body: { api_token } });

export const getTlsStatus = (): Promise<TlsStatus> => get('/tls/status');

export const renewTls = (): Promise<{ started: boolean }> => post('/tls/renew');

export const revokeTls = (reason: string): Promise<unknown> =>
	post('/tls/revoke', { body: { reason } });

export const rotateTls = (): Promise<{ rotated: boolean }> => post('/tls/rotate');

export const preflightTls = (): Promise<{ ok: boolean; checks: unknown[] }> =>
	post('/tls/preflight');

export const triggerDyndns = (): Promise<unknown> => post('/tls/dyndns');

export const uploadCertificate = (body: {
	cert_pem: string;
	key_pem: string;
	chain_pem?: string;
}): Promise<{ mode: string }> => put('/tls/certificate', { body });
