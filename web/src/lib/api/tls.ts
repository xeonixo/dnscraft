import { get, post, put, type RequestOptions } from './client';
import type { TlsMode } from './stats';

/** Subset of `GET /api/v1/tls/status` (typed TLS DTO). */
export interface TlsStatus {
	mode?: TlsMode;
	fingerprint_sha256?: string;
	not_after?: string | null;
	identifiers?: string[];
	self_signed?: boolean;
	[key: string]: unknown;
}

export interface TlsConfigResponse {
	tls: Record<string, unknown>;
}

export const getTlsConfig = (): Promise<TlsConfigResponse> => get('/tls');

export const saveTlsConfig = (
	tls: Record<string, unknown>,
	options?: RequestOptions,
): Promise<{ version: number; tls: Record<string, unknown> }> =>
	put('/tls', { body: tls, ...options });

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
