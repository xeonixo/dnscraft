import { get } from './client';

export interface AuditRow {
	id: number;
	time: string;
	node_id: string | null;
	actor_id: string;
	actor_type: string;
	action: string;
	object_type: string | null;
	object_id: string | null;
	config_version: number | null;
	before_digest: string | null;
	after_digest: string | null;
	before: unknown;
	after: unknown;
	result: string;
	error_code: string | null;
}

export const listAudit = (limit = 50, offset = 0): Promise<AuditRow[]> =>
	get<{ audit: unknown }>(`/audit?limit=${limit}&offset=${offset}`).then((data) =>
		Array.isArray(data.audit) ? (data.audit as AuditRow[]) : [],
	);
