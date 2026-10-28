// Every error code the UI maps to a translated message. The control-api codes follow the error
// table in SPEC-control-api.md (§ Error codes); the client codes are raised by this app itself.
// A code needs an `error_<code>` key in every locale (see error-codes.test.ts).

export const CONTROL_API_ERROR_CODES = [
	'control_api.config.invalid',
	'control_api.config.read',
	'control_api.config.apply',
	'control_api.config.version',
	'control_api.config.unknown_version',
	'control_api.not_found',
	'control_api.internal',
	'control_api.method_not_allowed',
	'control_api.payload_too_large',
	'control_api.rate_limited',
	'control_api.query_log.read',
	'control_api.query_log.export',
	'control_api.query_log.dropped',
	'control_api.query_log.invalid',
	'control_api.auth.oidc',
	'control_api.auth.local',
	'control_api.auth.locked',
	'control_api.tls.self_signed',
	'control_api.auth.unknown_token',
	'control_api.auth.unknown_session',
	'control_api.auth.session_current',
	'control_api.auth.unauthenticated',
	'control_api.auth.invalid_scope',
	'control_api.auth.invalid_origin',
	'control_api.auth.insufficient_scope',
	'control_api.auth.session_expired',
	'control_api.auth.csrf',
	'control_api.audit.read',
	'control_api.not_ready',
] as const;

/** Raised by the client when no valid envelope arrived (`status` is 0 for failed fetches). */
export const CLIENT_NETWORK = 'client.network';
export const CLIENT_MALFORMED = 'client.malformed';

export const CLIENT_ERROR_CODES = [CLIENT_NETWORK, CLIENT_MALFORMED] as const;

export const ERROR_CODES: readonly string[] = [...CONTROL_API_ERROR_CODES, ...CLIENT_ERROR_CODES];

/** The CSRF mismatch code; the client refreshes the token once on it. */
export const CSRF_CODE = 'control_api.auth.csrf';
