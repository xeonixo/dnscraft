//! Token scopes, endpoint families and the single RBAC middleware.
//!
//! Every bearer token carries exactly one of four fixed scopes. `viewer` and
//! `admin` are valid only on `/api/v1`; `mcp:read` and `mcp:write` are valid
//! only on `/mcp/v1`. [`rbac_middleware`] maps each request to a required
//! permission, enforces the endpoint family, and inserts the authenticated
//! [`Authenticated`] principal for downstream handlers.
//!
//! Cookie sessions (A6) authenticate `/api/v1` only; their role is treated as
//! the equivalent `viewer`/`admin` scope. Bearer authentication is shared with
//! A6's CSRF exemption through [`super::bearer_token`].

use axum::extract::{Request, State};
use axum::http::Method;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use super::bearer_token;
use super::sessions::{Principal, Role};
use crate::error::ControlApiError;
use crate::server::AppState;

/// The endpoint family a credential may be used on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointFamily {
    /// The regular control API (`/api/v1`).
    Api,
    /// The MCP endpoint (`/mcp/v1`).
    Mcp,
}

impl EndpointFamily {
    /// The family encoded by `path`, or `None` for paths outside both families.
    fn for_path(path: &str) -> Option<Self> {
        let path = path.trim_end_matches('/');
        if path == "/api/v1" || path.starts_with("/api/v1/") {
            Some(Self::Api)
        } else if path == "/mcp/v1" || path.starts_with("/mcp/v1/") {
            Some(Self::Mcp)
        } else {
            None
        }
    }
}

/// The four fixed bearer-token scopes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// Read-only access on `/api/v1`.
    Viewer,
    /// Read/write access on `/api/v1`.
    Admin,
    /// Read tools on `/mcp/v1`.
    McpRead,
    /// Read and write tools on `/mcp/v1`.
    McpWrite,
}

impl Scope {
    /// The wire name (`viewer` | `admin` | `mcp:read` | `mcp:write`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Admin => "admin",
            Self::McpRead => "mcp:read",
            Self::McpWrite => "mcp:write",
        }
    }

    /// Parses a scope name; `None` for anything else.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "viewer" => Some(Self::Viewer),
            "admin" => Some(Self::Admin),
            "mcp:read" => Some(Self::McpRead),
            "mcp:write" => Some(Self::McpWrite),
            _ => None,
        }
    }

    /// The endpoint family this scope is valid on.
    pub fn family(self) -> EndpointFamily {
        match self {
            Self::Viewer | Self::Admin => EndpointFamily::Api,
            Self::McpRead | Self::McpWrite => EndpointFamily::Mcp,
        }
    }

    /// Whether the scope grants the administrative role.
    pub fn is_admin(self) -> bool {
        matches!(self, Self::Admin)
    }
}

impl From<Role> for Scope {
    fn from(role: Role) -> Self {
        match role {
            Role::Viewer => Self::Viewer,
            Role::Admin => Self::Admin,
        }
    }
}

/// Which credential authenticated the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActorType {
    /// A cookie session (or OIDC/break-glass login).
    User,
    /// A bearer API token.
    Token,
}

impl ActorType {
    /// The audit-log wire name (`user` | `token`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Token => "token",
        }
    }
}

/// The authenticated principal inserted by [`rbac_middleware`].
///
/// Sessions and bearer tokens both produce this value, so handlers downstream
/// do not need to know which credential authenticated the request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authenticated {
    actor_id: String,
    scope: Scope,
    actor_type: ActorType,
}

impl Authenticated {
    /// The actor that owns the session or token.
    pub fn actor_id(&self) -> &str {
        &self.actor_id
    }

    /// The resolved scope (a session role maps to `viewer`/`admin`).
    pub fn scope(&self) -> Scope {
        self.scope
    }

    /// Which credential authenticated the request.
    pub fn actor_type(&self) -> ActorType {
        self.actor_type
    }
}

/// What a request path requires.
///
/// Exposed together with [`requirement`] and [`authorize`] so the cluster write
/// relay can re-check a relayed request against the actor's own scope on the
/// master, exactly as [`rbac_middleware`] does locally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Requirement {
    /// No authentication required (health, status, login/OIDC).
    Public,
    /// Any authenticated `viewer`/`admin` principal.
    Api,
    /// The `admin` role only.
    ApiAdmin,
    /// Any MCP scope (`mcp:read` or `mcp:write`); tool-level checks happen in
    /// the MCP layer.
    Mcp,
}

/// Maps a request to its required permission.
///
/// Public so a cluster caller can evaluate a relayed method+path without
/// re-implementing the route table; pair it with [`authorize`].
pub fn requirement(method: &Method, path: &str) -> Requirement {
    let path = path.trim_end_matches('/');
    if path == "/api/v1/status"
        || path == "/api/v1/auth/oidc/authorize-url"
        || path == "/api/v1/auth/oidc/callback"
        || (method == Method::GET && path == "/api/v1/auth/oidc/status")
        || path == "/api/v1/auth/local/login"
    {
        return Requirement::Public;
    }
    // OIDC admin surfaces (client secret, future settings probes).
    if path.starts_with("/api/v1/auth/oidc") {
        return Requirement::ApiAdmin;
    }
    if path == "/api/v1/auth/tokens" || path.starts_with("/api/v1/auth/tokens/") {
        return Requirement::ApiAdmin;
    }
    if path == "/api/v1/auth/logout" || path == "/api/v1/auth/me" {
        return Requirement::Api;
    }
    // Session list/revoke: viewers reach their own sessions; the handlers
    // enforce the admin-only `scope=all` and foreign-session rules (WX8).
    if path == "/api/v1/auth/sessions" || path.starts_with("/api/v1/auth/sessions/") {
        return Requirement::Api;
    }
    // Dry-run reads: they do not mutate config, so viewer may use them even
    // though they are POSTs under the config-family `/policy` prefix.
    if path == "/api/v1/filtering/explain-block" || path == "/api/v1/policy/test-query" {
        return Requirement::Api;
    }
    // The TLS status DTO is operational state (mode, expiry, fingerprint), not
    // configuration: viewers may read it even though `/api/v1/tls/*` is
    // otherwise admin-only.
    if path == "/api/v1/tls/status" {
        return Requirement::Api;
    }
    // The audit log exposes every actor's actions and redacted config
    // snapshots: admin-only, even for reads.
    if path == "/api/v1/audit" || path.starts_with("/api/v1/audit/") {
        return Requirement::ApiAdmin;
    }
    // Backup status exposes the backup directory path: admin-only, even for reads.
    if path == "/api/v1/backups" || path.starts_with("/api/v1/backups/") {
        return Requirement::ApiAdmin;
    }
    if is_config_path(path) {
        return Requirement::ApiAdmin;
    }
    match EndpointFamily::for_path(path) {
        Some(EndpointFamily::Mcp) => Requirement::Mcp,
        Some(EndpointFamily::Api) => {
            if method == Method::GET || method == Method::HEAD {
                Requirement::Api
            } else {
                Requirement::ApiAdmin
            }
        }
        None => Requirement::Public,
    }
}

/// Whether `path` is a configuration-family route. These are admin-only for
/// reads and writes: config exposes network topology (client names, filter
/// rules, forward zones, TLS settings) that `viewer` must not read.
fn is_config_path(path: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "/api/v1/config",
        "/api/v1/policy",
        "/api/v1/clients",
        "/api/v1/cluster",
        "/api/v1/filter-sets",
        "/api/v1/filter-lists",
        "/api/v1/listeners",
        "/api/v1/tls",
    ];
    PREFIXES
        .iter()
        .any(|p| path == *p || (path.starts_with(p) && path.as_bytes().get(p.len()) == Some(&b'/')))
}

/// Checks the scope against the requirement, returning the documented error.
///
/// Public so a cluster caller can re-authorize a relayed write using the
/// actor's replicated `scope`; a sub-node cannot escalate because the master
/// evaluates the actor's original scope, never the node identity.
pub fn authorize(requirement: Requirement, scope: Scope) -> Result<(), ControlApiError> {
    match requirement {
        Requirement::Public => Ok(()),
        Requirement::Api => match scope.family() {
            EndpointFamily::Api => Ok(()),
            EndpointFamily::Mcp => Err(ControlApiError::AuthInvalidScope),
        },
        Requirement::ApiAdmin => match scope.family() {
            EndpointFamily::Api if scope.is_admin() => Ok(()),
            EndpointFamily::Api => Err(ControlApiError::AuthInsufficientScope {
                required: "admin".to_owned(),
            }),
            EndpointFamily::Mcp => Err(ControlApiError::AuthInvalidScope),
        },
        Requirement::Mcp => match scope.family() {
            EndpointFamily::Mcp => Ok(()),
            EndpointFamily::Api => Err(ControlApiError::AuthInvalidScope),
        },
    }
}

/// Central RBAC middleware for `/api/v1` and `/mcp/v1`.
///
/// A cookie-session [`Principal`] inserted by A6 takes precedence; otherwise a
/// bearer token is validated against the [`AppState`]'s token store. Missing or
/// invalid credentials on a protected path return
/// `control_api.auth.unauthenticated` (401); a token from the wrong endpoint
/// family returns `control_api.auth.invalid_scope` (403); a role that lacks the
/// permission returns `control_api.auth.insufficient_scope` (403).
///
/// When no auth state is configured (an embedding without persistence), the
/// middleware passes requests through so the rest of the server keeps working.
pub async fn rbac_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let requirement = requirement(req.method(), req.uri().path());
    if requirement == Requirement::Public {
        return next.run(req).await;
    }
    // A disabled MCP endpoint does not exist: answer exactly like the router
    // fallback (404 `control_api.not_found`) before any credential check.
    if requirement == Requirement::Mcp && !state.mcp_config().enabled {
        return ControlApiError::NotFound {
            what: req.uri().path().to_owned(),
        }
        .into_response();
    }
    let Some(auth) = state.auth_state() else {
        return next.run(req).await;
    };

    let (actor_id, scope, actor_type) =
        if let Some(principal) = req.extensions().get::<Principal>().cloned() {
            (
                principal.actor_id,
                Scope::from(principal.role),
                ActorType::User,
            )
        } else if let Some(token) = bearer_token(req.headers()).map(str::to_owned) {
            match auth.tokens().authenticate(&token).await {
                Ok(principal) => (
                    principal.actor_id().to_owned(),
                    principal.scope(),
                    ActorType::Token,
                ),
                Err(err) => return err.into_response(),
            }
        } else {
            return ControlApiError::AuthUnauthenticated.into_response();
        };

    if let Err(err) = authorize(requirement, scope) {
        return err.into_response();
    }
    // Per-principal bucket (SPEC-control-api § General rules): the same
    // class the source bucket uses, charged to the authenticated actor.
    if let Err(seconds) =
        crate::api::rate_limit::check_principal(&state, &actor_id, req.method(), req.uri().path())
    {
        return crate::api::rate_limit::rate_limited_response(seconds);
    }
    req.extensions_mut().insert(Authenticated {
        actor_id,
        scope,
        actor_type,
    });
    next.run(req).await
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn scopes_have_one_family_and_round_trip() {
        for (name, scope, family) in [
            ("viewer", Scope::Viewer, EndpointFamily::Api),
            ("admin", Scope::Admin, EndpointFamily::Api),
            ("mcp:read", Scope::McpRead, EndpointFamily::Mcp),
            ("mcp:write", Scope::McpWrite, EndpointFamily::Mcp),
        ] {
            assert_eq!(Scope::parse(name), Some(scope));
            assert_eq!(scope.as_str(), name);
            assert_eq!(scope.family(), family);
        }
        assert_eq!(Scope::parse("owner"), None);
        assert_eq!(Scope::parse("mcp:admin"), None);
    }

    #[test]
    fn requirement_maps_routes_to_roles() {
        assert_eq!(requirement(&Method::GET, "/healthz"), Requirement::Public);
        assert_eq!(
            requirement(&Method::GET, "/api/v1/status"),
            Requirement::Public
        );
        assert_eq!(
            requirement(&Method::POST, "/api/v1/auth/local/login"),
            Requirement::Public
        );
        assert_eq!(
            requirement(&Method::GET, "/api/v1/query-log"),
            Requirement::Api
        );
        assert_eq!(
            requirement(&Method::GET, "/api/v1/domain-zones"),
            Requirement::Api
        );
        assert_eq!(
            requirement(&Method::GET, "/api/v1/domain-zones/zone-1/records"),
            Requirement::Api
        );
        // The TLS status DTO is viewer-readable; every other TLS route is admin.
        assert_eq!(
            requirement(&Method::GET, "/api/v1/tls/status"),
            Requirement::Api
        );
        assert_eq!(
            requirement(&Method::GET, "/api/v1/tls/certificate"),
            Requirement::ApiAdmin
        );
        assert_eq!(
            requirement(&Method::POST, "/api/v1/tls/renew"),
            Requirement::ApiAdmin
        );
        // MCP dry-run reads are viewer-readable even though they are POSTs
        // under the config-family `/policy` prefix.
        assert_eq!(
            requirement(&Method::POST, "/api/v1/filtering/explain-block"),
            Requirement::Api
        );
        assert_eq!(
            requirement(&Method::POST, "/api/v1/policy/test-query"),
            Requirement::Api
        );
        assert_eq!(
            requirement(&Method::GET, "/api/v1/filtering/mcp-rules"),
            Requirement::Api
        );
        assert_eq!(
            requirement(&Method::POST, "/api/v1/filtering/custom-rules"),
            Requirement::ApiAdmin
        );
        // Configuration-family routes are admin-only for reads too.
        for path in [
            "/api/v1/config",
            "/api/v1/config/versions",
            "/api/v1/policy/views",
            "/api/v1/clients",
            "/api/v1/clients/manual",
            "/api/v1/cluster/nodes",
            "/api/v1/filter-sets",
            "/api/v1/filter-lists",
            "/api/v1/listeners",
            "/api/v1/tls",
        ] {
            assert_eq!(
                requirement(&Method::GET, path),
                Requirement::ApiAdmin,
                "config read {path} must be admin-only"
            );
        }
        assert_eq!(
            requirement(&Method::POST, "/api/v1/config"),
            Requirement::ApiAdmin
        );
        // The cluster admin surface is admin-only for every method.
        assert_eq!(
            requirement(&Method::POST, "/api/v1/cluster/join-tokens"),
            Requirement::ApiAdmin
        );
        assert_eq!(
            requirement(&Method::GET, "/api/v1/cluster/nodes"),
            Requirement::ApiAdmin
        );
        assert_eq!(
            requirement(&Method::DELETE, "/api/v1/cluster/nodes/node-a"),
            Requirement::ApiAdmin
        );
        assert_eq!(
            requirement(&Method::GET, "/api/v1/cluster/writes/r1"),
            Requirement::ApiAdmin
        );
        assert_eq!(
            requirement(&Method::GET, "/api/v1/auth/tokens"),
            Requirement::ApiAdmin
        );
        assert_eq!(
            requirement(&Method::POST, "/api/v1/auth/tokens"),
            Requirement::ApiAdmin
        );
        assert_eq!(
            requirement(&Method::POST, "/api/v1/auth/logout"),
            Requirement::Api
        );
        assert_eq!(
            requirement(&Method::GET, "/api/v1/auth/me"),
            Requirement::Api
        );
        // The audit log is admin-only, even for reads.
        assert_eq!(
            requirement(&Method::GET, "/api/v1/audit"),
            Requirement::ApiAdmin
        );
        assert_eq!(requirement(&Method::POST, "/mcp/v1"), Requirement::Mcp);
    }

    #[test]
    fn authorize_enforces_family_and_role() {
        assert!(authorize(Requirement::Api, Scope::Viewer).is_ok());
        assert!(authorize(Requirement::Api, Scope::Admin).is_ok());
        assert!(authorize(Requirement::ApiAdmin, Scope::Admin).is_ok());
        assert_eq!(
            authorize(Requirement::ApiAdmin, Scope::Viewer)
                .unwrap_err()
                .code(),
            "control_api.auth.insufficient_scope"
        );
        assert_eq!(
            authorize(Requirement::Mcp, Scope::Viewer)
                .unwrap_err()
                .code(),
            "control_api.auth.invalid_scope"
        );
        assert_eq!(
            authorize(Requirement::Api, Scope::McpRead)
                .unwrap_err()
                .code(),
            "control_api.auth.invalid_scope"
        );
        assert!(authorize(Requirement::Mcp, Scope::McpRead).is_ok());
        assert!(authorize(Requirement::Mcp, Scope::McpWrite).is_ok());
    }

    #[test]
    fn public_recheck_matches_middleware_decisions() {
        // The same two steps `rbac_middleware` runs, using only the public
        // requirement/authorize surface a cluster relay will call.
        let viewer = Authenticated {
            actor_id: "u1".to_owned(),
            scope: Scope::Viewer,
            actor_type: ActorType::User,
        };
        let admin = Authenticated {
            actor_id: "u2".to_owned(),
            scope: Scope::Admin,
            actor_type: ActorType::Token,
        };

        for (method, path) in [
            (Method::GET, "/api/v1/query-log"),
            (Method::POST, "/api/v1/auth/logout"),
        ] {
            assert!(
                authorize(requirement(&method, path), viewer.scope()).is_ok(),
                "viewer must be allowed on {method} {path}"
            );
        }
        for (method, path) in [
            (Method::GET, "/api/v1/config"),
            (Method::POST, "/api/v1/config"),
            (Method::GET, "/api/v1/auth/tokens"),
            (Method::GET, "/api/v1/audit"),
        ] {
            let err = authorize(requirement(&method, path), viewer.scope()).unwrap_err();
            assert_eq!(
                err.code(),
                "control_api.auth.insufficient_scope",
                "viewer must be denied on {method} {path}"
            );
            assert!(
                authorize(requirement(&method, path), admin.scope()).is_ok(),
                "admin must be allowed on {method} {path}"
            );
        }
        // Family mismatch is the documented invalid-scope error, same as the
        // middleware.
        assert_eq!(
            authorize(requirement(&Method::POST, "/mcp/v1"), Scope::Viewer)
                .unwrap_err()
                .code(),
            "control_api.auth.invalid_scope"
        );
    }
}
