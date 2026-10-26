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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Requirement {
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
fn requirement(method: &Method, path: &str) -> Requirement {
    let path = path.trim_end_matches('/');
    if path == "/api/v1/status"
        || path.starts_with("/api/v1/auth/oidc")
        || path == "/api/v1/auth/local/login"
    {
        return Requirement::Public;
    }
    if path == "/api/v1/auth/tokens" || path.starts_with("/api/v1/auth/tokens/") {
        return Requirement::ApiAdmin;
    }
    if path == "/api/v1/auth/logout" || path == "/api/v1/auth/me" {
        return Requirement::Api;
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

/// Checks the scope against the requirement, returning the documented error.
fn authorize(requirement: Requirement, scope: Scope) -> Result<(), ControlApiError> {
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
            requirement(&Method::POST, "/api/v1/config"),
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
}
