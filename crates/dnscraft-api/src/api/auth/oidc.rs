//! OIDC Authorization Code flow with PKCE (S256) and nonce.
//!
//! The control API is an OpenID Connect relying party. [`OidcState`] performs
//! discovery, builds the authorization URL (PKCE S256 + nonce + state), and
//! exchanges the one-time authorization code for an ID token. The ID token is
//! verified against the provider JWKS and the configured issuer, audience,
//! nonce, `exp` (with the configured skew), `iat` and `at_hash`. Only
//! asymmetric signatures are accepted: `alg=none` and HMAC algorithms (an
//! `alg`-confusion attempt with the client secret) are rejected.
//!
//! Pending logins are keyed by the random `state` value, expire after ten
//! minutes on the injected [`Clock`] (ADR-0005), and are removed when the
//! callback arrives, so a `state` is single-use whether or not the exchange
//! succeeds. The client secret lives in the crate's [`ClientSecret`] (its
//! `Debug` is redacted) and is never logged or serialized.
//!
//! [`Clock`]: crate::Clock

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use openidconnect::core::{
    CoreAuthDisplay, CoreAuthPrompt, CoreAuthenticationFlow, CoreErrorResponseType,
    CoreGenderClaim, CoreJsonWebKey, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm,
    CoreProviderMetadata, CoreRevocableToken, CoreRevocationErrorResponse,
    CoreTokenIntrospectionResponse, CoreTokenType,
};
use openidconnect::{
    AccessTokenHash, AdditionalClaims, AsyncHttpClient, AuthorizationCode, Client, ClientId,
    ClientSecret, CsrfToken, EmptyExtraTokenFields, EndpointMaybeSet, EndpointNotSet, EndpointSet,
    HttpClientError, HttpRequest, HttpResponse, IdTokenFields, IssuerUrl, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, StandardErrorResponse,
    StandardTokenResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::Role;
use super::ensure_same_origin;
use super::sessions::{secure_cookie, session_set_cookie};
use crate::clock::{Clock, SystemClock, unix_seconds};
use crate::config::AuthConfig;
use crate::error::ControlApiError;
use crate::server::AppState;

/// Callback for the authorization URL endpoint.
const CALLBACK_PATH: &str = "/api/v1/auth/oidc/callback";
/// How long an initiated login may wait for the provider callback.
const PENDING_TTL_SECS: i64 = 10 * 60;
/// JWS algorithms accepted for ID tokens. Deliberately asymmetric-only, so an
/// attacker cannot switch `alg` to `none` or to an HMAC keyed with a value the
/// client knows.
const ASYMMETRIC_SIGNING_ALGS: [CoreJwsSigningAlgorithm; 10] = [
    CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
    CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha384,
    CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha512,
    CoreJwsSigningAlgorithm::RsaSsaPssSha256,
    CoreJwsSigningAlgorithm::RsaSsaPssSha384,
    CoreJwsSigningAlgorithm::RsaSsaPssSha512,
    CoreJwsSigningAlgorithm::EcdsaP256Sha256,
    CoreJwsSigningAlgorithm::EcdsaP384Sha384,
    CoreJwsSigningAlgorithm::EcdsaP521Sha512,
    CoreJwsSigningAlgorithm::EdDsa,
];

/// The provider-specific claims this API reads. The configurable admin group
/// name is fixed at `groups` by the spec's default; only group membership is
/// consumed, never email or profile claims.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct OidcAdditionalClaims {
    #[serde(default)]
    groups: Option<Vec<String>>,
}

impl AdditionalClaims for OidcAdditionalClaims {}

type OidcIdTokenFields = IdTokenFields<
    OidcAdditionalClaims,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

type OidcTokenResponse = StandardTokenResponse<OidcIdTokenFields, CoreTokenType>;

type OidcClient = Client<
    OidcAdditionalClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    OidcTokenResponse,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

/// One in-flight authorization request, keyed by its CSRF `state`.
struct PendingAuth {
    nonce: Nonce,
    code_verifier: PkceCodeVerifier,
    redirect_url: RedirectUrl,
    expires_at: i64,
}

/// An HTTP client for the openidconnect/oauth2 machinery, backed by the shared
/// ring-only reqwest client (ADR-0002: no native-tls, aws-lc or OpenSSL).
#[derive(Clone)]
struct OidcHttpClient {
    client: reqwest::Client,
}

impl<'c> AsyncHttpClient<'c> for OidcHttpClient {
    type Error = HttpClientError<reqwest::Error>;
    type Future =
        Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + Send + Sync + 'c>>;

    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(async move {
            let response = self
                .client
                .execute(request.try_into().map_err(Box::new)?)
                .await
                .map_err(Box::new)?;
            let mut builder = openidconnect::http::Response::builder()
                .status(response.status())
                .version(response.version());
            for (name, value) in response.headers().iter() {
                builder = builder.header(name, value);
            }
            builder
                .body(response.bytes().await.map_err(Box::new)?.to_vec())
                .map_err(HttpClientError::Http)
        })
    }
}

/// OIDC relying-party state: configured provider, pending logins and clock.
///
/// Construct it at startup from the validated [`AuthConfig`] with
/// [`OidcState::from_config`] (production: [`SystemClock`]) or
/// [`OidcState::from_config_with_clock`] (tests), then attach it to
/// [`AppState::with_oidc`](crate::AppState::with_oidc) together with the
/// session store. When OIDC is disabled or both issuer and client id are
/// empty, construction returns `None` and the routes are not mounted.
pub struct OidcState {
    issuer: IssuerUrl,
    client_id: ClientId,
    client_secret: Option<ClientSecret>,
    admin_group: String,
    token_skew: Duration,
    clock: Arc<dyn Clock>,
    http: OidcHttpClient,
    pending: Mutex<HashMap<String, PendingAuth>>,
}

impl fmt::Debug for OidcState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OidcState")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[redacted]")
            .field("admin_group", &self.admin_group)
            .field("token_skew", &self.token_skew)
            .finish_non_exhaustive()
    }
}

impl OidcState {
    /// Builds the OIDC state from `auth` using the real system clock.
    ///
    /// Returns `Ok(None)` when `oidc_enabled` is false or when neither an
    /// issuer nor a client id is configured.
    pub fn from_config(auth: &AuthConfig) -> Result<Option<Self>, ControlApiError> {
        Self::from_config_with_clock(auth, Arc::new(SystemClock))
    }

    /// Builds the OIDC state against an injected [`Clock`] (ADR-0005).
    pub fn from_config_with_clock(
        auth: &AuthConfig,
        clock: Arc<dyn Clock>,
    ) -> Result<Option<Self>, ControlApiError> {
        if !auth.oidc_enabled {
            return Ok(None);
        }
        let issuer = auth.oidc_issuer.trim();
        let client_id = auth.oidc_client_id.trim();
        if issuer.is_empty() && client_id.is_empty() {
            return Ok(None);
        }
        if issuer.is_empty() || client_id.is_empty() {
            return Err(ControlApiError::config(
                "OIDC requires both oidc_issuer and oidc_client_id",
            ));
        }
        let issuer = IssuerUrl::new(issuer.to_owned())
            .map_err(|err| oidc_error(format!("invalid OIDC issuer: {err}")))?;
        let client_secret = auth.oidc_client_secret.expose();
        Ok(Some(Self {
            issuer,
            client_id: ClientId::new(client_id.to_owned()),
            client_secret: (!client_secret.is_empty())
                .then(|| ClientSecret::new(client_secret.to_owned())),
            admin_group: auth.oidc_admin_group.clone(),
            token_skew: auth.oidc_token_skew,
            clock,
            http: OidcHttpClient {
                client: build_http_client()?,
            },
            pending: Mutex::new(HashMap::new()),
        }))
    }

    /// Starts a login: discovers the provider, builds the authorization URL
    /// with a fresh state, nonce and PKCE S256 challenge, records the pending
    /// login, and returns `(authorization_url, state)`.
    pub async fn authorization_url(
        &self,
        redirect_url: RedirectUrl,
    ) -> Result<(String, String), ControlApiError> {
        let client = self.discovered_client(redirect_url.clone()).await?;
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let (url, state, nonce) = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_pkce_challenge(challenge)
            .url();

        let now = unix_seconds(self.clock.now());
        let state_value = state.secret().clone();
        let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        pending.retain(|_, auth| auth.expires_at > now);
        pending.insert(
            state_value.clone(),
            PendingAuth {
                nonce,
                code_verifier: verifier,
                redirect_url,
                expires_at: now.saturating_add(PENDING_TTL_SECS),
            },
        );
        drop(pending);
        Ok((url.to_string(), state_value))
    }

    /// Completes a login: consumes the pending `state` (single-use), exchanges
    /// `code` at the token endpoint, and verifies the ID token. On success
    /// returns the OIDC `sub` and the mapped role (`admin` when the configured
    /// admin group is present, otherwise `viewer`).
    pub async fn complete_login(
        &self,
        code: String,
        state: &str,
    ) -> Result<(String, Role), ControlApiError> {
        let pending = {
            let now = unix_seconds(self.clock.now());
            let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
            let auth = pending
                .remove(state)
                .ok_or_else(|| oidc_error("unknown or already-used OIDC state"))?;
            if auth.expires_at <= now {
                return Err(oidc_error("expired OIDC login state"));
            }
            auth
        };
        let PendingAuth {
            nonce,
            code_verifier,
            redirect_url,
            ..
        } = pending;
        let client = self.discovered_client(redirect_url).await?;
        let token_request = client
            .exchange_code(AuthorizationCode::new(code))
            .map_err(|err| oidc_error(format!("OIDC token request failed: {err}")))?;
        let token_response = token_request
            .set_pkce_verifier(code_verifier)
            .request_async(&self.http)
            .await
            .map_err(|err| oidc_error(format!("OIDC token exchange failed: {err}")))?;
        let id_token = token_response
            .extra_fields()
            .id_token()
            .ok_or_else(|| oidc_error("OIDC token response has no ID token"))?;

        let time_clock = self.clock.clone();
        let iat_clock = self.clock.clone();
        let skew = self.token_skew;
        let skew_secs = i64::try_from(skew.as_secs()).unwrap_or(i64::MAX);
        let verifier = client
            .id_token_verifier()
            .set_allowed_algs(ASYMMETRIC_SIGNING_ALGS.iter().cloned())
            .set_time_fn(move || {
                let now = time_clock.now();
                // Validate `exp` against now minus the allowed skew, so a
                // token expiring up to `skew` ago is still accepted.
                DateTime::<Utc>::from(now.checked_sub(skew).unwrap_or(now))
            })
            .set_issue_time_verifier_fn(move |issued| {
                if issued.timestamp() > unix_seconds(iat_clock.now()).saturating_add(skew_secs) {
                    Err("ID token issued in the future".to_owned())
                } else {
                    Ok(())
                }
            });
        let claims = id_token
            .claims(&verifier, &nonce)
            .map_err(|err| oidc_error(format!("ID token validation failed: {err}")))?;

        // `at_hash` binds the ID token to this access token. Verify it only
        // when the provider sent one, as the spec allows.
        if let Some(expected) = claims.access_token_hash() {
            let alg = id_token
                .signing_alg()
                .map_err(|err| oidc_error(format!("ID token algorithm error: {err}")))?;
            let key = id_token
                .signing_key(&verifier)
                .map_err(|err| oidc_error(format!("ID token key error: {err}")))?;
            let actual = AccessTokenHash::from_token(token_response.access_token(), alg, key)
                .map_err(|err| oidc_error(format!("ID token at_hash error: {err}")))?;
            // Compare digests rather than the raw values: fixed-length and
            // non-short-circuiting enough for a non-secret derived claim.
            let actual_digest = ring::digest::digest(&ring::digest::SHA256, actual.as_bytes());
            let expected_digest = ring::digest::digest(&ring::digest::SHA256, expected.as_bytes());
            if actual_digest.as_ref() != expected_digest.as_ref() {
                return Err(oidc_error(
                    "ID token at_hash does not match the access token",
                ));
            }
        }

        let role = match claims.additional_claims().groups.as_deref() {
            Some(groups) if groups.iter().any(|group| group == &self.admin_group) => Role::Admin,
            _ => Role::Viewer,
        };
        Ok((claims.subject().to_string(), role))
    }

    /// Discovers the provider metadata and builds a client for one redirect URI.
    async fn discovered_client(
        &self,
        redirect_url: RedirectUrl,
    ) -> Result<OidcClient, ControlApiError> {
        let metadata = CoreProviderMetadata::discover_async(self.issuer.clone(), &self.http)
            .await
            .map_err(|err| oidc_error(format!("OIDC discovery failed: {err}")))?;
        Ok(OidcClient::from_provider_metadata(
            metadata,
            self.client_id.clone(),
            self.client_secret.clone(),
        )
        .set_redirect_uri(redirect_url))
    }
}

/// `GET /api/v1/auth/oidc/authorize-url`: public endpoint returning the
/// provider authorization URL and the matching `state` value.
pub(crate) async fn oidc_authorize_url(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ControlApiError> {
    ensure_same_origin(&headers)?;
    let oidc = state
        .oidc_state()
        .ok_or_else(|| ControlApiError::Internal {
            message: "OIDC login is not configured".to_owned(),
        })?;
    let redirect_url = callback_url(&state, &headers)?;
    let (authorization_url, csrf_state) = oidc.authorization_url(redirect_url).await?;
    Ok(crate::api::response::success(json!({
        "authorization_url": authorization_url,
        "state": csrf_state,
    }))
    .into_response())
}

/// Query parameters of the authorization response.
#[derive(Deserialize)]
pub(crate) struct OidcCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// `GET /api/v1/auth/oidc/callback`: public endpoint that completes the login
/// and mints a cookie session for the mapped role.
pub(crate) async fn oidc_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<OidcCallbackQuery>,
) -> Result<Response, ControlApiError> {
    ensure_same_origin(&headers)?;
    let oidc = state
        .oidc_state()
        .ok_or_else(|| ControlApiError::Internal {
            message: "OIDC login is not configured".to_owned(),
        })?;
    if let Some(error) = query.error {
        let description = query.error_description.unwrap_or_default();
        return Err(oidc_error(format!(
            "OIDC provider returned {error}: {description}"
        )));
    }
    let code = query
        .code
        .ok_or_else(|| oidc_error("OIDC callback is missing the authorization code"))?;
    let csrf_state = query
        .state
        .ok_or_else(|| oidc_error("OIDC callback is missing the state parameter"))?;
    let (actor_id, role) = oidc.complete_login(code, &csrf_state).await?;

    let sessions = state
        .auth_state()
        .map(|auth| auth.sessions().store().clone())
        .ok_or_else(|| ControlApiError::Internal {
            message: "session authentication is not configured".to_owned(),
        })?;
    let created = sessions.create(actor_id, role).await?;
    let cookie = session_set_cookie(
        created.cookie().expose(),
        secure_cookie(
            state.tls_status().is_some(),
            headers
                .get("x-forwarded-proto")
                .and_then(|value| value.to_str().ok()),
        ),
    );
    let cookie = HeaderValue::from_str(&cookie).map_err(|err| ControlApiError::Internal {
        message: format!("build session cookie: {err}"),
    })?;

    let mut response = crate::api::response::success(json!({
        "actor_id": created.principal().actor_id,
        "role": role.as_str(),
        "csrf_token": created.csrf_token().expose(),
    }))
    .into_response();
    response.headers_mut().insert(header::SET_COOKIE, cookie);
    Ok(response)
}

/// Derives the callback URL from the request. Direct TLS wins; otherwise an
/// `X-Forwarded-Proto: https` from a terminating proxy keeps the redirect URI
/// on https. A mismatched host produces a redirect URI the provider rejects
/// (the client is registered with one exact callback), so this cannot redirect
/// credentials elsewhere.
fn callback_url(state: &AppState, headers: &HeaderMap) -> Result<RedirectUrl, ControlApiError> {
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .ok_or_else(|| oidc_error("OIDC login requires a Host header"))?;
    let forwarded_https = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|proto| proto.eq_ignore_ascii_case("https"));
    let scheme = if state.tls_status().is_some() || forwarded_https {
        "https"
    } else {
        "http"
    };
    RedirectUrl::new(format!("{scheme}://{host}{CALLBACK_PATH}"))
        .map_err(|err| oidc_error(format!("invalid OIDC redirect URL: {err}")))
}

/// Builds the ring-only reqwest client used for discovery and the token
/// endpoint, trusting the bundled Mozilla roots.
fn build_http_client() -> Result<reqwest::Client, ControlApiError> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|err| oidc_error(format!("build OIDC TLS config: {err}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        // Discovery/token endpoints never legitimately redirect; refusing
        // redirects avoids SSRF pivots from a compromised discovery document.
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .build()
        .map_err(|err| oidc_error(format!("build OIDC HTTP client: {err}")))
}

/// The documented OIDC error: `control_api.auth.oidc` (HTTP 502).
fn oidc_error(message: impl Into<String>) -> ControlApiError {
    ControlApiError::AuthOidc {
        message: message.into(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Threat model: `alg=none` and HMAC algorithms (alg-confusion) must never
    /// be accepted for an ID token. The integration suite proves rejection
    /// end to end; this pins the allow-list that causes it.
    #[test]
    fn alg_confusion_allow_list_is_asymmetric_only() {
        assert!(!ASYMMETRIC_SIGNING_ALGS.is_empty());
        for algorithm in ASYMMETRIC_SIGNING_ALGS.iter().cloned() {
            assert!(
                !matches!(
                    algorithm,
                    CoreJwsSigningAlgorithm::None
                        | CoreJwsSigningAlgorithm::HmacSha256
                        | CoreJwsSigningAlgorithm::HmacSha384
                        | CoreJwsSigningAlgorithm::HmacSha512
                ),
                "ID-token algorithm list must not accept {algorithm:?}"
            );
        }
    }
}
