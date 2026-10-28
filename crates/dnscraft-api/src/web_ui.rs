//! Embedded SPA static assets (`web/build`) for production control-api.
//!
//! Enabled with the `web-ui` feature. CI builds without the feature keep using the
//! JSON 404 fallback. With the feature, compile against `embed-web-ui/` (placeholder)
//! or replace that directory with `web/build` before release (see tasks/w10-rust-embed-notes.md).

#[cfg(feature = "web-ui")]
mod inner {
    use std::sync::OnceLock;

    use axum::body::Body;
    use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
    use axum::response::{IntoResponse, Response};
    use rust_embed::Embed;

    /// Stable hash of the theme bootstrap inline script in `web/src/app.html`.
    const THEME_BOOTSTRAP_HASH: &str = "sha256-+/UWW+kFTQfRcLtOTJw4BrviiPaL5UMxrjQpU8Pu7Mk=";

    #[derive(Embed)]
    #[folder = "embed-web-ui/"]
    struct WebUi;

    fn content_type(path: &str) -> &'static str {
        if path.ends_with(".html") {
            return "text/html; charset=utf-8";
        }
        if path.ends_with(".js") {
            return "text/javascript; charset=utf-8";
        }
        if path.ends_with(".css") {
            return "text/css; charset=utf-8";
        }
        if path.ends_with(".json") {
            return "application/json; charset=utf-8";
        }
        if path.ends_with(".webmanifest") {
            return "application/manifest+json; charset=utf-8";
        }
        if path.ends_with(".png") {
            return "image/png";
        }
        if path.ends_with(".svg") {
            return "image/svg+xml";
        }
        if path.ends_with(".woff2") {
            return "font/woff2";
        }
        if path.ends_with(".ico") {
            return "image/x-icon";
        }
        "application/octet-stream"
    }

    fn csp_header_value() -> HeaderValue {
        static CSP: OnceLock<HeaderValue> = OnceLock::new();
        CSP.get_or_init(|| {
            let hashes: Vec<String> = WebUi::get("csp-script-hashes.json")
                .and_then(|file| serde_json::from_slice(file.data.as_ref()).ok())
                .filter(|hashes: &Vec<String>| !hashes.is_empty())
                .unwrap_or_else(|| vec![THEME_BOOTSTRAP_HASH.to_owned()]);
            let mut parts = vec!["'self'".to_owned()];
            for hash in &hashes {
                let token = hash.trim();
                if token.starts_with('\'') {
                    parts.push(token.to_owned());
                } else {
                    parts.push(format!("'{token}'"));
                }
            }
            let script_src = parts.join(" ");
            let value = format!(
                "default-src 'self'; script-src {script_src}; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
            );
            HeaderValue::try_from(value).expect("CSP header value is valid")
        })
        .clone()
    }

    fn security_headers(content_type: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
        headers.insert(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        );
        if content_type.starts_with("text/html") {
            headers.insert(header::CONTENT_SECURITY_POLICY, csp_header_value());
        }
        headers
    }

    fn cache_control(path: &str) -> &'static str {
        if path.contains("/_app/immutable/") {
            "public, max-age=31536000, immutable"
        } else if path.ends_with(".html") || path == "index.html" {
            "no-cache"
        } else if path == "manifest.webmanifest" || path == "sw.js" {
            "no-cache"
        } else {
            "public, max-age=3600"
        }
    }

    /// Serves a file from the embedded tree, or `index.html` for SPA navigations.
    pub async fn serve(uri: Uri, method: Method) -> Response {
        if method != Method::GET && method != Method::HEAD {
            return StatusCode::METHOD_NOT_ALLOWED.into_response();
        }
        let path = uri.path().trim_start_matches('/');
        let path = if path.is_empty() { "index.html" } else { path };
        if path.contains("..") || path.contains('\\') {
            return StatusCode::BAD_REQUEST.into_response();
        }

        let (served_path, file) = if let Some(file) = WebUi::get(path) {
            (path, file)
        } else if let Some(file) = WebUi::get("index.html") {
            ("index.html", file)
        } else {
            return StatusCode::NOT_FOUND.into_response();
        };

        let ctype = content_type(served_path);
        let mut headers = security_headers(ctype);
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(ctype));
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static(cache_control(served_path)),
        );
        if method == Method::HEAD {
            return (StatusCode::OK, headers).into_response();
        }
        (StatusCode::OK, headers, Body::from(file.data.into_owned())).into_response()
    }
}

#[cfg(feature = "web-ui")]
pub(crate) use inner::serve;
