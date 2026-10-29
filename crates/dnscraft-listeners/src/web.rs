//! Hand-off of non-DNS HTTP requests on a local DoH listener (web UI / control API on `:443`).

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::combinators::UnsyncBoxBody;
use hyper::body::Incoming;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

/// Response body of a [`WebHandler`].
pub type WebBody = UnsyncBoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

/// Future returned by a [`WebHandler`].
pub type WebFuture = Pin<Box<dyn Future<Output = Response<WebBody>> + Send>>;

/// Serves one request (the TCP peer plus the raw request) that is not a DoH path.
pub type WebHandler = Arc<dyn Fn(SocketAddr, Request<Incoming>) -> WebFuture + Send + Sync>;

/// Late-bound [`WebHandler`] shared by the DoH listeners of a [`crate::ListenerSet`].
///
/// The control API is built after the listeners start, so the slot is filled once it is ready.
/// While it is empty (or never filled) every non-DoH path answers `404`, as before.
#[derive(Default)]
pub struct WebSlot(OnceLock<WebHandler>);

impl WebSlot {
    /// Installs the handler; returns `false` when one is already installed.
    pub fn set(&self, handler: WebHandler) -> bool {
        self.0.set(handler).is_ok()
    }

    pub(crate) fn get(&self) -> Option<&WebHandler> {
        self.0.get()
    }
}
