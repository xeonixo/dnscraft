//! Hand-off of non-DNS HTTP requests on a local DoH listener (web UI / control API on `:443`).

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::combinators::UnsyncBoxBody;
use hyper::body::Incoming;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
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
///
/// `public` additionally lets non-private sources reach the handler on a public-exposure listener;
/// it is off by default and can be flipped at runtime.
#[derive(Default)]
pub struct WebSlot {
    handler: OnceLock<WebHandler>,
    public: AtomicBool,
}

impl WebSlot {
    /// Installs the handler; returns `false` when one is already installed.
    pub fn set(&self, handler: WebHandler) -> bool {
        self.handler.set(handler).is_ok()
    }

    /// Allows (or stops allowing) public sources to reach the handler; takes effect immediately.
    pub fn set_public(&self, enabled: bool) {
        self.public.store(enabled, Ordering::Relaxed);
    }

    /// Whether public sources may reach the handler.
    pub fn public(&self) -> bool {
        self.public.load(Ordering::Relaxed)
    }

    pub(crate) fn get(&self) -> Option<&WebHandler> {
        self.handler.get()
    }
}
