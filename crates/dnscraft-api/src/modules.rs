//! Narrow per-module apply traits used by the atomic config service.
//!
//! The control API does not own the module engines; it only needs to hand one
//! validated config section to each module in a fixed order. Keeping the traits
//! narrow (one `apply`, one optional `validate`) lets tests substitute recording
//! fakes without standing up a resolver, listener set or TLS engine.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use dnscraft_filtering::FilterEngine;
use serde_json::Value;

use crate::error::ControlApiError;
use crate::query_log::QueryLog;

/// A boxed, `Send` apply future (avoids an `async-trait` dependency).
pub type ModuleFuture<'a> = Pin<Box<dyn Future<Output = Result<(), ControlApiError>> + Send + 'a>>;

macro_rules! apply_trait {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        pub trait $name: Send + Sync {
            /// Validates the module's config section before any apply runs.
            ///
            /// The default accepts every value; real adapters override this so a
            /// bad section is rejected before the first module is touched.
            fn validate(&self, _config: &Value) -> Result<(), ControlApiError> {
                Ok(())
            }

            /// Applies one config section, replacing the module's active snapshot.
            fn apply<'a>(&'a self, config: &'a Value) -> ModuleFuture<'a>;
        }
    };
}

apply_trait!(ApplyFiltering, "Applies the `filtering` config section.");
apply_trait!(ApplyResolver, "Applies the `resolver` config section (forward zones).");
apply_trait!(ApplyClients, "Applies the `clients` config section.");
apply_trait!(ApplyPolicy, "Applies the `policy` config section.");
apply_trait!(ApplyListeners, "Applies the `listeners` config section.");
apply_trait!(ApplyTls, "Applies the `tls` config section.");

/// The module appliers wired into a [`crate::ConfigService`].
///
/// A missing applier is a no-op: an embedding that does not run a module simply
/// leaves its slot empty. The apply order is fixed and owned by the service,
/// not by this struct.
#[derive(Clone, Default)]
pub struct ModuleAppliers {
    /// Filtering engine adapter.
    pub filtering: Option<Arc<dyn ApplyFiltering>>,
    /// Resolver adapter (forward zones from the versioned snapshot).
    pub resolver: Option<Arc<dyn ApplyResolver>>,
    /// Clients engine adapter.
    pub clients: Option<Arc<dyn ApplyClients>>,
    /// Policy engine adapter.
    pub policy: Option<Arc<dyn ApplyPolicy>>,
    /// Listener set adapter.
    pub listeners: Option<Arc<dyn ApplyListeners>>,
    /// TLS engine adapter.
    pub tls: Option<Arc<dyn ApplyTls>>,
    /// Filtering engine used to refresh remote lists after a versioned write (GF2).
    ///
    /// Bootstrap seed, boot reconcile, and cluster sync apply filtering offline
    /// only; this handle is used for admin versioned writes (GF2).
    pub filtering_engine: Option<Arc<FilterEngine>>,
    /// Query log whose runtime settings (`control_api_settings.query_log`) are
    /// pushed after every applied config version. Not a module section: it is
    /// updated only when the whole version applied.
    pub query_log: Option<Arc<QueryLog>>,
}
