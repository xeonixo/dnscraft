//! Production `Apply*` adapters: one per module engine.
//!
//! Each adapter deserializes one stored config section into the module's own
//! config type (the module crates derive `serde`) and hands it to that module's
//! hot-reload path. Deserialization failures use the module's stable
//! `*.config.invalid` code; apply failures forward the engine's own code.
//!
//! Filtering, clients, policy and TLS all expose a live `apply_config`; the
//! listener adapter holds a [`Weak`] handle to the running set so shutting the
//! server down still consumes the set.

use std::sync::{Arc, Weak};

use dnscraft_api::{
    ApplyClients, ApplyFiltering, ApplyListeners, ApplyPolicy, ApplyTls, ControlApiError,
    ModuleAppliers, ModuleFuture,
};
use dnscraft_clients::{ClientEngine, ClientsConfig};
use dnscraft_filtering::{FilterConfig, FilterEngine};
use dnscraft_listeners::{ListenerSet, ListenersConfig};
use dnscraft_policy::{PolicyConfig, PolicyEngine};
use dnscraft_tls::{TlsConfig, TlsEngine};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::engine::Engines;

/// Stable code for a `filtering` section that does not parse.
const FILTERING_INVALID: &str = "filtering.config.invalid";
/// Stable code for a `clients` section that does not parse.
const CLIENTS_INVALID: &str = "clients.config.invalid";
/// Stable code for a `policy` section that does not parse.
const POLICY_INVALID: &str = "policy.config.invalid";
/// Stable code for a `listeners` section that does not parse.
const LISTENERS_INVALID: &str = "listeners.config.invalid";
/// Stable code for a `tls` section that does not parse.
const TLS_INVALID: &str = "tls.config.invalid";

/// Deserializes a module section with the module's own serde contract.
fn parse<T: DeserializeOwned>(config: &Value, code: &'static str) -> Result<T, ControlApiError> {
    serde_json::from_value(config.clone()).map_err(|error| module_error(code, error.to_string()))
}

/// Builds a forwarded module error carrying a non-secret reason.
fn module_error(code: &'static str, reason: String) -> ControlApiError {
    ControlApiError::Module {
        code,
        params: Some(json!({ "reason": reason })),
    }
}

/// Applies the `filtering` section by rebuilding the filter snapshot.
struct FilteringApplier {
    engine: Arc<FilterEngine>,
}

impl ApplyFiltering for FilteringApplier {
    fn validate(&self, config: &Value) -> Result<(), ControlApiError> {
        parse::<FilterConfig>(config, FILTERING_INVALID).map(|_| ())
    }

    fn apply<'a>(&'a self, config: &'a Value) -> ModuleFuture<'a> {
        Box::pin(async move {
            let parsed = parse::<FilterConfig>(config, FILTERING_INVALID)?;
            self.engine
                .apply_config(parsed)
                .await
                .map(|_| ())
                .map_err(|error| module_error(error.code(), error.to_string()))
        })
    }
}

/// Applies the `clients` section by swapping the client lookup snapshot.
struct ClientsApplier {
    engine: Arc<ClientEngine>,
}

impl ApplyClients for ClientsApplier {
    fn validate(&self, config: &Value) -> Result<(), ControlApiError> {
        parse::<ClientsConfig>(config, CLIENTS_INVALID).map(|_| ())
    }

    fn apply<'a>(&'a self, config: &'a Value) -> ModuleFuture<'a> {
        Box::pin(async move {
            let parsed = parse::<ClientsConfig>(config, CLIENTS_INVALID)?;
            self.engine
                .apply_config(parsed)
                .await
                .map_err(|error| module_error(error.code(), error.to_string()))
        })
    }
}

/// Applies the `policy` section by rebuilding the policy snapshot.
struct PolicyApplier {
    engine: Arc<PolicyEngine>,
}

impl ApplyPolicy for PolicyApplier {
    fn validate(&self, config: &Value) -> Result<(), ControlApiError> {
        parse::<PolicyConfig>(config, POLICY_INVALID).map(|_| ())
    }

    fn apply<'a>(&'a self, config: &'a Value) -> ModuleFuture<'a> {
        Box::pin(async move {
            let parsed = parse::<PolicyConfig>(config, POLICY_INVALID)?;
            self.engine
                .apply_config(parsed)
                .await
                .map_err(|error| module_error(error.code(), error.to_string()))
        })
    }
}

/// Applies the `listeners` section by rebinding changed listeners.
///
/// Holds a [`Weak`] handle: the [`crate::App`] owns the set and consumes it on
/// shutdown, so an apply racing a shutdown reports a stable internal error
/// instead of keeping the sockets alive.
struct ListenersApplier {
    set: Weak<ListenerSet<PolicyEngine>>,
}

impl ApplyListeners for ListenersApplier {
    fn validate(&self, config: &Value) -> Result<(), ControlApiError> {
        parse::<ListenersConfig>(config, LISTENERS_INVALID)?
            .validate()
            .map_err(|error| module_error(error.code(), error.to_string()))
    }

    fn apply<'a>(&'a self, config: &'a Value) -> ModuleFuture<'a> {
        Box::pin(async move {
            let parsed = parse::<ListenersConfig>(config, LISTENERS_INVALID)?;
            let set = self
                .set
                .upgrade()
                .ok_or_else(|| ControlApiError::Internal {
                    message: "listener set is shutting down".to_owned(),
                })?;
            set.apply_config(parsed)
                .await
                .map_err(|error| module_error(error.code(), error.to_string()))
        })
    }
}

/// Applies the `tls` section to the TLS engine.
struct TlsApplier {
    engine: Arc<TlsEngine>,
}

impl ApplyTls for TlsApplier {
    fn validate(&self, config: &Value) -> Result<(), ControlApiError> {
        parse::<TlsConfig>(config, TLS_INVALID).map(|_| ())
    }

    fn apply<'a>(&'a self, config: &'a Value) -> ModuleFuture<'a> {
        Box::pin(async move {
            let parsed = parse::<TlsConfig>(config, TLS_INVALID)?;
            self.engine
                .apply_config(parsed)
                .await
                .map_err(|error| module_error(error.code(), error.to_string()))
        })
    }
}

/// Wires the five adapters around the assembled engines and listener set.
///
/// A TLS section is only applied when a TLS engine exists; an unconfigured
/// `[tls]` section leaves the slot empty, so the service treats it as a no-op.
pub(crate) fn appliers(
    engines: &Engines,
    listeners: &Arc<ListenerSet<PolicyEngine>>,
) -> ModuleAppliers {
    ModuleAppliers {
        filtering: Some(Arc::new(FilteringApplier {
            engine: Arc::clone(&engines.filtering),
        })),
        clients: Some(Arc::new(ClientsApplier {
            engine: Arc::clone(&engines.clients),
        })),
        policy: Some(Arc::new(PolicyApplier {
            engine: Arc::clone(&engines.policy),
        })),
        listeners: Some(Arc::new(ListenersApplier {
            set: Arc::downgrade(listeners),
        })),
        tls: engines.tls.as_ref().map(|engine| {
            Arc::new(TlsApplier {
                engine: Arc::clone(engine),
            }) as Arc<dyn ApplyTls>
        }),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Every module config the bootstrap writes round-trips through the same
    /// serde contract each applier uses.
    #[test]
    fn module_sections_round_trip_through_serde() {
        let filtering = serde_json::to_value(FilterConfig::default()).unwrap();
        let clients = serde_json::to_value(ClientsConfig::default()).unwrap();
        let policy = serde_json::to_value(PolicyConfig::default()).unwrap();
        let listeners = serde_json::to_value(ListenersConfig::default()).unwrap();
        let tls = serde_json::to_value(TlsConfig::default()).unwrap();

        assert!(parse::<FilterConfig>(&filtering, FILTERING_INVALID).is_ok());
        assert!(parse::<ClientsConfig>(&clients, CLIENTS_INVALID).is_ok());
        assert!(parse::<PolicyConfig>(&policy, POLICY_INVALID).is_ok());
        assert!(parse::<ListenersConfig>(&listeners, LISTENERS_INVALID).is_ok());
        assert!(parse::<TlsConfig>(&tls, TLS_INVALID).is_ok());

        let error = parse::<FilterConfig>(&json!({ "sets": "no" }), FILTERING_INVALID).unwrap_err();
        assert_eq!(error.code(), FILTERING_INVALID);
    }
}
